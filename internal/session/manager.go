package session

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"time"

	"gosestor/internal/store"
)

// Config holds the timeout and behavior knobs the Manager needs.
type Config struct {
	Inactive    time.Duration
	Final       time.Duration
	Grace       time.Duration
	Synchronize bool
}

// Manager owns session/key lifecycle over a Store.
type Manager struct {
	store store.Store
	clock Clock
	cfg   Config
	rng   io.Reader // crypto/rand.Reader in production; deterministic in tests
}

func NewManager(s store.Store, clk Clock, cfg Config, rng io.Reader) *Manager {
	if rng == nil {
		rng = rand.Reader
	}
	return &Manager{store: s, clock: clk, cfg: cfg, rng: rng}
}

// Live is an in-request handle to a session.
type Live struct {
	KeyID     string
	SessionID string
	OwnerID   int64
	Cookies   map[string]string

	m       *Manager
	shas    map[string]string
	newKey  string // set when a proxy cookie must be (re)written
	rewrite bool
}

func (m *Manager) newID() (string, error) {
	buf := make([]byte, 32) // 256-bit
	if _, err := io.ReadFull(m.rng, buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// Begin creates a brand-new session with a fresh key and emits the proxy cookie.
func (m *Manager) Begin(ctx context.Context) (*Live, error) {
	now := m.clock.Now().Unix()
	sid, err := m.newID()
	if err != nil {
		return nil, err
	}
	key, err := m.newID()
	if err != nil {
		return nil, err
	}
	sess := store.Session{
		ID:              sid,
		Creation:        now,
		LastAccess:      now,
		InactiveTimeout: int64(m.cfg.Inactive.Seconds()),
		FinalTimeout:    int64(m.cfg.Final.Seconds()),
	}
	// TTL must respect min(inactive, remaining-until-final) so the store never
	// outlives the absolute deadline; at creation (Creation==now) this equals
	// min(Inactive, Final).
	ttl := m.ttl(sess, now)
	if err := m.store.PutSession(ctx, sess, ttl); err != nil {
		return nil, err
	}
	if err := m.store.PutKey(ctx, key, sid, ttl); err != nil {
		return nil, err
	}
	return &Live{
		KeyID: key, SessionID: sid, Cookies: map[string]string{}, shas: map[string]string{},
		m: m, newKey: key, rewrite: true,
	}, nil
}

// Resolve loads a session by client key, enforcing inactive + final timeouts.
// Returns (nil, nil) when there is no live session.
func (m *Manager) Resolve(ctx context.Context, keyID string) (*Live, error) {
	sid, err := m.store.GetKey(ctx, keyID)
	if err == store.ErrNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	sess, err := m.store.GetSession(ctx, sid)
	if err == store.ErrNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	now := m.clock.Now().Unix()
	if m.expired(sess, now) {
		_ = m.store.DeleteSession(ctx, sid)
		return nil, nil
	}
	// Slide the window: update last_access and refresh TTLs.
	sess.LastAccess = now
	ttl := m.ttl(sess, now)
	if err := m.store.PutSession(ctx, sess, ttl); err != nil {
		return nil, err
	}
	if err := m.store.Refresh(ctx, sid, ttl); err != nil {
		return nil, err
	}
	if err := m.store.SetKeyTTL(ctx, keyID, ttl); err != nil {
		return nil, err
	}
	cookies, err := m.store.GetCookies(ctx, sid)
	if err != nil {
		return nil, err
	}
	shas, err := m.store.CookieSHAs(ctx, sid)
	if err != nil {
		return nil, err
	}
	return &Live{
		KeyID: keyID, SessionID: sid, OwnerID: sess.OwnerID,
		Cookies: cookies, shas: shas, m: m,
	}, nil
}

// expired reports whether the session is past its inactive or final limit.
func (m *Manager) expired(s store.Session, now int64) bool {
	if now-s.LastAccess >= s.InactiveTimeout {
		return true
	}
	if now >= s.Creation+s.FinalTimeout {
		return true
	}
	return false
}

// ttl returns min(inactive, remaining-until-final) so Redis never keeps a
// session past its absolute deadline.
func (m *Manager) ttl(s store.Session, now int64) time.Duration {
	inactive := time.Duration(s.InactiveTimeout) * time.Second
	remainingFinal := time.Duration(s.Creation+s.FinalTimeout-now) * time.Second
	if remainingFinal < inactive {
		return remainingFinal
	}
	return inactive
}

// NewProxyCookie reports the value to set on the client, if a (re)write is due.
func (l *Live) NewProxyCookie() (string, bool) {
	if l.rewrite {
		return l.newKey, true
	}
	return "", false
}

// StoreCookie writes a cached cookie, skipping the write when the value is
// unchanged (VALUE_SHA dedupe).
func (l *Live) StoreCookie(ctx context.Context, name, value string) error {
	sum := sha256.Sum256([]byte(value))
	sha := base64.RawURLEncoding.EncodeToString(sum[:])
	if l.shas[name] == sha {
		return nil // unchanged; skip rewrite
	}
	if err := l.m.store.PutCookie(ctx, l.SessionID, name, value, sha); err != nil {
		return err
	}
	l.Cookies[name] = value
	l.shas[name] = sha
	return nil
}

// BindOwner sets OWNER_ID when it changes and rotates the KEY_ID on that
// transition (fixation defense). No-op when ownerID equals the current owner.
func (l *Live) BindOwner(ctx context.Context, ownerID int64) (bool, error) {
	if ownerID == l.OwnerID {
		return false, nil
	}
	now := l.m.clock.Now().Unix()
	sess, err := l.m.store.GetSession(ctx, l.SessionID)
	if err != nil {
		return false, err
	}
	sess.OwnerID = ownerID
	sess.LastAccess = now
	ttl := l.m.ttl(sess, now)
	if err := l.m.store.PutSession(ctx, sess, ttl); err != nil {
		return false, err
	}
	if err := l.m.store.AddOwnerIndex(ctx, ownerID, l.SessionID); err != nil {
		return false, err
	}
	// Rotate: mint a new key, keep the old one alive for the grace window.
	newKey, err := l.m.newID()
	if err != nil {
		return false, err
	}
	if err := l.m.store.PutKey(ctx, newKey, l.SessionID, ttl); err != nil {
		return false, err
	}
	// Hard-delete the old KEY_ID rather than grace it. A graced key still maps
	// to the now-authenticated session, and Resolve slides any live key's TTL
	// back to the full inactive window on use — so a graced key defeats the
	// fixation defense: an attacker who fixated a pre-auth KEY_ID could use it
	// after login (within grace) to gain authenticated access and renew it
	// indefinitely. Deleting it closes that window entirely.
	if err := l.m.store.DeleteKey(ctx, l.KeyID); err != nil {
		return false, err
	}
	l.OwnerID = ownerID
	l.KeyID = newKey
	l.newKey = newKey
	l.rewrite = true
	return true, nil
}

// RevokeOwner deletes every session bound to an owner (logout-everywhere).
func (m *Manager) RevokeOwner(ctx context.Context, ownerID int64) error {
	sids, err := m.store.OwnerSessions(ctx, ownerID)
	if err != nil {
		return err
	}
	// Attempt every deletion — logout-everywhere must not leave sessions alive
	// on a transient error — and return the first error seen.
	var firstErr error
	for _, sid := range sids {
		if err := m.store.DeleteSession(ctx, sid); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// WithLock serializes same-session work when Synchronize is enabled. When it
// is disabled, fn runs directly. A failure to acquire the lock is surfaced so
// the caller can apply fail_closed.
func (m *Manager) WithLock(ctx context.Context, sessionID string, fn func() error) error {
	if !m.cfg.Synchronize {
		return fn()
	}
	unlock, ok, err := m.store.Lock(ctx, sessionID, 5*time.Second)
	if err != nil {
		return err
	}
	if !ok {
		return ErrLockContended
	}
	defer func() { _ = unlock(ctx) }()
	return fn()
}

// ErrLockContended is returned when synchronize_sessions is on and the
// per-session lock is already held; the handler maps it through on_store_error.
var ErrLockContended = errors.New("session: lock contended")
