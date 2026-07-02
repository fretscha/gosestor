package session

import (
	"context"
	"crypto/rand"
	"encoding/base64"
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
	ttl := m.cfg.Inactive
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
