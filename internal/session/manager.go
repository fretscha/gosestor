package session

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/fretscha/gosestor/internal/store"
)

// Config holds the timeout and behavior knobs the Manager needs.
type Config struct {
	Inactive    time.Duration
	Final       time.Duration
	Synchronize bool
	// RotateOnLogin rotates the KEY_ID on an OWNER_ID transition (fixation
	// defense). Callers must set it explicitly; the handler defaults it to true.
	RotateOnLogin bool
	// RotateInterval, when > 0, rotates a session's KEY_ID on the first request
	// after this much time has elapsed since the last rotation. Zero disables it.
	// The rotation is decided in Resolve but executed by MaybeRotate on the
	// response path, so a failed request can never strand the client's key.
	RotateInterval time.Duration
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
	Labels    []string // sorted, deduped authorization labels (see SetLabels)

	m         *Manager
	shas      map[string]string
	newKey    string // set when a proxy cookie must be (re)written
	rewrite   bool
	rotateDue bool // interval rotation decided in Resolve, executed in MaybeRotate
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
		LastRotation:    now,
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
	// Decide whether this request crosses a periodic-rotation boundary. The key
	// swap itself is deferred to MaybeRotate on the response path: destroying
	// the old KEY_ID here, before the replacement cookie is guaranteed to reach
	// the client, would strand the session on any upstream/response failure.
	rotateDue := false
	if m.cfg.RotateInterval > 0 {
		if sess.LastRotation == 0 {
			// Pre-rotation session (created before rotate_interval existed):
			// start its clock now instead of mass-rotating every legacy session
			// on its first post-upgrade request.
			sess.LastRotation = now
		} else {
			rotateDue = now-sess.LastRotation >= int64(m.cfg.RotateInterval.Seconds())
		}
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
		Labels:  strings.Fields(sess.Labels),
		Cookies: cookies, shas: shas, m: m, rotateDue: rotateDue,
	}, nil
}

// MaybeRotate executes an interval rotation decided during Resolve. It must run
// on the response path — after the upstream completed, under the per-session
// lock when synchronize_sessions is on — so the old KEY_ID is only hard-deleted
// once its replacement cookie cannot miss the response. It re-reads the session
// so a concurrent request that already rotated is detected and skipped.
func (l *Live) MaybeRotate(ctx context.Context) error {
	if !l.rotateDue || l.rewrite {
		// Not due, or this request already carries a fresh key (Begin or a
		// login rotation) — a second swap would churn keys for nothing.
		return nil
	}
	now := l.m.clock.Now().Unix()
	sess, err := l.m.store.GetSession(ctx, l.SessionID)
	if err != nil {
		return err
	}
	if now-sess.LastRotation < int64(l.m.cfg.RotateInterval.Seconds()) {
		return nil // a concurrent request rotated meanwhile
	}
	sess.LastRotation = now
	ttl := l.m.ttl(sess, now)
	// LastRotation is persisted BEFORE the key swap: if the swap fails, the
	// client keeps its still-valid old key and rotation retries next interval.
	// The reverse order could delete the old key and then fail before the new
	// cookie is emitted, stranding the client.
	if err := l.m.store.PutSession(ctx, sess, ttl); err != nil {
		return err
	}
	return l.rotateKey(ctx, ttl)
}

// ForceRotate executes a backend-requested rotation (step-up re-auth,
// suspicious account, …). Like MaybeRotate it must run on the response path,
// under the per-session lock when synchronize_sessions is on. LastRotation is
// persisted BEFORE the key swap — on a partial failure the client keeps its
// still-valid old key — and the swap hard-deletes the old key: every backend
// trigger is security-motivated, so the pre-trigger key must not keep
// resolving to the now-elevated session. Setting LastRotation also resets the
// periodic clock, so an interval rotation never immediately follows.
func (l *Live) ForceRotate(ctx context.Context) error {
	if l.rewrite {
		return nil // a fresh key is already pending in this response
	}
	now := l.m.clock.Now().Unix()
	sess, err := l.m.store.GetSession(ctx, l.SessionID)
	if err != nil {
		return err
	}
	sess.LastRotation = now
	ttl := l.m.ttl(sess, now)
	if err := l.m.store.PutSession(ctx, sess, ttl); err != nil {
		return err
	}
	return l.rotateKey(ctx, ttl)
}

// normalizeLabels sorts, dedupes, and drops empty entries, returning the
// canonical space-joined form stored in the session.
func normalizeLabels(labels []string) string {
	seen := map[string]bool{}
	var out []string
	for _, l := range labels {
		l = strings.TrimSpace(l)
		if l == "" || seen[l] {
			continue
		}
		seen[l] = true
		out = append(out, l)
	}
	sort.Strings(out)
	return strings.Join(out, " ")
}

// HasLabel reports whether the session's label set contains label.
func (l *Live) HasLabel(label string) bool {
	return slices.Contains(l.Labels, label)
}

// SetLabels REPLACES the session's label set (grant and downgrade are the
// same symmetric operation) and rotates the KEY_ID when the set changed — a
// label change is a same-owner privilege change, exactly what OWASP's
// renew-on-privilege-change covers. The rotation is skipped when this
// response already carries a fresh key (rewrite pending): labels still
// persist, only the redundant second swap is elided. Persistence ordering
// matches every other rotation: session (labels + LastRotation) FIRST, key
// swap last, so a partial failure leaves the client's old key valid.
func (l *Live) SetLabels(ctx context.Context, labels []string) (bool, error) {
	norm := normalizeLabels(labels)
	if norm == strings.Join(l.Labels, " ") {
		return false, nil
	}
	now := l.m.clock.Now().Unix()
	sess, err := l.m.store.GetSession(ctx, l.SessionID)
	if err != nil {
		return false, err
	}
	sess.Labels = norm
	sess.LastAccess = now
	rotate := !l.rewrite
	if rotate {
		sess.LastRotation = now // this rotation also resets the periodic clock
	}
	ttl := l.m.ttl(sess, now)
	if err := l.m.store.PutSession(ctx, sess, ttl); err != nil {
		return false, err
	}
	l.Labels = strings.Fields(norm)
	if !rotate {
		return true, nil
	}
	if err := l.rotateKey(ctx, ttl); err != nil {
		return false, err
	}
	return true, nil
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
// transition (fixation defense, gated by RotateOnLogin). No-op when ownerID
// equals the current owner or is non-positive: 0 is the anonymous sentinel and
// negatives are invalid, and neither may ever reach the owner index — the
// delete-time pruning skips owner 0, so an indexed 0-set could never shrink.
func (l *Live) BindOwner(ctx context.Context, ownerID int64) (bool, error) {
	if ownerID <= 0 || ownerID == l.OwnerID {
		return false, nil
	}
	now := l.m.clock.Now().Unix()
	sess, err := l.m.store.GetSession(ctx, l.SessionID)
	if err != nil {
		return false, err
	}
	sess.OwnerID = ownerID
	sess.LastAccess = now
	if l.m.cfg.RotateOnLogin {
		sess.LastRotation = now // the fixation rotation below also resets the periodic clock
	}
	ttl := l.m.ttl(sess, now)
	if err := l.m.store.ReassignOwner(ctx, sess, ttl, time.Duration(sess.FinalTimeout)*time.Second); err != nil {
		return false, err
	}
	l.OwnerID = ownerID
	if !l.m.cfg.RotateOnLogin {
		return false, nil
	}
	// Rotate the KEY_ID on the identity transition (session-fixation defense).
	if err := l.rotateKey(ctx, ttl); err != nil {
		return false, err
	}
	return true, nil
}

// rotateKey mints a fresh KEY_ID, persists it, and hard-deletes the current one,
// marking the handle so the new proxy cookie is re-emitted on the response.
//
// The old KEY_ID is hard-deleted rather than graced. A graced key still maps to
// the session, and Resolve slides any live key's TTL back to the full inactive
// window on use — so a graced key would defeat the fixation defense: an attacker
// who fixated a pre-auth KEY_ID could use it after login (within grace) to gain
// authenticated access and renew it indefinitely. Deleting it closes that window.
func (l *Live) rotateKey(ctx context.Context, ttl time.Duration) error {
	newKey, err := l.m.newID()
	if err != nil {
		return err
	}
	// PutKey before DeleteKey: on a partial store failure the new key is orphaned but is never issued to the client.
	if err := l.m.store.PutKey(ctx, newKey, l.SessionID, ttl); err != nil {
		return err
	}
	if err := l.m.store.DeleteKey(ctx, l.KeyID); err != nil {
		return err
	}
	l.KeyID = newKey
	l.newKey = newKey
	l.rewrite = true
	return nil
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
		if _, err := m.store.DeleteSessionByOwner(ctx, ownerID, sid); err != nil {
			if firstErr == nil {
				firstErr = err
			}
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
