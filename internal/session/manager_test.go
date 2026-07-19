package session

import (
	"context"
	"testing"
	"time"

	"github.com/fretscha/gosestor/internal/store"
)

type fakeClock struct{ t time.Time }

func (c *fakeClock) Now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

// deterministic non-random reader for key/session id generation in tests.
//
// A constant byte stream cannot back this: every 256-bit id would base64 to the
// same string, so a rotated KEY_ID would equal the original and the rotation
// test could never pass. We instead emit a monotonically increasing byte
// sequence — fully reproducible, but distinct per read window, so successive
// ids (session, key, rotated key) differ.
type fixedRandReader struct{ n byte }

func (r *fixedRandReader) Read(p []byte) (int, error) {
	for i := range p {
		r.n++
		p[i] = r.n
	}
	return len(p), nil
}

func fixedRand() *fixedRandReader { return &fixedRandReader{} }

func newTestManager(clk Clock) (*Manager, *store.Memory) {
	st := store.NewMemory()
	m := NewManager(st, clk, Config{
		Inactive:      30 * time.Minute,
		Final:         8 * time.Hour,
		RotateOnLogin: true,
	}, fixedRand())
	return m, st
}

func TestBeginThenResolve(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_000_000, 0)}
	m, _ := newTestManager(clk)
	ctx := context.Background()

	live, err := m.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	val, changed := live.NewProxyCookie()
	if !changed || val == "" {
		t.Fatalf("new session must emit a proxy cookie: val=%q changed=%v", val, changed)
	}

	got, err := m.Resolve(ctx, val)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.SessionID != live.SessionID {
		t.Fatalf("resolve mismatch: %+v", got)
	}
}

func TestInactiveTimeoutExpires(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_000_000, 0)}
	m, _ := newTestManager(clk)
	ctx := context.Background()
	live, _ := m.Begin(ctx)
	key, _ := live.NewProxyCookie()

	clk.advance(31 * time.Minute) // past 30m inactive window
	got, err := m.Resolve(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Fatal("session should have expired on inactivity")
	}
}

func TestFinalTimeoutExpiresDespiteActivity(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_000_000, 0)}
	m, _ := newTestManager(clk)
	ctx := context.Background()
	live, _ := m.Begin(ctx)
	key, _ := live.NewProxyCookie()

	// Stay active every 20 minutes, but cross the 8h final cap.
	for i := 0; i < 25; i++ {
		clk.advance(20 * time.Minute)
		got, err := m.Resolve(ctx, key)
		if err != nil {
			t.Fatal(err)
		}
		if got == nil {
			// Expired at some point after 8h — assert it was after the cap.
			if clk.t.Unix()-1_000_000 < int64((8 * time.Hour).Seconds()) {
				t.Fatal("expired before final timeout")
			}
			return
		}
	}
	t.Fatal("session never hit the final timeout")
}

func TestStoreCookieDedupe(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_000_000, 0)}
	m, st := newTestManager(clk)
	ctx := context.Background()
	live, _ := m.Begin(ctx)

	if err := live.StoreCookie(ctx, "JSESSIONID", "abc"); err != nil {
		t.Fatal(err)
	}
	vals, _ := st.GetCookies(ctx, live.SessionID)
	if vals["JSESSIONID"] != "abc" {
		t.Fatalf("cookie not stored: %v", vals)
	}
	// Same value → sha match → no error, value unchanged.
	if err := live.StoreCookie(ctx, "JSESSIONID", "abc"); err != nil {
		t.Fatal(err)
	}
}

func TestBindOwnerRotatesOnTransition(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_000_000, 0)}
	m, st := newTestManager(clk)
	ctx := context.Background()
	live, _ := m.Begin(ctx)
	firstKey := live.KeyID

	rotated, err := live.BindOwner(ctx, 42)
	if err != nil {
		t.Fatal(err)
	}
	if !rotated {
		t.Fatal("0->user must rotate the key")
	}
	newKey, changed := live.NewProxyCookie()
	if !changed || newKey == firstKey {
		t.Fatalf("expected a rotated key, got %q (changed=%v)", newKey, changed)
	}
	// New key resolves; owner is set.
	got, _ := m.Resolve(ctx, newKey)
	if got == nil || got.OwnerID != 42 {
		t.Fatalf("owner not bound: %+v", got)
	}
	sids, _ := st.OwnerSessions(ctx, 42)
	if len(sids) != 1 {
		t.Fatalf("owner index missing: %v", sids)
	}

	// Same owner again → no rotation.
	got2, _ := m.Resolve(ctx, newKey)
	rotated2, _ := got2.BindOwner(ctx, 42)
	if rotated2 {
		t.Fatal("same owner must not rotate")
	}
}

// TestBindOwnerNoRotateWhenDisabled: rotate_on_login false must bind the owner
// and index the session but leave the KEY_ID untouched.
func TestBindOwnerNoRotateWhenDisabled(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_000_000, 0)}
	st := store.NewMemory()
	m := NewManager(st, clk, Config{
		Inactive:      30 * time.Minute,
		Final:         8 * time.Hour,
		RotateOnLogin: false,
	}, fixedRand())
	ctx := context.Background()
	live, _ := m.Begin(ctx)
	firstKey := live.KeyID
	// Drain the Begin-time cookie so a later rewrite is observable in isolation.
	got, err := m.Resolve(ctx, firstKey)
	if err != nil {
		t.Fatal(err)
	}

	rotated, err := got.BindOwner(ctx, 42)
	if err != nil {
		t.Fatal(err)
	}
	if rotated {
		t.Fatal("rotation ran despite rotate_on_login=false")
	}
	if _, changed := got.NewProxyCookie(); changed {
		t.Fatal("no new cookie should be emitted without rotation")
	}
	// Owner is bound, key unchanged, index written.
	r, _ := m.Resolve(ctx, firstKey)
	if r == nil || r.OwnerID != 42 {
		t.Fatalf("owner not bound with rotation disabled: %+v", r)
	}
	sids, _ := st.OwnerSessions(ctx, 42)
	if len(sids) != 1 {
		t.Fatalf("owner index missing: %v", sids)
	}
}

// TestBindOwnerIgnoresNonPositiveOwner: owner id 0 is the anonymous sentinel
// and negatives are invalid — binding must be a no-op so the owner index can
// never accumulate an un-prunable 0/negative set.
func TestBindOwnerIgnoresNonPositiveOwner(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_000_000, 0)}
	m, st := newTestManager(clk)
	ctx := context.Background()
	live, _ := m.Begin(ctx)
	_, _ = live.BindOwner(ctx, 42) // authenticated first

	for _, bad := range []int64{0, -5} {
		rotated, err := live.BindOwner(ctx, bad)
		if err != nil {
			t.Fatal(err)
		}
		if rotated {
			t.Fatalf("BindOwner(%d) must be a no-op", bad)
		}
	}
	if live.OwnerID != 42 {
		t.Fatalf("owner clobbered by non-positive bind: %d", live.OwnerID)
	}
	if sids, _ := st.OwnerSessions(ctx, 0); len(sids) != 0 {
		t.Fatalf("owner-0 index written: %v", sids)
	}
}

// TestBindOwnerInvalidatesOldKey is the session-fixation regression guard: a
// KEY_ID known before authentication must not resolve after the OWNER_ID
// transition rotates it away, even immediately (no grace revival).
func TestBindOwnerInvalidatesOldKey(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_000_000, 0)}
	m, _ := newTestManager(clk)
	ctx := context.Background()
	live, _ := m.Begin(ctx)
	oldKey := live.KeyID

	if _, err := live.BindOwner(ctx, 42); err != nil {
		t.Fatal(err)
	}
	// The pre-auth key must be dead immediately.
	if got, err := m.Resolve(ctx, oldKey); err != nil || got != nil {
		t.Fatalf("fixated pre-auth key still resolves after rotation: got=%+v err=%v", got, err)
	}
	// And it must stay dead on a later attempt (no TTL revival path).
	clk.advance(time.Second)
	if got, _ := m.Resolve(ctx, oldKey); got != nil {
		t.Fatal("old key resurfaced on a subsequent request")
	}
}

func newRotatingManager(clk Clock, interval time.Duration) (*Manager, *store.Memory) {
	st := store.NewMemory()
	m := NewManager(st, clk, Config{
		Inactive:       30 * time.Minute,
		Final:          8 * time.Hour,
		RotateOnLogin:  true,
		RotateInterval: interval,
	}, fixedRand())
	return m, st
}

// TestRotateIntervalDefersRotationToResponsePath pins the two-phase rotation
// contract: Resolve only *decides* that rotation is due — it must not touch the
// key, so an upstream/response failure can never strand the client with a
// hard-deleted KEY_ID. MaybeRotate (called on the response path, under the
// session lock) performs the swap and emits the replacement cookie.
func TestRotateIntervalDefersRotationToResponsePath(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_000_000, 0)}
	m, _ := newRotatingManager(clk, 10*time.Minute)
	ctx := context.Background()
	live, _ := m.Begin(ctx)
	firstKey := live.KeyID

	// Within the interval: nothing due.
	clk.advance(5 * time.Minute)
	got, err := m.Resolve(ctx, firstKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := got.MaybeRotate(ctx); err != nil {
		t.Fatal(err)
	}
	if _, changed := got.NewProxyCookie(); changed {
		t.Fatal("rotation happened before the interval elapsed")
	}

	// Past the interval: Resolve alone must leave the old key fully intact.
	clk.advance(6 * time.Minute) // 11m since last rotation
	got2, err := m.Resolve(ctx, firstKey)
	if err != nil {
		t.Fatal(err)
	}
	if got2 == nil {
		t.Fatal("session expired unexpectedly")
	}
	if _, changed := got2.NewProxyCookie(); changed {
		t.Fatal("Resolve must not rotate on the request path")
	}
	if still, _ := m.Resolve(ctx, firstKey); still == nil {
		t.Fatal("old key must survive Resolve at the boundary (rotation is response-path)")
	}

	// MaybeRotate executes the swap: new cookie, old key dead, new key live.
	if err := got2.MaybeRotate(ctx); err != nil {
		t.Fatal(err)
	}
	newKey, changed := got2.NewProxyCookie()
	if !changed || newKey == firstKey {
		t.Fatalf("interval elapsed but key not rotated: newKey=%q changed=%v", newKey, changed)
	}
	if old, _ := m.Resolve(ctx, firstKey); old != nil {
		t.Fatal("old key still resolves after interval rotation")
	}
	if r, _ := m.Resolve(ctx, newKey); r == nil {
		t.Fatal("rotated key does not resolve")
	}
}

// TestRotateIntervalBackfillsLegacySession: sessions created before
// rotate_interval existed have last_rotation == 0. They must NOT all rotate on
// their first post-upgrade request (thundering herd at deploy time); instead
// the rotation clock starts at that request.
func TestRotateIntervalBackfillsLegacySession(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_000_000, 0)}
	m, st := newRotatingManager(clk, 10*time.Minute)
	ctx := context.Background()

	// Simulate a pre-upgrade session: no LastRotation field.
	now := clk.Now().Unix()
	sess := store.Session{
		ID: "legacy", Creation: now, LastAccess: now,
		InactiveTimeout: 1800, FinalTimeout: 28800, LastRotation: 0,
	}
	if err := st.PutSession(ctx, sess, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := st.PutKey(ctx, "legacy-key", "legacy", time.Hour); err != nil {
		t.Fatal(err)
	}

	clk.advance(20 * time.Minute) // well past the interval by wall clock
	live, err := m.Resolve(ctx, "legacy-key")
	if err != nil {
		t.Fatal(err)
	}
	if err := live.MaybeRotate(ctx); err != nil {
		t.Fatal(err)
	}
	if _, changed := live.NewProxyCookie(); changed {
		t.Fatal("legacy session rotated on first post-upgrade request")
	}

	// The clock started at the first request; the NEXT interval does rotate.
	clk.advance(11 * time.Minute)
	live2, err := m.Resolve(ctx, "legacy-key")
	if err != nil {
		t.Fatal(err)
	}
	if err := live2.MaybeRotate(ctx); err != nil {
		t.Fatal(err)
	}
	if _, changed := live2.NewProxyCookie(); !changed {
		t.Fatal("rotation clock did not start at the backfill request")
	}
}

// TestMaybeRotateSkipsAfterLoginRotation: when an interval boundary and an
// identity bind land in the same request, only the login rotation runs — a
// second swap would churn keys for nothing.
func TestMaybeRotateSkipsAfterLoginRotation(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_000_000, 0)}
	m, _ := newRotatingManager(clk, 10*time.Minute)
	ctx := context.Background()
	live, _ := m.Begin(ctx)
	firstKey := live.KeyID

	clk.advance(11 * time.Minute)
	got, err := m.Resolve(ctx, firstKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := got.BindOwner(ctx, 42); err != nil {
		t.Fatal(err)
	}
	keyAfterBind := got.KeyID
	if err := got.MaybeRotate(ctx); err != nil {
		t.Fatal(err)
	}
	if got.KeyID != keyAfterBind {
		t.Fatal("interval rotation ran on top of the login rotation")
	}
}

// TestMaybeRotateRechecksStore: two in-flight requests resolved with the same
// key at the boundary must not both rotate — the second MaybeRotate re-reads
// LastRotation under the lock and skips, so only one replacement cookie exists.
func TestMaybeRotateRechecksStore(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_000_000, 0)}
	m, _ := newRotatingManager(clk, 10*time.Minute)
	ctx := context.Background()
	live, _ := m.Begin(ctx)
	firstKey := live.KeyID

	clk.advance(11 * time.Minute)
	r1, err := m.Resolve(ctx, firstKey)
	if err != nil {
		t.Fatal(err)
	}
	r2, err := m.Resolve(ctx, firstKey) // concurrent request, same old key
	if err != nil {
		t.Fatal(err)
	}

	if err := r1.MaybeRotate(ctx); err != nil {
		t.Fatal(err)
	}
	if _, changed := r1.NewProxyCookie(); !changed {
		t.Fatal("first request must rotate")
	}
	if err := r2.MaybeRotate(ctx); err != nil {
		t.Fatal(err)
	}
	if _, changed := r2.NewProxyCookie(); changed {
		t.Fatal("second concurrent request must detect the fresh rotation and skip")
	}
}

func TestRevokeOwnerKillsAllSessions(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_000_000, 0)}
	m, st := newTestManager(clk)
	ctx := context.Background()
	live, _ := m.Begin(ctx)
	_, _ = live.BindOwner(ctx, 7)

	if err := m.RevokeOwner(ctx, 7); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetSession(ctx, live.SessionID); err != store.ErrNotFound {
		t.Fatalf("session survived revoke: %v", err)
	}
}

// TestRevokeOwnerPrunesStaleIndexEntries: sessions that expired via store TTL
// never pass through DeleteSession's owner-aware cascade, so their sids linger
// in the owner set. RevokeOwner knows the owner and must prune every member it
// walks — live or stale — or the set can only grow.
func TestRevokeOwnerPrunesStaleIndexEntries(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_000_000, 0)}
	m, st := newTestManager(clk)
	ctx := context.Background()
	live, _ := m.Begin(ctx)
	_, _ = live.BindOwner(ctx, 7)
	// A sid whose session no longer exists (TTL-expired before revoke).
	_ = st.AddOwnerIndex(ctx, 7, "ttl-expired-sid", time.Hour)

	if err := m.RevokeOwner(ctx, 7); err != nil {
		t.Fatal(err)
	}
	if sids, _ := st.OwnerSessions(ctx, 7); len(sids) != 0 {
		t.Fatalf("owner index not fully pruned after revoke: %v", sids)
	}
}
