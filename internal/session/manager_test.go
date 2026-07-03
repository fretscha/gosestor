package session

import (
	"context"
	"testing"
	"time"

	"gosestor/internal/store"
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
		Inactive: 30 * time.Minute,
		Final:    8 * time.Hour,
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
