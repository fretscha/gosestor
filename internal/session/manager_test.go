package session

import (
	"bytes"
	"context"
	"testing"
	"time"

	"gosestor/internal/store"
)

type fakeClock struct{ t time.Time }

func (c *fakeClock) Now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

// deterministic non-random reader for key/session id generation in tests.
func fixedRand() *bytes.Reader {
	return bytes.NewReader(bytes.Repeat([]byte{0xAB}, 4096))
}

func newTestManager(clk Clock) (*Manager, *store.Memory) {
	st := store.NewMemory()
	m := NewManager(st, clk, Config{
		Inactive: 30 * time.Minute,
		Final:    8 * time.Hour,
		Grace:    time.Minute,
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
