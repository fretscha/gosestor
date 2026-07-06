package store

import (
	"context"
	"testing"
	"time"
)

// RunContract exercises any Store implementation. newStore must return a fresh,
// empty store per call.
func RunContract(t *testing.T, newStore func() Store) {
	ctx := context.Background()

	t.Run("session round-trip", func(t *testing.T) {
		s := newStore()
		sess := Session{ID: "sid", Creation: 100, LastAccess: 100, InactiveTimeout: 1800, FinalTimeout: 28800}
		if err := s.PutSession(ctx, sess, time.Hour); err != nil {
			t.Fatal(err)
		}
		got, err := s.GetSession(ctx, "sid")
		if err != nil {
			t.Fatal(err)
		}
		if got.ID != "sid" || got.FinalTimeout != 28800 {
			t.Fatalf("got %+v", got)
		}
	})

	t.Run("missing session is ErrNotFound", func(t *testing.T) {
		s := newStore()
		if _, err := s.GetSession(ctx, "nope"); err != ErrNotFound {
			t.Fatalf("err = %v, want ErrNotFound", err)
		}
	})

	t.Run("key mapping and delete cascade", func(t *testing.T) {
		s := newStore()
		_ = s.PutSession(ctx, Session{ID: "sid", Creation: 1, LastAccess: 1, InactiveTimeout: 10, FinalTimeout: 100}, time.Hour)
		_ = s.PutKey(ctx, "k1", "sid", time.Hour)
		if sid, err := s.GetKey(ctx, "k1"); err != nil || sid != "sid" {
			t.Fatalf("GetKey = %q, %v", sid, err)
		}
		_ = s.DeleteSession(ctx, "sid")
		if _, err := s.GetKey(ctx, "k1"); err != ErrNotFound {
			t.Fatalf("key survived session delete: %v", err)
		}
	})

	t.Run("cookies and shas", func(t *testing.T) {
		s := newStore()
		_ = s.PutSession(ctx, Session{ID: "sid", Creation: 1, LastAccess: 1, InactiveTimeout: 10, FinalTimeout: 100}, time.Hour)
		_ = s.PutCookie(ctx, "sid", "JSESSIONID", "abc", "sha1")
		vals, _ := s.GetCookies(ctx, "sid")
		if vals["JSESSIONID"] != "abc" {
			t.Fatalf("cookies = %v", vals)
		}
		shas, _ := s.CookieSHAs(ctx, "sid")
		if shas["JSESSIONID"] != "sha1" {
			t.Fatalf("shas = %v", shas)
		}
	})

	t.Run("owner index", func(t *testing.T) {
		s := newStore()
		_ = s.AddOwnerIndex(ctx, 42, "sidA", time.Hour)
		_ = s.AddOwnerIndex(ctx, 42, "sidB", time.Hour)
		sids, _ := s.OwnerSessions(ctx, 42)
		if len(sids) != 2 {
			t.Fatalf("owner sessions = %v", sids)
		}
	})

	t.Run("owner index prunes deleted session", func(t *testing.T) {
		// Deleting a session must drop it from its owner's index, otherwise the
		// owner set grows without bound as sessions come and go.
		s := newStore()
		_ = s.PutSession(ctx, Session{ID: "sidA", OwnerID: 42, Creation: 1, LastAccess: 1, InactiveTimeout: 10, FinalTimeout: 100}, time.Hour)
		_ = s.PutSession(ctx, Session{ID: "sidB", OwnerID: 42, Creation: 1, LastAccess: 1, InactiveTimeout: 10, FinalTimeout: 100}, time.Hour)
		_ = s.AddOwnerIndex(ctx, 42, "sidA", time.Hour)
		_ = s.AddOwnerIndex(ctx, 42, "sidB", time.Hour)
		_ = s.DeleteSession(ctx, "sidA")
		sids, _ := s.OwnerSessions(ctx, 42)
		if len(sids) != 1 || sids[0] != "sidB" {
			t.Fatalf("owner index after delete = %v, want [sidB]", sids)
		}
	})

	t.Run("remove owner index entry", func(t *testing.T) {
		// RemoveOwnerIndex prunes a specific member — including stale sids whose
		// session already expired via TTL and so never went through
		// DeleteSession's owner-aware cascade.
		s := newStore()
		_ = s.AddOwnerIndex(ctx, 42, "stale", time.Hour)
		_ = s.AddOwnerIndex(ctx, 42, "live", time.Hour)
		if err := s.RemoveOwnerIndex(ctx, 42, "stale"); err != nil {
			t.Fatal(err)
		}
		sids, _ := s.OwnerSessions(ctx, 42)
		if len(sids) != 1 || sids[0] != "live" {
			t.Fatalf("owner index after remove = %v, want [live]", sids)
		}
	})

	t.Run("lock is exclusive then released", func(t *testing.T) {
		s := newStore()
		unlock, ok, err := s.Lock(ctx, "sid", time.Minute)
		if err != nil || !ok {
			t.Fatalf("first lock failed: ok=%v err=%v", ok, err)
		}
		if _, ok2, _ := s.Lock(ctx, "sid", time.Minute); ok2 {
			t.Fatal("second lock should not be acquired")
		}
		if err := unlock(ctx); err != nil {
			t.Fatal(err)
		}
		if _, ok3, _ := s.Lock(ctx, "sid", time.Minute); !ok3 {
			t.Fatal("lock should be re-acquirable after unlock")
		}
	})
}
