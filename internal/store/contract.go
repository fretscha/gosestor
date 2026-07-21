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
		sess := Session{ID: "sid", Creation: 100, LastAccess: 100, InactiveTimeout: 1800, FinalTimeout: 28800, Labels: "adm default"}
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
		// Labels persist round-trip; a legacy session without the field must
		// read back as the empty set.
		if got.Labels != "adm default" {
			t.Fatalf("labels = %q, want %q", got.Labels, "adm default")
		}
	})

	t.Run("missing session is ErrNotFound", func(t *testing.T) {
		s := newStore()
		if _, err := s.GetSession(ctx, "nope"); err != ErrNotFound {
			t.Fatalf("err = %v, want ErrNotFound", err)
		}
	})

	t.Run("stale mutations cannot recreate a deleted session", func(t *testing.T) {
		s := newStore()
		missing := Session{ID: "gone", Creation: 1, LastAccess: 2, InactiveTimeout: 10, FinalTimeout: 100}
		if err := s.TouchSession(ctx, missing.ID, "missing-key", 2, 2, time.Hour); err != ErrNotFound {
			t.Fatalf("TouchSession err = %v, want ErrNotFound", err)
		}
		controls := SessionControls{OldKeyID: "missing-key", LastRotation: 2}
		if err := s.ApplySessionControls(ctx, missing.ID, controls, time.Hour, time.Hour); err != ErrNotFound {
			t.Fatalf("ApplySessionControls err = %v, want ErrNotFound", err)
		}
		if err := s.PutKey(ctx, "orphan-key", "gone", time.Hour); err != ErrNotFound {
			t.Fatalf("PutKey err = %v, want ErrNotFound", err)
		}
		if _, err := s.GetKey(ctx, "orphan-key"); err != ErrNotFound {
			t.Fatalf("orphan key was created: %v", err)
		}
		if err := s.PutCookie(ctx, "gone", "JSESSIONID", "secret", "sha"); err != ErrNotFound {
			t.Fatalf("PutCookie err = %v, want ErrNotFound", err)
		}
		if values, _ := s.GetCookies(ctx, "gone"); len(values) != 0 {
			t.Fatalf("orphan cookie was created: %v", values)
		}
		if shas, _ := s.CookieSHAs(ctx, "gone"); len(shas) != 0 {
			t.Fatalf("orphan cookie SHA was created: %v", shas)
		}
	})

	t.Run("field-scoped updates preserve unrelated state", func(t *testing.T) {
		s := newStore()
		original := Session{
			ID: "scoped", Creation: 1, LastAccess: 1, InactiveTimeout: 10,
			FinalTimeout: 100, OwnerID: 42, LastRotation: 10, Labels: "default",
		}
		if err := s.PutSession(ctx, original, time.Hour); err != nil {
			t.Fatal(err)
		}
		if err := s.PutKey(ctx, "scoped-key", original.ID, time.Hour); err != nil {
			t.Fatal(err)
		}
		if err := s.TouchSession(ctx, original.ID, "scoped-key", 2, 99, time.Hour); err != nil {
			t.Fatal(err)
		}
		got, _ := s.GetSession(ctx, original.ID)
		if got.LastAccess != 2 || got.LastRotation != 10 || got.OwnerID != 42 || got.Labels != "default" {
			t.Fatalf("touch overwrote unrelated state: %+v", got)
		}
		if err := s.RotateSessionKey(ctx, original.ID, "scoped-key", "rotated-key", 20, time.Hour); err != nil {
			t.Fatal(err)
		}
		got, _ = s.GetSession(ctx, original.ID)
		if got.LastRotation != 20 || got.OwnerID != 42 || got.Labels != "default" {
			t.Fatalf("rotation overwrote unrelated state: %+v", got)
		}
		controls := SessionControls{SetLabels: true, Labels: "adm", LastAccess: 3, OldKeyID: "rotated-key"}
		if err := s.ApplySessionControls(ctx, original.ID, controls, time.Hour, time.Hour); err != nil {
			t.Fatal(err)
		}
		got, _ = s.GetSession(ctx, original.ID)
		if got.Labels != "adm" || got.LastAccess != 3 || got.LastRotation != 20 || got.OwnerID != 42 {
			t.Fatalf("label-only update overwrote unrelated state: %+v", got)
		}
		controls.Labels = "default adm"
		controls.LastAccess = 4
		controls.LastRotation = 30
		if err := s.ApplySessionControls(ctx, original.ID, controls, time.Hour, time.Hour); err != nil {
			t.Fatal(err)
		}
		got, _ = s.GetSession(ctx, original.ID)
		if got.Labels != "default adm" || got.LastAccess != 4 || got.LastRotation != 30 || got.OwnerID != 42 {
			t.Fatalf("label+rotation update mismatch: %+v", got)
		}
		if err := s.TouchSession(ctx, original.ID, "rotated-key", 3, 20, time.Hour); err != nil {
			t.Fatal(err)
		}
		controls.Labels = "latest"
		controls.LastAccess = 3
		controls.LastRotation = 20
		if err := s.ApplySessionControls(ctx, original.ID, controls, time.Hour, time.Hour); err != nil {
			t.Fatal(err)
		}
		got, _ = s.GetSession(ctx, original.ID)
		if got.Labels != "latest" || got.LastAccess != 4 || got.LastRotation != 30 {
			t.Fatalf("stale temporal update regressed state: %+v", got)
		}
	})

	t.Run("atomic key replacement admits only one winner", func(t *testing.T) {
		s := newStore()
		_ = s.PutSession(ctx, Session{ID: "sid", Creation: 1, LastAccess: 1, InactiveTimeout: 10, FinalTimeout: 100}, time.Hour)
		_ = s.PutKey(ctx, "old", "sid", time.Hour)
		if err := s.ReplaceKey(ctx, "old", "new-1", "sid", time.Hour); err != nil {
			t.Fatal(err)
		}
		if err := s.ReplaceKey(ctx, "old", "new-2", "sid", time.Hour); err != ErrConflict {
			t.Fatalf("losing replacement err = %v, want ErrConflict", err)
		}
		if _, err := s.GetKey(ctx, "old"); err != ErrNotFound {
			t.Fatalf("old key survived: %v", err)
		}
		if sid, err := s.GetKey(ctx, "new-1"); err != nil || sid != "sid" {
			t.Fatalf("winning key = %q, %v", sid, err)
		}
		if _, err := s.GetKey(ctx, "new-2"); err != ErrNotFound {
			t.Fatalf("losing key became valid: %v", err)
		}
	})

	t.Run("equal old and new rotation key is rejected atomically", func(t *testing.T) {
		s := newStore()
		original := Session{ID: "equal-key", Creation: 1, LastAccess: 1, InactiveTimeout: 10, FinalTimeout: 100, LastRotation: 1}
		if err := s.PutSession(ctx, original, time.Hour); err != nil {
			t.Fatal(err)
		}
		if err := s.PutKey(ctx, "same-key", original.ID, time.Hour); err != nil {
			t.Fatal(err)
		}
		controls := SessionControls{
			OldKeyID: "same-key", NewKeyID: "same-key", Rotate: true,
			LastAccess: 2, LastRotation: 2,
		}
		if err := s.ApplySessionControls(ctx, original.ID, controls, time.Hour, time.Hour); err != ErrConflict {
			t.Fatalf("equal-key rotation err = %v, want ErrConflict", err)
		}
		if sid, err := s.GetKey(ctx, "same-key"); err != nil || sid != original.ID {
			t.Fatalf("equal-key conflict changed mapping: sid=%q err=%v", sid, err)
		}
		got, err := s.GetSession(ctx, original.ID)
		if err != nil || got.LastAccess != original.LastAccess || got.LastRotation != original.LastRotation {
			t.Fatalf("equal-key conflict changed session: got=%+v err=%v", got, err)
		}
	})

	t.Run("atomic response controls are all-or-nothing", func(t *testing.T) {
		s := newStore()
		original := Session{ID: "controls", Creation: 1, LastAccess: 1, InactiveTimeout: 10, FinalTimeout: 100, OwnerID: 1, Labels: "default"}
		_ = s.PutSession(ctx, original, time.Hour)
		_ = s.PutKey(ctx, "old-controls", original.ID, time.Hour)
		_ = s.AddOwnerIndex(ctx, 1, original.ID, time.Hour)
		controls := SessionControls{
			SetOwner: true, OwnerID: 2, SetLabels: true, Labels: "adm",
			LastAccess: 2, LastRotation: 2, OldKeyID: "old-controls", NewKeyID: "new-controls", Rotate: true,
			Cookies: []CookieMutation{{Name: "JSESSIONID", Value: "winner", SHA: "winner-sha"}},
		}
		if err := s.ApplySessionControls(ctx, original.ID, controls, time.Hour, time.Hour); err != nil {
			t.Fatal(err)
		}
		got, err := s.GetSession(ctx, original.ID)
		if err != nil || got.OwnerID != 2 || got.Labels != "adm" || got.LastAccess != 2 || got.LastRotation != 2 {
			t.Fatalf("controls mismatch: %+v err=%v", got, err)
		}
		if _, err := s.GetKey(ctx, "old-controls"); err != ErrNotFound {
			t.Fatalf("old controls key survived: %v", err)
		}
		if sid, err := s.GetKey(ctx, "new-controls"); err != nil || sid != original.ID {
			t.Fatalf("new controls key = %q, %v", sid, err)
		}
		if err := s.TouchSession(ctx, original.ID, "old-controls", 99, 99, time.Hour); err != ErrConflict {
			t.Fatalf("stale touch err = %v, want ErrConflict", err)
		}
		controls.NewKeyID = "losing-controls"
		controls.OwnerID = 3
		controls.Labels = "stale"
		controls.LastAccess = 3
		controls.LastRotation = 3
		controls.Cookies = []CookieMutation{{Name: "JSESSIONID", Value: "stale", SHA: "stale-sha"}}
		if err := s.ApplySessionControls(ctx, original.ID, controls, time.Hour, time.Hour); err != ErrConflict {
			t.Fatalf("stale controls err = %v, want ErrConflict", err)
		}
		got, _ = s.GetSession(ctx, original.ID)
		if got.OwnerID != 2 || got.Labels != "adm" || got.LastRotation != 2 {
			t.Fatalf("stale controls partially applied: %+v", got)
		}
		cookies, _ := s.GetCookies(ctx, original.ID)
		shas, _ := s.CookieSHAs(ctx, original.ID)
		if cookies["JSESSIONID"] != "winner" || shas["JSESSIONID"] != "winner-sha" {
			t.Fatalf("stale controls changed cookies: cookies=%v shas=%v", cookies, shas)
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
		if err := s.DeleteCookie(ctx, "sid", "JSESSIONID"); err != nil {
			t.Fatal(err)
		}
		if err := s.DeleteCookie(ctx, "sid", "JSESSIONID"); err != nil {
			t.Fatalf("repeated DeleteCookie must be idempotent: %v", err)
		}
		vals, _ = s.GetCookies(ctx, "sid")
		shas, _ = s.CookieSHAs(ctx, "sid")
		if _, ok := vals["JSESSIONID"]; ok {
			t.Fatalf("deleted cookie remains: %v", vals)
		}
		if _, ok := shas["JSESSIONID"]; ok {
			t.Fatalf("deleted cookie SHA remains: %v", shas)
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

	t.Run("owner reassignment refuses a missing session", func(t *testing.T) {
		s := newStore()
		sess := Session{ID: "missing", OwnerID: 42, Creation: 1, LastAccess: 1, InactiveTimeout: 10, FinalTimeout: 100}
		if err := s.ReassignOwner(ctx, sess, time.Hour, time.Hour); err != ErrNotFound {
			t.Fatalf("ReassignOwner missing session error = %v, want ErrNotFound", err)
		}
		if sids, err := s.OwnerSessions(ctx, 42); err != nil || len(sids) != 0 {
			t.Fatalf("missing session was added to owner index: sids=%v err=%v", sids, err)
		}
	})

	t.Run("owner reassignment updates row and indexes atomically", func(t *testing.T) {
		s := newStore()
		original := Session{ID: "sid", OwnerID: 41, Creation: 1, LastAccess: 1, InactiveTimeout: 10, FinalTimeout: 100, LastRotation: 10, Labels: "default"}
		if err := s.PutSession(ctx, original, time.Hour); err != nil {
			t.Fatal(err)
		}
		if err := s.AddOwnerIndex(ctx, 41, "sid", time.Hour); err != nil {
			t.Fatal(err)
		}
		updated := original
		updated.OwnerID = 42
		updated.LastAccess = 2
		updated.Labels = "stale"
		updated.Creation = 999
		if err := s.ReassignOwner(ctx, updated, time.Hour, 2*time.Hour); err != nil {
			t.Fatal(err)
		}
		got, err := s.GetSession(ctx, "sid")
		if err != nil || got.OwnerID != 42 || got.LastAccess != 2 || got.Creation != 1 || got.Labels != "default" {
			t.Fatalf("session after reassignment = %+v, %v", got, err)
		}
		oldSIDs, err := s.OwnerSessions(ctx, 41)
		if err != nil || len(oldSIDs) != 0 {
			t.Fatalf("old owner index = %v, %v", oldSIDs, err)
		}
		newSIDs, err := s.OwnerSessions(ctx, 42)
		if err != nil || len(newSIDs) != 1 || newSIDs[0] != "sid" {
			t.Fatalf("new owner index = %v, %v", newSIDs, err)
		}
	})

	t.Run("owner-conditional delete removes the complete session", func(t *testing.T) {
		s := newStore()
		sess := Session{ID: "sid", OwnerID: 42, Creation: 1, LastAccess: 1, InactiveTimeout: 10, FinalTimeout: 100}
		if err := s.PutSession(ctx, sess, time.Hour); err != nil {
			t.Fatal(err)
		}
		if err := s.PutKey(ctx, "key", "sid", time.Hour); err != nil {
			t.Fatal(err)
		}
		if err := s.PutCookie(ctx, "sid", "JSESSIONID", "secret", "sha"); err != nil {
			t.Fatal(err)
		}
		if err := s.AddOwnerIndex(ctx, 42, "sid", time.Hour); err != nil {
			t.Fatal(err)
		}
		deleted, err := s.DeleteSessionByOwner(ctx, 42, "sid")
		if err != nil || !deleted {
			t.Fatalf("DeleteSessionByOwner = deleted=%v err=%v", deleted, err)
		}
		if _, err := s.GetSession(ctx, "sid"); err != ErrNotFound {
			t.Fatalf("session survived owner delete: %v", err)
		}
		if _, err := s.GetKey(ctx, "key"); err != ErrNotFound {
			t.Fatalf("key survived owner delete: %v", err)
		}
		if cookies, err := s.GetCookies(ctx, "sid"); err != nil || len(cookies) != 0 {
			t.Fatalf("cookies survived owner delete: cookies=%v err=%v", cookies, err)
		}
		if shas, err := s.CookieSHAs(ctx, "sid"); err != nil || len(shas) != 0 {
			t.Fatalf("cookie SHAs survived owner delete: shas=%v err=%v", shas, err)
		}
		if sids, err := s.OwnerSessions(ctx, 42); err != nil || len(sids) != 0 {
			t.Fatalf("owner index survived owner delete: sids=%v err=%v", sids, err)
		}
	})

	t.Run("owner-conditional delete preserves reassigned session", func(t *testing.T) {
		s := newStore()
		original := Session{ID: "sid", OwnerID: 41, Creation: 1, LastAccess: 1, InactiveTimeout: 10, FinalTimeout: 100}
		if err := s.PutSession(ctx, original, time.Hour); err != nil {
			t.Fatal(err)
		}
		if err := s.AddOwnerIndex(ctx, 41, "sid", time.Hour); err != nil {
			t.Fatal(err)
		}
		updated := original
		updated.OwnerID = 42
		if err := s.ReassignOwner(ctx, updated, time.Hour, time.Hour); err != nil {
			t.Fatal(err)
		}
		deleted, err := s.DeleteSessionByOwner(ctx, 41, "sid")
		if err != nil {
			t.Fatal(err)
		}
		if deleted {
			t.Fatal("delete reported a session now owned by someone else")
		}
		got, err := s.GetSession(ctx, "sid")
		if err != nil || got.OwnerID != 42 {
			t.Fatalf("reassigned session was deleted: %+v, %v", got, err)
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
