package store

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func TestRedisContract(t *testing.T) {
	RunContract(t, func() Store {
		mr, err := miniredis.Run()
		if err != nil {
			t.Fatal(err)
		}
		mr.SetTime(time.Unix(1, 0))
		t.Cleanup(mr.Close)
		client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
		return NewRedis(client, "gs:")
	})
}

func TestRedisSessionCascadeTTLsStayAligned(t *testing.T) {
	ctx := context.Background()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	mr.SetTime(time.Unix(1, 0))
	t.Cleanup(mr.Close)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	r := NewRedis(client, "gs:")
	sess := Session{ID: "sid", Creation: 1, LastAccess: 10, LastRotation: 10, InactiveTimeout: 3600, FinalTimeout: 7200}
	if err := r.PutSession(ctx, sess, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := r.PutKey(ctx, "kid", sess.ID, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := r.PutCookie(ctx, sess.ID, "JSESSIONID", "secret", "sha"); err != nil {
		t.Fatal(err)
	}
	keys := []string{"gs:sess:sid", "gs:key:kid", "gs:sess:sid:keys", "gs:sess:sid:attr", "gs:sess:sid:sha"}
	for _, key := range keys {
		if ttl := mr.TTL(key); ttl != time.Hour {
			t.Fatalf("%s TTL = %v, want 1h", key, ttl)
		}
	}

	mr.FastForward(10 * time.Minute)
	if err := r.TouchSession(ctx, sess.ID, "kid", 9, 9, time.Hour); err != nil {
		t.Fatal(err)
	}
	staleControls := SessionControls{SetLabels: true, Labels: "adm", LastAccess: 9, LastRotation: 9, OldKeyID: "kid"}
	if err := r.ApplySessionControls(ctx, sess.ID, staleControls, time.Hour, time.Hour); err != nil {
		t.Fatal(err)
	}
	for _, key := range keys {
		if ttl := mr.TTL(key); ttl != 50*time.Minute {
			t.Fatalf("stale mutation lengthened %s TTL to %v", key, ttl)
		}
	}
	if err := r.RotateSessionKey(ctx, sess.ID, "stale-kid", "losing-kid", 99, time.Hour); err != ErrConflict {
		t.Fatalf("stale rotation err = %v, want ErrConflict", err)
	}
	persisted, err := r.GetSession(ctx, sess.ID)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.LastRotation != 10 {
		t.Fatalf("CAS loser advanced LastRotation: %d", persisted.LastRotation)
	}
	for _, key := range keys {
		if ttl := mr.TTL(key); ttl != 50*time.Minute {
			t.Fatalf("CAS loser changed %s TTL to %v", key, ttl)
		}
	}

	if err := r.TouchSession(ctx, sess.ID, "kid", 11, 10, time.Hour); err != nil {
		t.Fatal(err)
	}
	for _, key := range keys {
		if ttl := mr.TTL(key); ttl != time.Hour {
			t.Fatalf("fresh touch did not align %s TTL: %v", key, ttl)
		}
	}
	mr.FastForward(2 * time.Hour)
	for _, key := range keys {
		if mr.Exists(key) {
			t.Fatalf("orphaned cascade key survived session expiry: %s", key)
		}
	}
}

// The owner set must carry a TTL that slides on each add: sessions that expire
// via Redis TTL never pass through DeleteSession, so without a set-level expiry
// an owner's index would grow forever on abandoned sessions.
func TestRedisOwnerIndexHasTTL(t *testing.T) {
	ctx := context.Background()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	mr.SetTime(time.Unix(1, 0))
	t.Cleanup(mr.Close)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	r := NewRedis(client, "gs:")

	if err := r.AddOwnerIndex(ctx, 42, "sidA", time.Hour); err != nil {
		t.Fatal(err)
	}
	if ttl := mr.TTL("gs:owner:42"); ttl != time.Hour {
		t.Fatalf("owner set TTL = %v, want 1h", ttl)
	}
	// The set (with its stale members) disappears once the TTL lapses.
	mr.FastForward(2 * time.Hour)
	sids, err := r.OwnerSessions(ctx, 42)
	if err != nil {
		t.Fatal(err)
	}
	if len(sids) != 0 {
		t.Fatalf("owner set survived its TTL: %v", sids)
	}
}

// DeleteKey must also drop the key from the session's reverse set, otherwise
// every key rotation (BindOwner, rotate_interval) leaves a dead member behind
// and the set grows unbounded over a long-lived session.
func TestRedisDeleteKeyPrunesReverseSet(t *testing.T) {
	ctx := context.Background()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	mr.SetTime(time.Unix(1, 0))
	t.Cleanup(mr.Close)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	r := NewRedis(client, "gs:")
	if err := r.PutSession(ctx, Session{ID: "sid"}, time.Hour); err != nil {
		t.Fatal(err)
	}

	if err := r.PutKey(ctx, "k1", "sid", time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := r.DeleteKey(ctx, "k1"); err != nil {
		t.Fatal(err)
	}
	members, err := client.SMembers(ctx, "gs:sess:sid:keys").Result()
	if err != nil {
		t.Fatal(err)
	}
	if len(members) != 0 {
		t.Fatalf("reverse set kept deleted key: %v", members)
	}
}

func TestRedisReassignOwnerFailureLeavesSessionAndIndexesUnchanged(t *testing.T) {
	ctx := context.Background()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	mr.SetTime(time.Unix(1, 0))
	t.Cleanup(mr.Close)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	r := NewRedis(client, "gs:")
	original := Session{ID: "sid", OwnerID: 41, Creation: 1, LastAccess: 1, InactiveTimeout: 10, FinalTimeout: 100}
	if err := r.PutSession(ctx, original, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := r.AddOwnerIndex(ctx, 41, "sid", time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := client.Set(ctx, "gs:owner:42", "wrong type", 0).Err(); err != nil {
		t.Fatal(err)
	}
	updated := original
	updated.OwnerID = 42
	if err := r.ReassignOwner(ctx, updated, time.Hour, time.Hour); err == nil {
		t.Fatal("ReassignOwner succeeded with a wrong-typed destination index")
	}
	got, err := r.GetSession(ctx, "sid")
	if err != nil || got.OwnerID != 41 {
		t.Fatalf("failed transition changed session: %+v, %v", got, err)
	}
	sids, err := r.OwnerSessions(ctx, 41)
	if err != nil || len(sids) != 1 || sids[0] != "sid" {
		t.Fatalf("failed transition changed old index: %v, %v", sids, err)
	}
	if err := client.Del(ctx, "gs:owner:42").Err(); err != nil {
		t.Fatal(err)
	}
	if err := r.ReassignOwner(ctx, updated, time.Hour, time.Hour); err != nil {
		t.Fatalf("retry did not repair transition: %v", err)
	}
}

func TestRedisReassignOwnerOldIndexFailureLeavesSessionAndNewIndexUnchanged(t *testing.T) {
	ctx := context.Background()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	mr.SetTime(time.Unix(1, 0))
	t.Cleanup(mr.Close)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	r := NewRedis(client, "gs:")
	original := Session{ID: "sid", OwnerID: 41, Creation: 1, LastAccess: 1, InactiveTimeout: 10, FinalTimeout: 100}
	if err := r.PutSession(ctx, original, time.Hour); err != nil {
		t.Fatal(err)
	}
	// This is the Redis equivalent of the former RemoveOwnerIndex step
	// failing after PutSession had already succeeded.
	if err := client.Set(ctx, "gs:owner:41", "wrong type", 0).Err(); err != nil {
		t.Fatal(err)
	}
	updated := original
	updated.OwnerID = 42
	if err := r.ReassignOwner(ctx, updated, time.Hour, time.Hour); err == nil {
		t.Fatal("ReassignOwner succeeded with a wrong-typed old owner index")
	}
	got, err := r.GetSession(ctx, "sid")
	if err != nil || got.OwnerID != 41 {
		t.Fatalf("failed transition changed session: %+v, %v", got, err)
	}
	newSIDs, err := r.OwnerSessions(ctx, 42)
	if err != nil || len(newSIDs) != 0 {
		t.Fatalf("failed transition changed new index: %v, %v", newSIDs, err)
	}
	if err := client.Del(ctx, "gs:owner:41").Err(); err != nil {
		t.Fatal(err)
	}
	if err := r.AddOwnerIndex(ctx, 41, "sid", time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := r.ReassignOwner(ctx, updated, time.Hour, time.Hour); err != nil {
		t.Fatalf("retry after repairing old index failed: %v", err)
	}
}

func TestRedisOwnerIDsAboveFloatPrecisionRemainDistinct(t *testing.T) {
	ctx := context.Background()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	mr.SetTime(time.Unix(1, 0))
	t.Cleanup(mr.Close)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	r := NewRedis(client, "gs:")
	const oldOwner int64 = 9_007_199_254_740_992
	const newOwner int64 = 9_007_199_254_740_993
	original := Session{ID: "sid", OwnerID: oldOwner, Creation: 1, LastAccess: 1, InactiveTimeout: 10, FinalTimeout: 100}
	if err := r.PutSession(ctx, original, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := r.AddOwnerIndex(ctx, oldOwner, "sid", time.Hour); err != nil {
		t.Fatal(err)
	}
	updated := original
	updated.OwnerID = newOwner
	if err := r.ReassignOwner(ctx, updated, time.Hour, time.Hour); err != nil {
		t.Fatal(err)
	}
	if ttl, err := client.PTTL(ctx, "gs:sess:sid").Result(); err != nil || ttl != 10*time.Second {
		t.Fatalf("reassignment session TTL = %v, err=%v; want 10s deadline cap", ttl, err)
	}
	if sids, err := r.OwnerSessions(ctx, oldOwner); err != nil || len(sids) != 0 {
		t.Fatalf("old large owner index not pruned: sids=%v err=%v", sids, err)
	}
	deleted, err := r.DeleteSessionByOwner(ctx, oldOwner, "sid")
	if err != nil {
		t.Fatal(err)
	}
	if deleted {
		t.Fatal("adjacent large owner ID deleted reassigned session")
	}
	got, err := r.GetSession(ctx, "sid")
	if err != nil || got.OwnerID != newOwner {
		t.Fatalf("reassigned large-owner session missing: session=%+v err=%v", got, err)
	}
}

func TestRedisExecutionTimeCapsRejectDelayedSessionMutations(t *testing.T) {
	ctx := context.Background()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mr.Close)
	mr.SetTime(time.Unix(100, 0))
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	r := NewRedis(client, "gs:")
	sess := Session{ID: "sid", Creation: 100, LastAccess: 100, InactiveTimeout: 10, FinalTimeout: 100}
	if err := r.PutSession(ctx, sess, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := r.PutKey(ctx, "key", sess.ID, time.Hour); err != nil {
		t.Fatal(err)
	}

	mr.SetTime(time.Unix(116, 0))
	if err := r.TouchSession(ctx, sess.ID, "key", 105, 105, time.Hour); err != ErrNotFound {
		t.Fatalf("delayed touch err = %v, want ErrNotFound", err)
	}
	controls := SessionControls{
		OldKeyID: "key", LastAccess: 105,
		Cookies: []CookieMutation{{Name: "JSESSIONID", Value: "stale", SHA: "stale-sha"}},
	}
	if err := r.ApplySessionControls(ctx, sess.ID, controls, time.Hour, time.Hour); err != ErrNotFound {
		t.Fatalf("delayed controls err = %v, want ErrNotFound", err)
	}
	if cookies, err := r.GetCookies(ctx, sess.ID); err != nil || len(cookies) != 0 {
		t.Fatalf("delayed controls mutated cookies: cookies=%v err=%v", cookies, err)
	}

	mr.SetTime(time.Unix(201, 0))
	if err := r.ApplySessionControls(ctx, sess.ID, SessionControls{OldKeyID: "key", LastAccess: 190}, time.Hour, time.Hour); err != ErrNotFound {
		t.Fatalf("post-final controls err = %v, want ErrNotFound", err)
	}
}

func TestRedisRevocationMutationScriptsFailAtomicallyOnWrongTypes(t *testing.T) {
	newStore := func(t *testing.T) (context.Context, *redis.Client, *Redis) {
		t.Helper()
		ctx := context.Background()
		mr, err := miniredis.Run()
		if err != nil {
			t.Fatal(err)
		}
		mr.SetTime(time.Unix(1, 0))
		t.Cleanup(mr.Close)
		client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
		t.Cleanup(func() { _ = client.Close() })
		return ctx, client, NewRedis(client, "gs:")
	}

	t.Run("PutSessionAndOwnerIndexDoNotRetimestampWrongTypes", func(t *testing.T) {
		ctx, client, r := newStore(t)
		for _, tc := range []struct {
			name string
			key  string
			call func() error
		}{
			{"session", "gs:sess:sid", func() error { return r.PutSession(ctx, Session{ID: "sid"}, time.Hour) }},
			{"owner", "gs:owner:42", func() error { return r.AddOwnerIndex(ctx, 42, "sid", time.Hour) }},
		} {
			t.Run(tc.name, func(t *testing.T) {
				if err := client.Set(ctx, tc.key, "wrong", time.Minute).Err(); err != nil {
					t.Fatal(err)
				}
				before, _ := client.PTTL(ctx, tc.key).Result()
				if err := tc.call(); err == nil {
					t.Fatal("mutation succeeded with wrong-typed key")
				}
				after, _ := client.PTTL(ctx, tc.key).Result()
				if after != before {
					t.Fatalf("wrong-type failure changed TTL: before=%v after=%v", before, after)
				}
			})
		}
	})

	t.Run("PutCookie", func(t *testing.T) {
		ctx, client, r := newStore(t)
		if err := r.PutSession(ctx, Session{ID: "sid"}, time.Hour); err != nil {
			t.Fatal(err)
		}
		if err := client.HSet(ctx, "gs:sess:sid:attr", "JSESSIONID", "old").Err(); err != nil {
			t.Fatal(err)
		}
		if err := client.Set(ctx, "gs:sess:sid:sha", "wrong type", 0).Err(); err != nil {
			t.Fatal(err)
		}
		if err := r.PutCookie(ctx, "sid", "JSESSIONID", "new", "new-sha"); err == nil {
			t.Fatal("PutCookie succeeded with wrong-typed SHA key")
		}
		if got, _ := client.HGet(ctx, "gs:sess:sid:attr", "JSESSIONID").Result(); got != "old" {
			t.Fatalf("failed PutCookie changed value peer: %q", got)
		}
	})

	t.Run("SessionFieldUpdates", func(t *testing.T) {
		ctx, client, r := newStore(t)
		if err := client.Set(ctx, "gs:sess:sid", "wrong", 0).Err(); err != nil {
			t.Fatal(err)
		}
		for name, mutate := range map[string]func() error{
			"touch": func() error { return r.TouchSession(ctx, "sid", "key", 2, 2, time.Hour) },
			"controls": func() error {
				return r.ApplySessionControls(ctx, "sid", SessionControls{OldKeyID: "key", SetLabels: true, Labels: "adm"}, time.Hour, time.Hour)
			},
		} {
			if err := mutate(); err == nil {
				t.Fatalf("%s succeeded with wrong-typed session", name)
			}
		}
		if got, err := client.Get(ctx, "gs:sess:sid").Result(); err != nil || got != "wrong" {
			t.Fatalf("wrong-typed session changed: value=%q err=%v", got, err)
		}
	})

	t.Run("PutKey", func(t *testing.T) {
		ctx, client, r := newStore(t)
		if err := r.PutSession(ctx, Session{ID: "sid"}, time.Hour); err != nil {
			t.Fatal(err)
		}
		if err := client.Set(ctx, "gs:sess:sid:keys", "wrong type", 0).Err(); err != nil {
			t.Fatal(err)
		}
		if err := r.PutKey(ctx, "new-key", "sid", time.Hour); err == nil {
			t.Fatal("PutKey succeeded with wrong-typed reverse set")
		}
		if _, err := r.GetKey(ctx, "new-key"); err != ErrNotFound {
			t.Fatalf("failed PutKey created mapping: %v", err)
		}
	})

	t.Run("ReplaceKey", func(t *testing.T) {
		ctx, client, r := newStore(t)
		if err := r.PutSession(ctx, Session{ID: "sid"}, time.Hour); err != nil {
			t.Fatal(err)
		}
		if err := r.PutKey(ctx, "old-key", "sid", time.Hour); err != nil {
			t.Fatal(err)
		}
		if err := client.Del(ctx, "gs:sess:sid:keys").Err(); err != nil {
			t.Fatal(err)
		}
		if err := client.Set(ctx, "gs:sess:sid:keys", "wrong type", 0).Err(); err != nil {
			t.Fatal(err)
		}
		if err := r.ReplaceKey(ctx, "old-key", "new-key", "sid", time.Hour); err == nil {
			t.Fatal("ReplaceKey succeeded with wrong-typed reverse set")
		}
		if sid, err := r.GetKey(ctx, "old-key"); err != nil || sid != "sid" {
			t.Fatalf("failed ReplaceKey removed old mapping: sid=%q err=%v", sid, err)
		}
		if _, err := r.GetKey(ctx, "new-key"); err != ErrNotFound {
			t.Fatalf("failed ReplaceKey created new mapping: %v", err)
		}
	})

	t.Run("ApplySessionControls", func(t *testing.T) {
		ctx, client, r := newStore(t)
		if err := r.PutSession(ctx, Session{ID: "sid", LastAccess: 1}, time.Hour); err != nil {
			t.Fatal(err)
		}
		if err := r.PutKey(ctx, "old-key", "sid", time.Hour); err != nil {
			t.Fatal(err)
		}
		if err := client.Set(ctx, "gs:sess:sid:attr", "wrong type", 0).Err(); err != nil {
			t.Fatal(err)
		}
		controls := SessionControls{
			SetOwner: true, OwnerID: 42, SetLabels: true, Labels: "adm",
			LastAccess: 2, LastRotation: 2, OldKeyID: "old-key", NewKeyID: "new-key", Rotate: true,
		}
		if err := r.ApplySessionControls(ctx, "sid", controls, time.Hour, time.Hour); err == nil {
			t.Fatal("ApplySessionControls succeeded with wrong-typed attribute key")
		}
		got, err := r.GetSession(ctx, "sid")
		if err != nil || got.OwnerID != 0 || got.Labels != "" || got.LastRotation != 0 {
			t.Fatalf("failed controls changed session: %+v err=%v", got, err)
		}
		if sid, err := r.GetKey(ctx, "old-key"); err != nil || sid != "sid" {
			t.Fatalf("failed controls removed old key: sid=%q err=%v", sid, err)
		}
		if _, err := r.GetKey(ctx, "new-key"); err != ErrNotFound {
			t.Fatalf("failed controls created new key: %v", err)
		}
	})

	t.Run("DeleteSession", func(t *testing.T) {
		ctx, client, r := newStore(t)
		sess := Session{ID: "sid", OwnerID: 42}
		if err := r.PutSession(ctx, sess, time.Hour); err != nil {
			t.Fatal(err)
		}
		if err := r.PutKey(ctx, "key", "sid", time.Hour); err != nil {
			t.Fatal(err)
		}
		if err := r.PutCookie(ctx, "sid", "JSESSIONID", "secret", "sha"); err != nil {
			t.Fatal(err)
		}
		if err := client.Set(ctx, "gs:owner:42", "wrong type", 0).Err(); err != nil {
			t.Fatal(err)
		}
		if err := r.DeleteSession(ctx, "sid"); err == nil {
			t.Fatal("DeleteSession succeeded with wrong-typed owner index")
		}
		if _, err := r.GetSession(ctx, "sid"); err != nil {
			t.Fatalf("failed DeleteSession removed session: %v", err)
		}
		if sid, err := r.GetKey(ctx, "key"); err != nil || sid != "sid" {
			t.Fatalf("failed DeleteSession removed key: sid=%q err=%v", sid, err)
		}
		if got, _ := r.GetCookies(ctx, "sid"); got["JSESSIONID"] != "secret" {
			t.Fatalf("failed DeleteSession removed cookie: %v", got)
		}
	})
}

func TestRedisDeleteCookieFailureLeavesValueAndSHAUnchanged(t *testing.T) {
	for _, tc := range []struct {
		name          string
		wrongTypeKey  string
		wantCookie    bool
		wantCookieSHA bool
	}{
		{name: "attribute hash wrong type", wrongTypeKey: "gs:sess:sid:attr", wantCookie: false, wantCookieSHA: true},
		{name: "SHA hash wrong type", wrongTypeKey: "gs:sess:sid:sha", wantCookie: true, wantCookieSHA: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			mr, err := miniredis.Run()
			if err != nil {
				t.Fatal(err)
			}
			mr.SetTime(time.Unix(1, 0))
			t.Cleanup(mr.Close)
			client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
			r := NewRedis(client, "gs:")
			if err := r.PutSession(ctx, Session{ID: "sid"}, time.Hour); err != nil {
				t.Fatal(err)
			}
			if err := r.PutCookie(ctx, "sid", "JSESSIONID", "secret", "sha"); err != nil {
				t.Fatal(err)
			}
			if err := client.Del(ctx, tc.wrongTypeKey).Err(); err != nil {
				t.Fatal(err)
			}
			if err := client.Set(ctx, tc.wrongTypeKey, "wrong type", 0).Err(); err != nil {
				t.Fatal(err)
			}
			if err := r.DeleteCookie(ctx, "sid", "JSESSIONID"); err == nil {
				t.Fatal("DeleteCookie succeeded with a wrong-typed hash")
			}
			cookieExists, err := client.HExists(ctx, "gs:sess:sid:attr", "JSESSIONID").Result()
			if err != nil && tc.wantCookie {
				t.Fatal(err)
			}
			shaExists, err := client.HExists(ctx, "gs:sess:sid:sha", "JSESSIONID").Result()
			if err != nil && tc.wantCookieSHA {
				t.Fatal(err)
			}
			if cookieExists != tc.wantCookie || shaExists != tc.wantCookieSHA {
				t.Fatalf("failed delete changed peer hash: cookie=%v sha=%v", cookieExists, shaExists)
			}
		})
	}
}
