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
		t.Cleanup(mr.Close)
		client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
		return NewRedis(client, "gs:")
	})
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
	t.Cleanup(mr.Close)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	r := NewRedis(client, "gs:")

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
			t.Cleanup(mr.Close)
			client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
			r := NewRedis(client, "gs:")
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
