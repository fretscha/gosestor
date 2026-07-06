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
