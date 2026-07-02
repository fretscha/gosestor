package store

import (
	"testing"

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
