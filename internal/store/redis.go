package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

// Redis implements Store over any RESP-compatible server.
type Redis struct {
	c      redis.UniversalClient
	prefix string
}

func NewRedis(client redis.UniversalClient, prefix string) *Redis {
	return &Redis{c: client, prefix: prefix}
}

func (r *Redis) sessKey(id string) string   { return r.prefix + "sess:" + id }
func (r *Redis) attrKey(id string) string   { return r.prefix + "sess:" + id + ":attr" }
func (r *Redis) shaKey(id string) string    { return r.prefix + "sess:" + id + ":sha" }
func (r *Redis) keyKey(k string) string     { return r.prefix + "key:" + k }
func (r *Redis) ownerKey(o int64) string    { return r.prefix + "owner:" + strconv.FormatInt(o, 10) }
func (r *Redis) lockKey(id string) string   { return r.prefix + "lock:" + id }

func (r *Redis) PutSession(ctx context.Context, s Session, ttl time.Duration) error {
	pipe := r.c.TxPipeline()
	pipe.HSet(ctx, r.sessKey(s.ID), map[string]any{
		"creation":         s.Creation,
		"last_access":      s.LastAccess,
		"inactive_timeout": s.InactiveTimeout,
		"final_timeout":    s.FinalTimeout,
		"owner_id":         s.OwnerID,
	})
	if ttl > 0 {
		pipe.Expire(ctx, r.sessKey(s.ID), ttl)
	}
	_, err := pipe.Exec(ctx)
	return err
}

func (r *Redis) GetSession(ctx context.Context, id string) (Session, error) {
	vals, err := r.c.HGetAll(ctx, r.sessKey(id)).Result()
	if err != nil {
		return Session{}, err
	}
	if len(vals) == 0 {
		return Session{}, ErrNotFound
	}
	atoi := func(k string) int64 { n, _ := strconv.ParseInt(vals[k], 10, 64); return n }
	return Session{
		ID:              id,
		Creation:        atoi("creation"),
		LastAccess:      atoi("last_access"),
		InactiveTimeout: atoi("inactive_timeout"),
		FinalTimeout:    atoi("final_timeout"),
		OwnerID:         atoi("owner_id"),
	}, nil
}

func (r *Redis) DeleteSession(ctx context.Context, id string) error {
	keyIDs, _ := r.c.SMembers(ctx, r.sessKey(id)+":keys").Result()
	pipe := r.c.TxPipeline()
	for _, k := range keyIDs {
		pipe.Del(ctx, r.keyKey(k))
	}
	pipe.Del(ctx, r.sessKey(id), r.attrKey(id), r.shaKey(id), r.sessKey(id)+":keys")
	_, err := pipe.Exec(ctx)
	return err
}

func (r *Redis) PutKey(ctx context.Context, keyID, sessionID string, ttl time.Duration) error {
	pipe := r.c.TxPipeline()
	pipe.Set(ctx, r.keyKey(keyID), sessionID, ttl)
	pipe.SAdd(ctx, r.sessKey(sessionID)+":keys", keyID)
	_, err := pipe.Exec(ctx)
	return err
}

func (r *Redis) GetKey(ctx context.Context, keyID string) (string, error) {
	sid, err := r.c.Get(ctx, r.keyKey(keyID)).Result()
	if err == redis.Nil {
		return "", ErrNotFound
	}
	return sid, err
}

func (r *Redis) SetKeyTTL(ctx context.Context, keyID string, ttl time.Duration) error {
	return r.c.Expire(ctx, r.keyKey(keyID), ttl).Err()
}

func (r *Redis) DeleteKey(ctx context.Context, keyID string) error {
	return r.c.Del(ctx, r.keyKey(keyID)).Err()
}

func (r *Redis) GetCookies(ctx context.Context, sessionID string) (map[string]string, error) {
	return r.c.HGetAll(ctx, r.attrKey(sessionID)).Result()
}

func (r *Redis) CookieSHAs(ctx context.Context, sessionID string) (map[string]string, error) {
	return r.c.HGetAll(ctx, r.shaKey(sessionID)).Result()
}

func (r *Redis) PutCookie(ctx context.Context, sessionID, name, value, sha string) error {
	pipe := r.c.TxPipeline()
	pipe.HSet(ctx, r.attrKey(sessionID), name, value)
	pipe.HSet(ctx, r.shaKey(sessionID), name, sha)
	_, err := pipe.Exec(ctx)
	return err
}

func (r *Redis) AddOwnerIndex(ctx context.Context, ownerID int64, sessionID string) error {
	return r.c.SAdd(ctx, r.ownerKey(ownerID), sessionID).Err()
}

func (r *Redis) OwnerSessions(ctx context.Context, ownerID int64) ([]string, error) {
	return r.c.SMembers(ctx, r.ownerKey(ownerID)).Result()
}

func (r *Redis) Refresh(ctx context.Context, sessionID string, ttl time.Duration) error {
	if ttl <= 0 {
		return nil
	}
	pipe := r.c.TxPipeline()
	pipe.Expire(ctx, r.sessKey(sessionID), ttl)
	pipe.Expire(ctx, r.attrKey(sessionID), ttl)
	pipe.Expire(ctx, r.shaKey(sessionID), ttl)
	pipe.Expire(ctx, r.sessKey(sessionID)+":keys", ttl)
	_, err := pipe.Exec(ctx)
	return err
}

// Lock uses SET NX PX. unlock deletes the token only if we still own it.
func (r *Redis) Lock(ctx context.Context, sessionID string, ttl time.Duration) (func(context.Context) error, bool, error) {
	// token is derived from crypto/rand to prevent stale unlocks releasing another holder's lock.
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return nil, false, err
	}
	token := hex.EncodeToString(buf)
	ok, err := r.c.SetNX(ctx, r.lockKey(sessionID), token, ttl).Result()
	if err != nil || !ok {
		return nil, false, err
	}
	unlock := func(ctx context.Context) error {
		const script = `if redis.call("get", KEYS[1]) == ARGV[1] then return redis.call("del", KEYS[1]) else return 0 end`
		return r.c.Eval(ctx, script, []string{r.lockKey(sessionID)}, token).Err()
	}
	return unlock, true, nil
}

func (r *Redis) Ping(ctx context.Context) error { return r.c.Ping(ctx).Err() }
