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

func (r *Redis) sessKey(id string) string { return r.prefix + "sess:" + id }
func (r *Redis) attrKey(id string) string { return r.prefix + "sess:" + id + ":attr" }
func (r *Redis) shaKey(id string) string  { return r.prefix + "sess:" + id + ":sha" }
func (r *Redis) keyKey(k string) string   { return r.prefix + "key:" + k }
func (r *Redis) ownerKey(o int64) string  { return r.prefix + "owner:" + strconv.FormatInt(o, 10) }
func (r *Redis) lockKey(id string) string { return r.prefix + "lock:" + id }

func (r *Redis) PutSession(ctx context.Context, s Session, ttl time.Duration) error {
	pipe := r.c.TxPipeline()
	pipe.HSet(ctx, r.sessKey(s.ID), map[string]any{
		"creation":         s.Creation,
		"last_access":      s.LastAccess,
		"inactive_timeout": s.InactiveTimeout,
		"final_timeout":    s.FinalTimeout,
		"owner_id":         s.OwnerID,
		"last_rotation":    s.LastRotation,
		"labels":           s.Labels,
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
		LastRotation:    atoi("last_rotation"),
		Labels:          vals["labels"],
	}, nil
}

func (r *Redis) DeleteSession(ctx context.Context, id string) error {
	keyIDs, err := r.c.SMembers(ctx, r.sessKey(id)+":keys").Result()
	if err != nil {
		return err
	}
	// Read the owner before the hash is gone so we can prune the owner index;
	// owner_id 0 is anonymous and has no index entry. A missing hash (already
	// expired) is fine — a real read failure must not silently skip the prune.
	ownerID, err := r.c.HGet(ctx, r.sessKey(id), "owner_id").Int64()
	if err != nil && err != redis.Nil {
		return err
	}
	pipe := r.c.TxPipeline()
	for _, k := range keyIDs {
		pipe.Del(ctx, r.keyKey(k))
	}
	pipe.Del(ctx, r.sessKey(id), r.attrKey(id), r.shaKey(id), r.sessKey(id)+":keys")
	if ownerID != 0 {
		pipe.SRem(ctx, r.ownerKey(ownerID), id)
	}
	_, err = pipe.Exec(ctx)
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
	// Look up the owning session so we can also drop this key from its reverse
	// set; leaving it there lets the set grow unbounded across key rotations.
	sid, err := r.c.Get(ctx, r.keyKey(keyID)).Result()
	if err != nil && err != redis.Nil {
		return err
	}
	pipe := r.c.TxPipeline()
	pipe.Del(ctx, r.keyKey(keyID))
	if err == nil { // key existed; prune its reverse-set membership
		pipe.SRem(ctx, r.sessKey(sid)+":keys", keyID)
	}
	_, err = pipe.Exec(ctx)
	return err
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

func (r *Redis) AddOwnerIndex(ctx context.Context, ownerID int64, sessionID string, ttl time.Duration) error {
	pipe := r.c.TxPipeline()
	pipe.SAdd(ctx, r.ownerKey(ownerID), sessionID)
	if ttl > 0 {
		// Slide the whole set's TTL on each login so an abandoned owner set
		// (all member sessions TTL-expired) eventually disappears itself.
		pipe.Expire(ctx, r.ownerKey(ownerID), ttl)
	}
	_, err := pipe.Exec(ctx)
	return err
}

func (r *Redis) RemoveOwnerIndex(ctx context.Context, ownerID int64, sessionID string) error {
	return r.c.SRem(ctx, r.ownerKey(ownerID), sessionID).Err()
}

func (r *Redis) OwnerSessions(ctx context.Context, ownerID int64) ([]string, error) {
	return r.c.SMembers(ctx, r.ownerKey(ownerID)).Result()
}

const reassignOwnerScript = `
local function require_type(key, expected)
  local actual = redis.call("TYPE", key)["ok"]
  if actual ~= "none" and actual ~= expected then
    return redis.error_reply("WRONGTYPE " .. key .. " must be " .. expected)
  end
end
local err = require_type(KEYS[1], "hash")
if err then return err end
err = require_type(KEYS[2], "set")
if err then return err end
if redis.call("EXISTS", KEYS[1]) == 0 then return 0 end
local previous = redis.call("HGET", KEYS[1], "owner_id") or "0"
local previous_key = ARGV[11] .. previous
if previous ~= "0" and previous ~= ARGV[6] then
  err = require_type(previous_key, "set")
  if err then return err end
end
redis.call("HSET", KEYS[1],
  "creation", ARGV[1], "last_access", ARGV[2],
  "inactive_timeout", ARGV[3], "final_timeout", ARGV[4],
  "owner_id", ARGV[6], "last_rotation", ARGV[7], "labels", ARGV[8])
if tonumber(ARGV[9]) > 0 then redis.call("PEXPIRE", KEYS[1], ARGV[9]) end
redis.call("SADD", KEYS[2], ARGV[5])
if tonumber(ARGV[10]) > 0 then redis.call("PEXPIRE", KEYS[2], ARGV[10]) end
if previous ~= "0" and previous ~= ARGV[6] then
  redis.call("SREM", previous_key, ARGV[5])
end
return 1
`

func (r *Redis) ReassignOwner(ctx context.Context, s Session, sessionTTL, ownerIndexTTL time.Duration) error {
	result, err := r.c.Eval(ctx, reassignOwnerScript,
		[]string{r.sessKey(s.ID), r.ownerKey(s.OwnerID)},
		s.Creation, s.LastAccess, s.InactiveTimeout, s.FinalTimeout, s.ID,
		s.OwnerID, s.LastRotation, s.Labels, sessionTTL.Milliseconds(),
		ownerIndexTTL.Milliseconds(), r.prefix+"owner:").Int()
	if err != nil {
		return err
	}
	if result == 0 {
		return ErrNotFound
	}
	return nil
}

const deleteSessionByOwnerScript = `
local function require_type(key, expected)
  local actual = redis.call("TYPE", key)["ok"]
  if actual ~= "none" and actual ~= expected then
    return redis.error_reply("WRONGTYPE " .. key .. " must be " .. expected)
  end
end
local expected = {"hash", "set", "hash", "hash", "set"}
for i = 1, #expected do
  local err = require_type(KEYS[i], expected[i])
  if err then return err end
end
local current = redis.call("HGET", KEYS[1], "owner_id") or "0"
if current ~= ARGV[1] then
  redis.call("SREM", KEYS[2], ARGV[2])
  return 0
end
local key_ids = redis.call("SMEMBERS", KEYS[5])
for _, key_id in ipairs(key_ids) do redis.call("DEL", ARGV[3] .. key_id) end
redis.call("DEL", KEYS[1], KEYS[3], KEYS[4], KEYS[5])
redis.call("SREM", KEYS[2], ARGV[2])
return 1
`

func (r *Redis) DeleteSessionByOwner(ctx context.Context, ownerID int64, sessionID string) (bool, error) {
	result, err := r.c.Eval(ctx, deleteSessionByOwnerScript,
		[]string{r.sessKey(sessionID), r.ownerKey(ownerID), r.attrKey(sessionID), r.shaKey(sessionID), r.sessKey(sessionID) + ":keys"},
		ownerID, sessionID, r.prefix+"key:").Int()
	return result == 1, err
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
