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

const putSessionScript = `
local actual = redis.call("TYPE", KEYS[1])["ok"]
if actual ~= "none" and actual ~= "hash" then
  return redis.error_reply("WRONGTYPE " .. KEYS[1] .. " must be hash")
end
redis.call("HSET", KEYS[1],
  "creation", ARGV[1], "last_access", ARGV[2],
  "inactive_timeout", ARGV[3], "final_timeout", ARGV[4],
  "owner_id", ARGV[5], "last_rotation", ARGV[6], "labels", ARGV[7])
if tonumber(ARGV[8]) > 0 then redis.call("PEXPIRE", KEYS[1], ARGV[8]) end
return 1
`

func (r *Redis) PutSession(ctx context.Context, s Session, ttl time.Duration) error {
	return r.c.Eval(ctx, putSessionScript, []string{r.sessKey(s.ID)},
		s.Creation, s.LastAccess, s.InactiveTimeout, s.FinalTimeout,
		s.OwnerID, s.LastRotation, s.Labels, ttl.Milliseconds()).Err()
}

const touchSessionScript = `
local expected = {"hash", "string", "hash", "hash", "set"}
for i = 1, #expected do
  local actual = redis.call("TYPE", KEYS[i])["ok"]
  if actual ~= "none" and actual ~= expected[i] then
    return redis.error_reply("WRONGTYPE " .. KEYS[i] .. " must be " .. expected[i])
  end
end
if redis.call("EXISTS", KEYS[1]) == 0 then return 0 end
if redis.call("GET", KEYS[2]) ~= ARGV[4] then return -1 end
local current_access = tonumber(redis.call("HGET", KEYS[1], "last_access") or "0") or 0
local proposed_access = tonumber(ARGV[1]) or 0
local effective_access = math.max(current_access, proposed_access)
local ttl_ms = tonumber(ARGV[3]) or 0
local inactive_ms = (tonumber(redis.call("HGET", KEYS[1], "inactive_timeout") or "0") or 0) * 1000
local creation = tonumber(redis.call("HGET", KEYS[1], "creation") or "0") or 0
local final_timeout = tonumber(redis.call("HGET", KEYS[1], "final_timeout") or "0") or 0
local now = redis.call("TIME")
local now_ms = tonumber(now[1]) * 1000 + math.floor(tonumber(now[2]) / 1000)
local final_ms = (creation + final_timeout) * 1000 - now_ms
local inactive_deadline_ms = (effective_access * 1000) + inactive_ms - now_ms
if inactive_ms > 0 and inactive_deadline_ms < ttl_ms then ttl_ms = inactive_deadline_ms end
if final_timeout > 0 and final_ms < ttl_ms then ttl_ms = final_ms end
if ttl_ms <= 0 then return 0 end
if proposed_access > current_access then
  redis.call("HSET", KEYS[1], "last_access", ARGV[1])
  for i = 1, #KEYS do
    if redis.call("EXISTS", KEYS[i]) == 1 then redis.call("PEXPIRE", KEYS[i], ttl_ms) end
  end
end
local rotation = redis.call("HGET", KEYS[1], "last_rotation")
if not rotation or tonumber(rotation) == 0 then
  redis.call("HSET", KEYS[1], "last_rotation", ARGV[2])
end
return 1
`

func (r *Redis) TouchSession(ctx context.Context, id, keyID string, lastAccess, legacyRotation int64, ttl time.Duration) error {
	result, err := r.c.Eval(ctx, touchSessionScript,
		[]string{r.sessKey(id), r.keyKey(keyID), r.attrKey(id), r.shaKey(id), r.sessKey(id) + ":keys"},
		lastAccess, legacyRotation, ttl.Milliseconds(), id).Int()
	if err != nil {
		return err
	}
	if result == 0 {
		return ErrNotFound
	}
	if result == -1 {
		return ErrConflict
	}
	return nil
}

const applySessionControlsScript = `
local expected = {"hash", "string", "string", "hash", "hash", "set"}
for i = 1, #expected do
  local actual = redis.call("TYPE", KEYS[i])["ok"]
  if actual ~= "none" and actual ~= expected[i] then
    return redis.error_reply("WRONGTYPE " .. KEYS[i] .. " must be " .. expected[i])
  end
end
if redis.call("EXISTS", KEYS[1]) == 0 then return 0 end
if tonumber(ARGV[9]) <= 0 then return 0 end
if redis.call("GET", KEYS[2]) ~= ARGV[1] then return -1 end
if ARGV[8] == "1" then
  if ARGV[12] == ARGV[13] then return -1 end
  if KEYS[3] ~= KEYS[2] and redis.call("EXISTS", KEYS[3]) == 1 then return -1 end
end
local current_access = tonumber(redis.call("HGET", KEYS[1], "last_access") or "0") or 0
local proposed_access = tonumber(ARGV[6]) or 0
local effective_access = math.max(current_access, proposed_access)
local ttl_ms = tonumber(ARGV[9]) or 0
local inactive_ms = (tonumber(redis.call("HGET", KEYS[1], "inactive_timeout") or "0") or 0) * 1000
local creation = tonumber(redis.call("HGET", KEYS[1], "creation") or "0") or 0
local final_timeout = tonumber(redis.call("HGET", KEYS[1], "final_timeout") or "0") or 0
local now = redis.call("TIME")
local now_ms = tonumber(now[1]) * 1000 + math.floor(tonumber(now[2]) / 1000)
local final_ms = (creation + final_timeout) * 1000 - now_ms
local inactive_deadline_ms = (effective_access * 1000) + inactive_ms - now_ms
if inactive_ms > 0 and inactive_deadline_ms < ttl_ms then ttl_ms = inactive_deadline_ms end
if final_timeout > 0 and final_ms < ttl_ms then ttl_ms = final_ms end
if ttl_ms <= 0 then return 0 end
local previous = redis.call("HGET", KEYS[1], "owner_id") or "0"
local previous_owner_key = ARGV[11] .. previous
local new_owner_key = ARGV[11] .. ARGV[3]
if ARGV[2] == "1" then
  local actual = redis.call("TYPE", new_owner_key)["ok"]
  if actual ~= "none" and actual ~= "set" then
    return redis.error_reply("WRONGTYPE " .. new_owner_key .. " must be set")
  end
  if previous ~= "0" and previous ~= ARGV[3] then
    actual = redis.call("TYPE", previous_owner_key)["ok"]
    if actual ~= "none" and actual ~= "set" then
      return redis.error_reply("WRONGTYPE " .. previous_owner_key .. " must be set")
    end
  end
end
if ARGV[2] == "1" and previous ~= ARGV[3] then
  redis.call("HSET", KEYS[1], "owner_id", ARGV[3])
  redis.call("SADD", new_owner_key, ARGV[1])
  if tonumber(ARGV[10]) > 0 then redis.call("PEXPIRE", new_owner_key, ARGV[10]) end
  if previous ~= "0" then redis.call("SREM", previous_owner_key, ARGV[1]) end
end
if ARGV[4] == "1" then redis.call("HSET", KEYS[1], "labels", ARGV[5]) end
local advanced = ARGV[8] == "1" or (tonumber(ARGV[14]) or 0) > 0
if proposed_access > current_access then
  redis.call("HSET", KEYS[1], "last_access", ARGV[6])
  advanced = true
end
local current_rotation = tonumber(redis.call("HGET", KEYS[1], "last_rotation") or "0") or 0
if tonumber(ARGV[7]) > current_rotation then
  redis.call("HSET", KEYS[1], "last_rotation", ARGV[7])
  advanced = true
end
local active_key = KEYS[2]
if ARGV[8] == "1" then
  redis.call("SET", KEYS[3], ARGV[1], "PX", ttl_ms)
  redis.call("DEL", KEYS[2])
  redis.call("SREM", KEYS[6], ARGV[12])
  redis.call("SADD", KEYS[6], ARGV[13])
  active_key = KEYS[3]
end
local cookie_count = tonumber(ARGV[14]) or 0
for i = 0, cookie_count - 1 do
  local offset = 15 + i * 4
  local name = ARGV[offset]
  if ARGV[offset + 3] == "1" then
    redis.call("HDEL", KEYS[4], name)
    redis.call("HDEL", KEYS[5], name)
  else
    redis.call("HSET", KEYS[4], name, ARGV[offset + 1])
    redis.call("HSET", KEYS[5], name, ARGV[offset + 2])
  end
end
if advanced then
  for _, key in ipairs({KEYS[1], active_key, KEYS[4], KEYS[5], KEYS[6]}) do
    if redis.call("EXISTS", key) == 1 then redis.call("PEXPIRE", key, ttl_ms) end
  end
end
return 1
`

func boolArg(v bool) string {
	if v {
		return "1"
	}
	return "0"
}

func (r *Redis) ApplySessionControls(ctx context.Context, id string, c SessionControls, ttl, ownerTTL time.Duration) error {
	newKeyID := c.NewKeyID
	if !c.Rotate {
		newKeyID = c.OldKeyID
	}
	args := []any{
		id, boolArg(c.SetOwner), c.OwnerID, boolArg(c.SetLabels), c.Labels,
		c.LastAccess, c.LastRotation, boolArg(c.Rotate), ttl.Milliseconds(),
		ownerTTL.Milliseconds(), r.prefix + "owner:", c.OldKeyID, newKeyID, len(c.Cookies),
	}
	for _, cookie := range c.Cookies {
		args = append(args, cookie.Name, cookie.Value, cookie.SHA, boolArg(cookie.Delete))
	}
	result, err := r.c.Eval(ctx, applySessionControlsScript,
		[]string{r.sessKey(id), r.keyKey(c.OldKeyID), r.keyKey(newKeyID), r.attrKey(id), r.shaKey(id), r.sessKey(id) + ":keys"}, args...).Int()
	if err != nil {
		return err
	}
	if result == 0 {
		return ErrNotFound
	}
	if result == -1 {
		return ErrConflict
	}
	return nil
}

func (r *Redis) RotateSessionKey(ctx context.Context, id, oldKeyID, newKeyID string, lastRotation int64, ttl time.Duration) error {
	return r.ApplySessionControls(ctx, id, SessionControls{
		LastRotation: lastRotation,
		OldKeyID:     oldKeyID,
		NewKeyID:     newKeyID,
		Rotate:       true,
	}, ttl, 0)
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

const deleteSessionScript = `
local function require_type(key, expected)
  local actual = redis.call("TYPE", key)["ok"]
  if actual ~= "none" and actual ~= expected then
    return redis.error_reply("WRONGTYPE " .. key .. " must be " .. expected)
  end
end
local expected = {"hash", "hash", "hash", "set"}
for i = 1, #expected do
  local err = require_type(KEYS[i], expected[i])
  if err then return err end
end
local owner = redis.call("HGET", KEYS[1], "owner_id") or "0"
local owner_key = ARGV[2] .. owner
if owner ~= "0" then
  local err = require_type(owner_key, "set")
  if err then return err end
end
local key_ids = redis.call("SMEMBERS", KEYS[4])
for _, key_id in ipairs(key_ids) do redis.call("DEL", ARGV[1] .. key_id) end
redis.call("DEL", KEYS[1], KEYS[2], KEYS[3], KEYS[4])
if owner ~= "0" then redis.call("SREM", owner_key, ARGV[3]) end
return 1
`

func (r *Redis) DeleteSession(ctx context.Context, id string) error {
	return r.c.Eval(ctx, deleteSessionScript,
		[]string{r.sessKey(id), r.attrKey(id), r.shaKey(id), r.sessKey(id) + ":keys"},
		r.prefix+"key:", r.prefix+"owner:", id).Err()
}

const putKeyScript = `
local function require_type(key, expected)
  local actual = redis.call("TYPE", key)["ok"]
  if actual ~= "none" and actual ~= expected then
    return redis.error_reply("WRONGTYPE " .. key .. " must be " .. expected)
  end
end
local err = require_type(KEYS[1], "hash")
if err then return err end
err = require_type(KEYS[2], "string")
if err then return err end
err = require_type(KEYS[3], "set")
if err then return err end
if redis.call("EXISTS", KEYS[1]) == 0 then return 0 end
local ttl = redis.call("PTTL", KEYS[1])
if ttl == 0 then return 0 end
if ttl > 0 then
  redis.call("SET", KEYS[2], ARGV[1], "PX", ttl)
else
  redis.call("SET", KEYS[2], ARGV[1])
end
redis.call("SADD", KEYS[3], ARGV[2])
if ttl > 0 then redis.call("PEXPIRE", KEYS[3], ttl) end
return 1
`

func (r *Redis) PutKey(ctx context.Context, keyID, sessionID string, _ time.Duration) error {
	result, err := r.c.Eval(ctx, putKeyScript,
		[]string{r.sessKey(sessionID), r.keyKey(keyID), r.sessKey(sessionID) + ":keys"},
		sessionID, keyID).Int()
	if err != nil {
		return err
	}
	if result == 0 {
		return ErrNotFound
	}
	return nil
}

const replaceKeyScript = `
local expected = {"hash", "string", "string", "set"}
for i = 1, #expected do
  local actual = redis.call("TYPE", KEYS[i])["ok"]
  if actual ~= "none" and actual ~= expected[i] then
    return redis.error_reply("WRONGTYPE " .. KEYS[i] .. " must be " .. expected[i])
  end
end
if redis.call("EXISTS", KEYS[1]) == 0 then return 0 end
if redis.call("GET", KEYS[2]) ~= ARGV[1] then return -1 end
if redis.call("EXISTS", KEYS[3]) == 1 then return -1 end
local ttl = redis.call("PTTL", KEYS[1])
if ttl == 0 then return 0 end
if ttl > 0 then
  redis.call("SET", KEYS[3], ARGV[1], "PX", ttl)
else
  redis.call("SET", KEYS[3], ARGV[1])
end
redis.call("DEL", KEYS[2])
redis.call("SREM", KEYS[4], ARGV[2])
redis.call("SADD", KEYS[4], ARGV[3])
if ttl > 0 then redis.call("PEXPIRE", KEYS[4], ttl) end
return 1
`

func (r *Redis) ReplaceKey(ctx context.Context, oldKeyID, newKeyID, sessionID string, _ time.Duration) error {
	result, err := r.c.Eval(ctx, replaceKeyScript,
		[]string{r.sessKey(sessionID), r.keyKey(oldKeyID), r.keyKey(newKeyID), r.sessKey(sessionID) + ":keys"},
		sessionID, oldKeyID, newKeyID).Int()
	if err != nil {
		return err
	}
	switch result {
	case 0:
		return ErrNotFound
	case -1:
		return ErrConflict
	default:
		return nil
	}
}

func (r *Redis) GetKey(ctx context.Context, keyID string) (string, error) {
	sid, err := r.c.Get(ctx, r.keyKey(keyID)).Result()
	if err == redis.Nil {
		return "", ErrNotFound
	}
	return sid, err
}

const deleteKeyScript = `
local actual = redis.call("TYPE", KEYS[1])["ok"]
if actual ~= "none" and actual ~= "string" then
  return redis.error_reply("WRONGTYPE " .. KEYS[1] .. " must be string")
end
if actual == "none" then return 1 end
local sid = redis.call("GET", KEYS[1])
local reverse = ARGV[1] .. sid .. ":keys"
actual = redis.call("TYPE", reverse)["ok"]
if actual ~= "none" and actual ~= "set" then
  return redis.error_reply("WRONGTYPE " .. reverse .. " must be set")
end
redis.call("DEL", KEYS[1])
redis.call("SREM", reverse, ARGV[2])
return 1
`

func (r *Redis) DeleteKey(ctx context.Context, keyID string) error {
	return r.c.Eval(ctx, deleteKeyScript, []string{r.keyKey(keyID)}, r.prefix+"sess:", keyID).Err()
}

func (r *Redis) GetCookies(ctx context.Context, sessionID string) (map[string]string, error) {
	return r.c.HGetAll(ctx, r.attrKey(sessionID)).Result()
}

func (r *Redis) CookieSHAs(ctx context.Context, sessionID string) (map[string]string, error) {
	return r.c.HGetAll(ctx, r.shaKey(sessionID)).Result()
}

const putCookieScript = `
local function require_hash(key)
  local actual = redis.call("TYPE", key)["ok"]
  if actual ~= "none" and actual ~= "hash" then
    return redis.error_reply("WRONGTYPE " .. key .. " must be hash")
  end
end
for i = 1, 3 do
  local err = require_hash(KEYS[i])
  if err then return err end
end
if redis.call("EXISTS", KEYS[1]) == 0 then return 0 end
local ttl = redis.call("PTTL", KEYS[1])
if ttl == 0 then return 0 end
redis.call("HSET", KEYS[2], ARGV[1], ARGV[2])
redis.call("HSET", KEYS[3], ARGV[1], ARGV[3])
if ttl > 0 then
  redis.call("PEXPIRE", KEYS[2], ttl)
  redis.call("PEXPIRE", KEYS[3], ttl)
end
return 1
`

func (r *Redis) PutCookie(ctx context.Context, sessionID, name, value, sha string) error {
	result, err := r.c.Eval(ctx, putCookieScript,
		[]string{r.sessKey(sessionID), r.attrKey(sessionID), r.shaKey(sessionID)},
		name, value, sha).Int()
	if err != nil {
		return err
	}
	if result == 0 {
		return ErrNotFound
	}
	return nil
}

const deleteCookieScript = `
local function require_hash(key)
  local actual = redis.call("TYPE", key)["ok"]
  if actual ~= "none" and actual ~= "hash" then
    return redis.error_reply("WRONGTYPE " .. key .. " must be hash")
  end
end
local err = require_hash(KEYS[1])
if err then return err end
err = require_hash(KEYS[2])
if err then return err end
redis.call("HDEL", KEYS[1], ARGV[1])
redis.call("HDEL", KEYS[2], ARGV[1])
return 1
`

func (r *Redis) DeleteCookie(ctx context.Context, sessionID, name string) error {
	return r.c.Eval(ctx, deleteCookieScript,
		[]string{r.attrKey(sessionID), r.shaKey(sessionID)}, name).Err()
}

const addOwnerIndexScript = `
local actual = redis.call("TYPE", KEYS[1])["ok"]
if actual ~= "none" and actual ~= "set" then
  return redis.error_reply("WRONGTYPE " .. KEYS[1] .. " must be set")
end
redis.call("SADD", KEYS[1], ARGV[1])
if tonumber(ARGV[2]) > 0 then redis.call("PEXPIRE", KEYS[1], ARGV[2]) end
return 1
`

func (r *Redis) AddOwnerIndex(ctx context.Context, ownerID int64, sessionID string, ttl time.Duration) error {
	return r.c.Eval(ctx, addOwnerIndexScript, []string{r.ownerKey(ownerID)}, sessionID, ttl.Milliseconds()).Err()
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
local previous_key = ARGV[7] .. previous
local current_access = tonumber(redis.call("HGET", KEYS[1], "last_access") or "0") or 0
local proposed_access = tonumber(ARGV[1]) or 0
local effective_access = math.max(current_access, proposed_access)
local ttl_ms = tonumber(ARGV[5]) or 0
local inactive_ms = (tonumber(redis.call("HGET", KEYS[1], "inactive_timeout") or "0") or 0) * 1000
local creation = tonumber(redis.call("HGET", KEYS[1], "creation") or "0") or 0
local final_timeout = tonumber(redis.call("HGET", KEYS[1], "final_timeout") or "0") or 0
local now = redis.call("TIME")
local now_ms = tonumber(now[1]) * 1000 + math.floor(tonumber(now[2]) / 1000)
local final_ms = (creation + final_timeout) * 1000 - now_ms
local inactive_deadline_ms = (effective_access * 1000) + inactive_ms - now_ms
if inactive_ms > 0 and inactive_deadline_ms < ttl_ms then ttl_ms = inactive_deadline_ms end
if final_timeout > 0 and final_ms < ttl_ms then ttl_ms = final_ms end
if ttl_ms <= 0 then return 0 end
if previous ~= "0" and previous ~= ARGV[3] then
  err = require_type(previous_key, "set")
  if err then return err end
end
redis.call("HSET", KEYS[1], "owner_id", ARGV[3])
redis.call("PEXPIRE", KEYS[1], ttl_ms)
if proposed_access > current_access then
  redis.call("HSET", KEYS[1], "last_access", ARGV[1])
end
local current_rotation = tonumber(redis.call("HGET", KEYS[1], "last_rotation") or "0") or 0
local proposed_rotation = tonumber(ARGV[4]) or 0
if proposed_rotation > current_rotation then
  redis.call("HSET", KEYS[1], "last_rotation", ARGV[4])
end
redis.call("SADD", KEYS[2], ARGV[2])
if tonumber(ARGV[6]) > 0 then redis.call("PEXPIRE", KEYS[2], ARGV[6]) end
if previous ~= "0" and previous ~= ARGV[3] then
  redis.call("SREM", previous_key, ARGV[2])
end
return 1
`

func (r *Redis) ReassignOwner(ctx context.Context, s Session, sessionTTL time.Duration, ownerIndexTTL time.Duration) error {
	result, err := r.c.Eval(ctx, reassignOwnerScript,
		[]string{r.sessKey(s.ID), r.ownerKey(s.OwnerID)},
		s.LastAccess, s.ID, s.OwnerID, s.LastRotation,
		sessionTTL.Milliseconds(), ownerIndexTTL.Milliseconds(), r.prefix+"owner:").Int()
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
