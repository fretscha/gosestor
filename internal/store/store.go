package store

import (
	"context"
	"errors"
	"time"
)

// ErrNotFound is returned by getters when a session/key is absent or expired.
var ErrNotFound = errors.New("store: not found")

// ErrConflict is returned when an atomic conditional mutation loses a race.
var ErrConflict = errors.New("store: conflict")

// Session mirrors the reference `session` table. Times and timeouts are Unix
// seconds / seconds.
type Session struct {
	ID              string
	Creation        int64
	LastAccess      int64
	InactiveTimeout int64
	FinalTimeout    int64
	OwnerID         int64
	LastRotation    int64 // Unix seconds of the last KEY_ID rotation (for rotate_interval)
	// Labels is the session's authorization label set, space-joined and
	// normalized (sorted, deduped) by the session manager. "" = no labels.
	Labels string
}

type CookieMutation struct {
	Name   string
	Value  string
	SHA    string
	Delete bool
}

type SessionControls struct {
	SetOwner     bool
	OwnerID      int64
	SetLabels    bool
	Labels       string
	LastAccess   int64
	LastRotation int64
	OldKeyID     string
	NewKeyID     string
	Rotate       bool
	Cookies      []CookieMutation
}

// Store is the persistence contract. Implementations: in-memory (tests) and
// Redis (production). All methods take a context and must be safe for
// concurrent use.
type Store interface {
	// Session rows.
	PutSession(ctx context.Context, s Session, ttl time.Duration) error
	// TouchSession slides access/TTL state without overwriting owner or labels.
	// The legacyRotation value initializes a missing/zero last-rotation field.
	TouchSession(ctx context.Context, sessionID, keyID string, lastAccess, legacyRotation int64, ttl time.Duration) error
	// Conditional mutations return ErrNotFound rather than recreating a
	// session that a concurrent logout already revoked.
	ApplySessionControls(ctx context.Context, sessionID string, controls SessionControls, sessionTTL, ownerIndexTTL time.Duration) error
	RotateSessionKey(ctx context.Context, sessionID, oldKeyID, newKeyID string, lastRotation int64, ttl time.Duration) error
	GetSession(ctx context.Context, sessionID string) (Session, error) // ErrNotFound if absent
	DeleteSession(ctx context.Context, sessionID string) error         // also removes keys + attrs

	// key_id_map rows.
	PutKey(ctx context.Context, keyID, sessionID string, ttl time.Duration) error
	// ReplaceKey atomically swaps oldKeyID for newKeyID only while oldKeyID
	// still maps to the live session. Concurrent losers return ErrConflict.
	ReplaceKey(ctx context.Context, oldKeyID, newKeyID, sessionID string, ttl time.Duration) error
	GetKey(ctx context.Context, keyID string) (sessionID string, err error) // ErrNotFound if absent
	DeleteKey(ctx context.Context, keyID string) error

	// attribute rows (cached cookies): name -> value, plus name -> sha.
	GetCookies(ctx context.Context, sessionID string) (values map[string]string, err error)
	CookieSHAs(ctx context.Context, sessionID string) (shas map[string]string, err error)
	PutCookie(ctx context.Context, sessionID, name, value, sha string) error
	DeleteCookie(ctx context.Context, sessionID, name string) error

	// owner index. ttl bounds the whole owner set: it slides on every add, so a
	// set that stops receiving logins expires instead of growing forever on
	// TTL-expired sessions that never pass through DeleteSession.
	AddOwnerIndex(ctx context.Context, ownerID int64, sessionID string, ttl time.Duration) error
	RemoveOwnerIndex(ctx context.Context, ownerID int64, sessionID string) error
	OwnerSessions(ctx context.Context, ownerID int64) ([]string, error)
	// ReassignOwner updates owner/access/rotation fields without overwriting
	// unrelated session state, and moves owner-index membership atomically.
	// DeleteSessionByOwner deletes only when the session is still owned by
	// ownerID; it always prunes that owner's stale index member.
	ReassignOwner(ctx context.Context, s Session, sessionTTL, ownerIndexTTL time.Duration) error
	DeleteSessionByOwner(ctx context.Context, ownerID int64, sessionID string) (deleted bool, err error)

	// Lock takes a per-session advisory lock; returns (unlock, acquired, err).
	// unlock is nil when acquired is false.
	Lock(ctx context.Context, sessionID string, ttl time.Duration) (unlock func(context.Context) error, acquired bool, err error)
}
