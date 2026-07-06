package store

import (
	"context"
	"errors"
	"time"
)

// ErrNotFound is returned by getters when a session/key is absent or expired.
var ErrNotFound = errors.New("store: not found")

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
}

// Store is the persistence contract. Implementations: in-memory (tests) and
// Redis (production). All methods take a context and must be safe for
// concurrent use.
type Store interface {
	// Session rows.
	PutSession(ctx context.Context, s Session, ttl time.Duration) error
	GetSession(ctx context.Context, sessionID string) (Session, error) // ErrNotFound if absent
	DeleteSession(ctx context.Context, sessionID string) error         // also removes keys + attrs

	// key_id_map rows.
	PutKey(ctx context.Context, keyID, sessionID string, ttl time.Duration) error
	GetKey(ctx context.Context, keyID string) (sessionID string, err error) // ErrNotFound if absent
	SetKeyTTL(ctx context.Context, keyID string, ttl time.Duration) error
	DeleteKey(ctx context.Context, keyID string) error

	// attribute rows (cached cookies): name -> value, plus name -> sha.
	GetCookies(ctx context.Context, sessionID string) (values map[string]string, err error)
	CookieSHAs(ctx context.Context, sessionID string) (shas map[string]string, err error)
	PutCookie(ctx context.Context, sessionID, name, value, sha string) error

	// owner index. ttl bounds the whole owner set: it slides on every add, so a
	// set that stops receiving logins expires instead of growing forever on
	// TTL-expired sessions that never pass through DeleteSession.
	AddOwnerIndex(ctx context.Context, ownerID int64, sessionID string, ttl time.Duration) error
	RemoveOwnerIndex(ctx context.Context, ownerID int64, sessionID string) error
	OwnerSessions(ctx context.Context, ownerID int64) ([]string, error)

	// Refresh slides the TTL on the session + its attribute keys.
	Refresh(ctx context.Context, sessionID string, ttl time.Duration) error

	// Lock takes a per-session advisory lock; returns (unlock, acquired, err).
	// unlock is nil when acquired is false.
	Lock(ctx context.Context, sessionID string, ttl time.Duration) (unlock func(context.Context) error, acquired bool, err error)
}
