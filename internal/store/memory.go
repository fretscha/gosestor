package store

import (
	"context"
	"sync"
	"time"
)

// Memory is a non-persistent Store for tests. It ignores ttl (expiry is the
// Manager's job in unit tests via the injected Clock).
type Memory struct {
	mu       sync.Mutex
	sessions map[string]Session
	keys     map[string]string            // keyID -> sessionID
	cookies  map[string]map[string]string // sessionID -> name -> value
	shas     map[string]map[string]string // sessionID -> name -> sha
	owners   map[int64]map[string]struct{}
	locks    map[string]struct{}
}

func NewMemory() *Memory {
	return &Memory{
		sessions: map[string]Session{},
		keys:     map[string]string{},
		cookies:  map[string]map[string]string{},
		shas:     map[string]map[string]string{},
		owners:   map[int64]map[string]struct{}{},
		locks:    map[string]struct{}{},
	}
}

func (m *Memory) PutSession(_ context.Context, s Session, _ time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[s.ID] = s
	return nil
}

func (m *Memory) TouchSession(_ context.Context, id, keyID string, lastAccess, legacyRotation int64, _ time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[id]
	if !ok {
		return ErrNotFound
	}
	if sid, ok := m.keys[keyID]; !ok || sid != id {
		return ErrConflict
	}
	if lastAccess > s.LastAccess {
		s.LastAccess = lastAccess
	}
	if s.LastRotation == 0 {
		s.LastRotation = legacyRotation
	}
	m.sessions[id] = s
	return nil
}

func (m *Memory) ApplySessionControls(_ context.Context, id string, c SessionControls, _, _ time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[id]
	if !ok {
		return ErrNotFound
	}
	if sid, ok := m.keys[c.OldKeyID]; !ok || sid != id {
		return ErrConflict
	}
	if c.Rotate {
		if _, exists := m.keys[c.NewKeyID]; exists {
			return ErrConflict
		}
	}
	if c.SetOwner && c.OwnerID != s.OwnerID {
		if s.OwnerID != 0 {
			delete(m.owners[s.OwnerID], id)
			if len(m.owners[s.OwnerID]) == 0 {
				delete(m.owners, s.OwnerID)
			}
		}
		if m.owners[c.OwnerID] == nil {
			m.owners[c.OwnerID] = map[string]struct{}{}
		}
		m.owners[c.OwnerID][id] = struct{}{}
		s.OwnerID = c.OwnerID
	}
	if c.SetLabels {
		s.Labels = c.Labels
	}
	if c.LastAccess > s.LastAccess {
		s.LastAccess = c.LastAccess
	}
	if c.LastRotation > s.LastRotation {
		s.LastRotation = c.LastRotation
	}
	if c.Rotate {
		m.keys[c.NewKeyID] = id
		delete(m.keys, c.OldKeyID)
	}
	for _, cookie := range c.Cookies {
		if cookie.Delete {
			delete(m.cookies[id], cookie.Name)
			delete(m.shas[id], cookie.Name)
			continue
		}
		if m.cookies[id] == nil {
			m.cookies[id] = map[string]string{}
		}
		if m.shas[id] == nil {
			m.shas[id] = map[string]string{}
		}
		m.cookies[id][cookie.Name] = cookie.Value
		m.shas[id][cookie.Name] = cookie.SHA
	}
	m.sessions[id] = s
	return nil
}

func (m *Memory) RotateSessionKey(_ context.Context, id, oldKeyID, newKeyID string, lastRotation int64, _ time.Duration) error {
	return m.ApplySessionControls(context.Background(), id, SessionControls{
		LastRotation: lastRotation,
		OldKeyID:     oldKeyID,
		NewKeyID:     newKeyID,
		Rotate:       true,
	}, 0, 0)
}

func (m *Memory) GetSession(_ context.Context, id string) (Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[id]
	if !ok {
		return Session{}, ErrNotFound
	}
	return s, nil
}

func (m *Memory) DeleteSession(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.sessions[id]; ok && s.OwnerID != 0 {
		if set := m.owners[s.OwnerID]; set != nil {
			delete(set, id)
		}
	}
	delete(m.sessions, id)
	delete(m.cookies, id)
	delete(m.shas, id)
	for k, sid := range m.keys {
		if sid == id {
			delete(m.keys, k)
		}
	}
	return nil
}

func (m *Memory) PutKey(_ context.Context, keyID, sessionID string, _ time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.sessions[sessionID]; !ok {
		return ErrNotFound
	}
	m.keys[keyID] = sessionID
	return nil
}

func (m *Memory) ReplaceKey(_ context.Context, oldKeyID, newKeyID, sessionID string, _ time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.sessions[sessionID]; !ok {
		return ErrNotFound
	}
	if sid, ok := m.keys[oldKeyID]; !ok || sid != sessionID {
		return ErrConflict
	}
	if _, exists := m.keys[newKeyID]; exists {
		return ErrConflict
	}
	m.keys[newKeyID] = sessionID
	delete(m.keys, oldKeyID)
	return nil
}

func (m *Memory) GetKey(_ context.Context, keyID string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	sid, ok := m.keys[keyID]
	if !ok {
		return "", ErrNotFound
	}
	return sid, nil
}

func (m *Memory) DeleteKey(_ context.Context, keyID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.keys, keyID)
	return nil
}

func (m *Memory) GetCookies(_ context.Context, sessionID string) (map[string]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return copyMap(m.cookies[sessionID]), nil
}

func (m *Memory) CookieSHAs(_ context.Context, sessionID string) (map[string]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return copyMap(m.shas[sessionID]), nil
}

func (m *Memory) PutCookie(_ context.Context, sessionID, name, value, sha string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.sessions[sessionID]; !ok {
		return ErrNotFound
	}
	if m.cookies[sessionID] == nil {
		m.cookies[sessionID] = map[string]string{}
		m.shas[sessionID] = map[string]string{}
	}
	m.cookies[sessionID][name] = value
	m.shas[sessionID][name] = sha
	return nil
}

func (m *Memory) DeleteCookie(_ context.Context, sessionID, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.cookies[sessionID], name)
	delete(m.shas[sessionID], name)
	return nil
}

func (m *Memory) AddOwnerIndex(_ context.Context, ownerID int64, sessionID string, _ time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.owners[ownerID] == nil {
		m.owners[ownerID] = map[string]struct{}{}
	}
	m.owners[ownerID][sessionID] = struct{}{}
	return nil
}

func (m *Memory) RemoveOwnerIndex(_ context.Context, ownerID int64, sessionID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if set := m.owners[ownerID]; set != nil {
		delete(set, sessionID)
	}
	return nil
}

func (m *Memory) OwnerSessions(_ context.Context, ownerID int64) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for sid := range m.owners[ownerID] {
		out = append(out, sid)
	}
	return out, nil
}

func (m *Memory) ReassignOwner(_ context.Context, s Session, _, _ time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	previous, ok := m.sessions[s.ID]
	if !ok {
		return ErrNotFound
	}
	if previous.OwnerID > 0 && previous.OwnerID != s.OwnerID {
		if set := m.owners[previous.OwnerID]; set != nil {
			delete(set, s.ID)
		}
	}
	previous.OwnerID = s.OwnerID
	if s.LastAccess > previous.LastAccess {
		previous.LastAccess = s.LastAccess
	}
	if s.LastRotation > previous.LastRotation {
		previous.LastRotation = s.LastRotation
	}
	m.sessions[s.ID] = previous
	if m.owners[s.OwnerID] == nil {
		m.owners[s.OwnerID] = map[string]struct{}{}
	}
	m.owners[s.OwnerID][s.ID] = struct{}{}
	return nil
}

func (m *Memory) DeleteSessionByOwner(_ context.Context, ownerID int64, sessionID string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if set := m.owners[ownerID]; set != nil {
		delete(set, sessionID)
	}
	s, ok := m.sessions[sessionID]
	if !ok || s.OwnerID != ownerID {
		return false, nil
	}
	delete(m.sessions, sessionID)
	delete(m.cookies, sessionID)
	delete(m.shas, sessionID)
	for keyID, sid := range m.keys {
		if sid == sessionID {
			delete(m.keys, keyID)
		}
	}
	return true, nil
}

func (m *Memory) Lock(_ context.Context, sessionID string, _ time.Duration) (func(context.Context) error, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, held := m.locks[sessionID]; held {
		return nil, false, nil
	}
	m.locks[sessionID] = struct{}{}
	unlock := func(context.Context) error {
		m.mu.Lock()
		defer m.mu.Unlock()
		delete(m.locks, sessionID)
		return nil
	}
	return unlock, true, nil
}

func copyMap(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
