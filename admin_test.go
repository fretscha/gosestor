package gosestor

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"

	"gosestor/internal/session"
	"gosestor/internal/store"
)

// newMemHandler builds a Handler backed by an in-memory store for admin tests.
func newMemHandler() (*Handler, *store.Memory) {
	st := store.NewMemory()
	mgr := session.NewManager(st, session.RealClock{}, session.Config{
		Inactive: 30 * time.Minute,
		Final:    8 * time.Hour,
	}, nil)
	return &Handler{manager: mgr}, st
}

// isolateRegistry swaps in an empty revoker registry for the duration of a test.
func isolateRegistry(t *testing.T) {
	t.Helper()
	revocationMu.Lock()
	saved := revokers
	revokers = map[*Handler]*session.Manager{}
	revocationMu.Unlock()
	t.Cleanup(func() {
		revocationMu.Lock()
		revokers = saved
		revocationMu.Unlock()
	})
}

func TestRevokeRegistryTracksHandlers(t *testing.T) {
	isolateRegistry(t)
	h1, _ := newMemHandler()
	h2, _ := newMemHandler()
	registerRevoker(h1)
	registerRevoker(h2)

	if got := len(allRevokers()); got != 2 {
		t.Fatalf("registry has %d managers, want 2", got)
	}
	unregisterRevoker(h1)
	if got := len(allRevokers()); got != 1 {
		t.Fatalf("registry has %d managers after unregister, want 1", got)
	}
}

func TestAdminRevokeDeletesOwnerSessions(t *testing.T) {
	isolateRegistry(t)
	ctx := context.Background()
	h, st := newMemHandler()
	live, err := h.manager.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := live.BindOwner(ctx, 7); err != nil {
		t.Fatal(err)
	}
	registerRevoker(h)

	a := &AdminAPI{log: zap.NewNop()}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/gosestor/revoke/7", nil)
	if err := a.handleRevoke(rec, req); err != nil {
		t.Fatalf("handleRevoke returned error: %v", err)
	}
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}
	if _, err := st.GetSession(ctx, live.SessionID); err != store.ErrNotFound {
		t.Fatalf("session survived revoke: %v", err)
	}
}

func TestAdminRevokeRejectsBadOwnerID(t *testing.T) {
	isolateRegistry(t)
	h, _ := newMemHandler()
	registerRevoker(h)

	a := &AdminAPI{log: zap.NewNop()}
	// Non-integers, zero (the anonymous sentinel, never indexed), and negatives
	// are all rejected — a "revoke owner 0" must not silently no-op.
	for _, bad := range []string{"not-a-number", "0", "-7"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/gosestor/revoke/"+bad, nil)
		err := a.handleRevoke(rec, req)
		apiErr, ok := err.(caddy.APIError)
		if !ok || apiErr.HTTPStatus != http.StatusBadRequest {
			t.Fatalf("owner id %q: expected 400 API error, got %v", bad, err)
		}
	}
}

func TestAdminRevokeRejectsNonPost(t *testing.T) {
	a := &AdminAPI{log: zap.NewNop()}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/gosestor/revoke/7", nil)
	err := a.handleRevoke(rec, req)
	apiErr, ok := err.(caddy.APIError)
	if !ok || apiErr.HTTPStatus != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 API error, got %v", err)
	}
}

func TestAdminRevokeNoStoreProvisioned(t *testing.T) {
	isolateRegistry(t) // empty registry
	a := &AdminAPI{log: zap.NewNop()}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/gosestor/revoke/7", nil)
	err := a.handleRevoke(rec, req)
	apiErr, ok := err.(caddy.APIError)
	if !ok || apiErr.HTTPStatus != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 API error, got %v", err)
	}
}
