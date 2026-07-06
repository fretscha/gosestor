package gosestor

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"

	"gosestor/internal/session"
)

func init() {
	caddy.RegisterModule(AdminAPI{})
}

// revoker registry. Handlers register their provisioned Manager on Provision so
// the process-global admin endpoint can reach it; the admin extension is a
// separate module and has no other handle on per-site state. Keyed by *Handler
// so multiple session_store sites (distinct Redis backends) can each be revoked.
var (
	revocationMu sync.RWMutex
	revokers     = map[*Handler]*session.Manager{}
)

func registerRevoker(h *Handler) {
	revocationMu.Lock()
	defer revocationMu.Unlock()
	revokers[h] = h.manager
}

func unregisterRevoker(h *Handler) {
	revocationMu.Lock()
	defer revocationMu.Unlock()
	delete(revokers, h)
}

func allRevokers() []*session.Manager {
	revocationMu.RLock()
	defer revocationMu.RUnlock()
	out := make([]*session.Manager, 0, len(revokers))
	for _, m := range revokers {
		out = append(out, m)
	}
	return out
}

// AdminAPI exposes session administration over Caddy's admin endpoint. Because
// that endpoint is bound to localhost (and origin/host-checked) by default, the
// destructive revoke operation inherits Caddy's existing admin access control
// rather than introducing an app-level secret to manage.
type AdminAPI struct {
	log *zap.Logger
}

func (AdminAPI) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "admin.api.gosestor",
		New: func() caddy.Module { return new(AdminAPI) },
	}
}

func (a *AdminAPI) Provision(ctx caddy.Context) error {
	a.log = ctx.Logger()
	return nil
}

// Routes registers the admin endpoints under /gosestor/.
func (a *AdminAPI) Routes() []caddy.AdminRoute {
	return []caddy.AdminRoute{
		{
			Pattern: "/gosestor/revoke/",
			Handler: caddy.AdminHandlerFunc(a.handleRevoke),
		},
	}
}

// handleRevoke implements POST /gosestor/revoke/{owner_id} — logout-everywhere
// for a single owner across every provisioned session_store.
func (a *AdminAPI) handleRevoke(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodPost {
		return caddy.APIError{
			HTTPStatus: http.StatusMethodNotAllowed,
			Err:        fmt.Errorf("use POST to revoke"),
		}
	}
	idStr := strings.Trim(strings.TrimPrefix(r.URL.Path, "/gosestor/revoke/"), "/")
	ownerID, err := strconv.ParseInt(idStr, 10, 64)
	// Owner ids are positive; 0 is the anonymous sentinel and is never indexed,
	// so "revoke owner 0" has no meaningful target — reject rather than no-op.
	if err != nil || ownerID <= 0 {
		return caddy.APIError{
			HTTPStatus: http.StatusBadRequest,
			Err:        fmt.Errorf("invalid owner id %q: expected a positive integer", idStr),
		}
	}

	managers := allRevokers()
	if len(managers) == 0 {
		return caddy.APIError{
			HTTPStatus: http.StatusServiceUnavailable,
			Err:        fmt.Errorf("no session_store handler is provisioned"),
		}
	}

	var firstErr error
	for _, m := range managers {
		if err := m.RevokeOwner(r.Context(), ownerID); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if firstErr != nil {
		// Surface as 502: the request was valid but a backing store failed.
		return caddy.APIError{
			HTTPStatus: http.StatusBadGateway,
			Err:        fmt.Errorf("revoke owner %d: %w", ownerID, firstErr),
		}
	}

	a.log.Info("revoked owner sessions",
		zap.Int64("owner_id", ownerID),
		zap.Int("stores", len(managers)))
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// interface guards
var (
	_ caddy.AdminRouter = (*AdminAPI)(nil)
	_ caddy.Provisioner = (*AdminAPI)(nil)
)
