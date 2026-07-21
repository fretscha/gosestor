package gosestor

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/fretscha/gosestor/internal/authz"
	"github.com/fretscha/gosestor/internal/filter"
	"github.com/fretscha/gosestor/internal/session"
	"github.com/fretscha/gosestor/internal/store"
)

func init() {
	caddy.RegisterModule(Handler{})
	httpcaddyfile.RegisterHandlerDirective("session_store", parseCaddyfile)
}

// RedisConfig configures the backing store.
type RedisConfig struct {
	Address   string `json:"address,omitempty"`
	Password  string `json:"password,omitempty"`
	DB        int    `json:"db,omitempty"`
	KeyPrefix string `json:"key_prefix,omitempty"`
}

// CookieConfig configures the client-facing proxy cookie.
type CookieConfig struct {
	Name     string `json:"name,omitempty"`
	Path     string `json:"path,omitempty"` // empty => "/"
	SameSite string `json:"same_site,omitempty"`
	Insecure bool   `json:"insecure,omitempty"`
}

// Handler is the session_store Caddy HTTP handler.
type Handler struct {
	Redis           RedisConfig    `json:"redis,omitempty"`
	Cookie          CookieConfig   `json:"cookie,omitempty"`
	Forward         []string       `json:"forward,omitempty"`
	Store           []string       `json:"store,omitempty"`
	InactiveTimeout caddy.Duration `json:"inactive_timeout,omitempty"`
	FinalTimeout    caddy.Duration `json:"final_timeout,omitempty"`
	IdentityHeader  string         `json:"identity_header,omitempty"`
	// RotateOnLogin is a *bool so a raw-JSON config that omits it fails SAFE:
	// nil means true (rotate on identity change). A plain bool would zero-value
	// to false and silently disable the fixation defense for JSON users.
	RotateOnLogin  *bool          `json:"rotate_on_login,omitempty"`
	RotateInterval caddy.Duration `json:"rotate_interval,omitempty"`
	// RotateHeader names the backend response header that requests a KEY_ID
	// rotation (step-up re-auth, suspicious account, …). Empty = default
	// "X-Session-Rotate", enabled. The literal "off" disables triggering, but
	// the default name is still stripped from responses so backend signaling
	// never reaches the client.
	RotateHeader string `json:"rotate_header,omitempty"`
	// RevokeHeader names the backend response header that revokes the current
	// proxy session. Empty = default "X-Session-Revoke"; "off" disables the
	// trigger while the default header remains stripped.
	RevokeHeader string `json:"revoke_header,omitempty"`
	// LabelsHeader names the backend response header that grants session
	// labels (space/comma-separated; presence REPLACES the set, empty clears
	// it). Empty = default "X-Session-Labels". Parsed and stripped even when
	// authz is off, so grants can accumulate before enforcement is enabled.
	LabelsHeader string `json:"labels_header,omitempty"`
	// Authz enables path-based authorization; nil = feature off.
	Authz        *AuthzConfig `json:"authz,omitempty"`
	Synchronize  bool         `json:"synchronize_sessions,omitempty"`
	OnStoreError string       `json:"on_store_error,omitempty"`

	filter           *filter.Filter
	manager          *session.Manager
	store            store.Store
	redisClient      *redis.Client
	logger           *zap.Logger
	rotateHeaderName string // effective header to read + strip
	rotateEnabled    bool
	revokeHeaderName string // effective current-session revoke header
	revokeEnabled    bool
	labelsHeaderName string // effective labels header to read + strip
	authz            *authz.Authz
}

// defaultRotateHeader is the backend-facing rotation-request header name.
const defaultRotateHeader = "X-Session-Rotate"

// defaultRevokeHeader is the backend-facing current-session revocation header.
const defaultRevokeHeader = "X-Session-Revoke"

// defaultLabelsHeader is the backend-facing label-grant header name.
const defaultLabelsHeader = "X-Session-Labels"

// AuthzConfig is the user-facing shape of the authz block; compiled and
// validated by internal/authz.
type AuthzConfig struct {
	Rules         []AuthzRule       `json:"rules,omitempty"`
	DefaultLabel  string            `json:"default_label,omitempty"`  // "" = anonymous
	AuthEndpoints map[string]string `json:"auth_endpoints,omitempty"` // label -> path
	RedirectParam string            `json:"redirect_param,omitempty"` // "" = "rd"
}

// AuthzRule maps a path prefix to a required label.
type AuthzRule struct {
	Path  string `json:"path"`
	Label string `json:"label"`
}

func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.session_store",
		New: func() caddy.Module { return new(Handler) },
	}
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var handler Handler
	if err := handler.UnmarshalCaddyfile(h.Dispenser); err != nil {
		return nil, err
	}
	return &handler, nil
}

func (h *Handler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	// defaults
	h.Cookie.Name = "__gosestor"
	h.Cookie.Path = "/"
	h.Cookie.SameSite = "lax"
	h.IdentityHeader = "X-Auth-User"
	h.OnStoreError = "fail_closed"
	h.Redis.KeyPrefix = "gs:"
	// RotateOnLogin stays nil unless configured; nil resolves to true in
	// Provision (rotate KEY_ID on OWNER_ID transition).

	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "redis":
				for d.NextBlock(1) {
					switch d.Val() {
					case "address":
						if !d.NextArg() {
							return d.ArgErr()
						}
						h.Redis.Address = d.Val()
					case "password":
						if !d.NextArg() {
							return d.ArgErr()
						}
						h.Redis.Password = d.Val()
					case "db":
						if !d.NextArg() {
							return d.ArgErr()
						}
						if _, err := fmt.Sscanf(d.Val(), "%d", &h.Redis.DB); err != nil {
							return d.Errf("invalid db %q: %v", d.Val(), err)
						}
					case "key_prefix":
						if !d.NextArg() {
							return d.ArgErr()
						}
						h.Redis.KeyPrefix = d.Val()
					default:
						return d.Errf("unknown redis option %q", d.Val())
					}
				}
			case "cookie":
				for d.NextBlock(1) {
					switch d.Val() {
					case "name":
						if !d.NextArg() {
							return d.ArgErr()
						}
						h.Cookie.Name = d.Val()
					case "path":
						if !d.NextArg() {
							return d.ArgErr()
						}
						h.Cookie.Path = d.Val()
					case "same_site":
						if !d.NextArg() {
							return d.ArgErr()
						}
						h.Cookie.SameSite = d.Val()
					case "insecure":
						h.Cookie.Insecure = true
					default:
						return d.Errf("unknown cookie option %q", d.Val())
					}
				}
			case "forward":
				h.Forward = append(h.Forward, d.RemainingArgs()...)
			case "store":
				h.Store = append(h.Store, d.RemainingArgs()...)
			case "inactive_timeout":
				if !d.NextArg() {
					return d.ArgErr()
				}
				dur, err := time.ParseDuration(d.Val())
				if err != nil {
					return err
				}
				h.InactiveTimeout = caddy.Duration(dur)
			case "final_timeout":
				if !d.NextArg() {
					return d.ArgErr()
				}
				dur, err := time.ParseDuration(d.Val())
				if err != nil {
					return err
				}
				h.FinalTimeout = caddy.Duration(dur)
			case "identity_header":
				if !d.NextArg() {
					return d.ArgErr()
				}
				h.IdentityHeader = d.Val()
			case "rotate_on_login":
				// `false` disables identity-change rotation (fixation defense);
				// default is true.
				if !d.NextArg() {
					return d.ArgErr()
				}
				v, err := strconv.ParseBool(d.Val())
				if err != nil {
					return d.Errf("rotate_on_login: invalid boolean %q", d.Val())
				}
				h.RotateOnLogin = &v
			case "rotate_interval":
				// Lazily rotates a session's KEY_ID on the first request after this
				// much time elapses since the last rotation. Zero = off.
				if !d.NextArg() {
					return d.ArgErr()
				}
				dur, err := time.ParseDuration(d.Val())
				if err != nil {
					return err
				}
				h.RotateInterval = caddy.Duration(dur)
			case "rotate_header":
				// Custom header name, or the literal "off" to disable.
				if !d.NextArg() {
					return d.ArgErr()
				}
				h.RotateHeader = d.Val()
			case "revoke_header":
				if !d.NextArg() {
					return d.ArgErr()
				}
				h.RevokeHeader = d.Val()
			case "labels_header":
				if !d.NextArg() {
					return d.ArgErr()
				}
				h.LabelsHeader = d.Val()
			case "authz":
				if h.Authz == nil {
					h.Authz = &AuthzConfig{}
				}
				for d.NextBlock(1) {
					switch d.Val() {
					case "require":
						args := d.RemainingArgs()
						if len(args) != 2 {
							return d.Errf("require expects <path> <label>")
						}
						h.Authz.Rules = append(h.Authz.Rules, AuthzRule{Path: args[0], Label: args[1]})
					case "require_default":
						if !d.NextArg() {
							return d.ArgErr()
						}
						h.Authz.DefaultLabel = d.Val()
					case "auth_endpoint":
						args := d.RemainingArgs()
						if len(args) != 2 {
							return d.Errf("auth_endpoint expects <label> <path>")
						}
						if h.Authz.AuthEndpoints == nil {
							h.Authz.AuthEndpoints = map[string]string{}
						}
						h.Authz.AuthEndpoints[args[0]] = args[1]
					case "redirect_param":
						if !d.NextArg() {
							return d.ArgErr()
						}
						h.Authz.RedirectParam = d.Val()
					default:
						return d.Errf("unknown authz option %q", d.Val())
					}
				}
			case "synchronize_sessions":
				if !d.NextArg() {
					return d.ArgErr()
				}
				v, err := strconv.ParseBool(d.Val())
				if err != nil {
					// A silent false here would disable the per-session lock the
					// operator asked for — fail loudly like every other option.
					return d.Errf("synchronize_sessions: invalid boolean %q", d.Val())
				}
				h.Synchronize = v
			case "on_store_error":
				if !d.NextArg() {
					return d.ArgErr()
				}
				h.OnStoreError = d.Val()
			default:
				return d.Errf("unknown session_store option %q", d.Val())
			}
		}
	}
	return nil
}

func (h *Handler) Provision(ctx caddy.Context) error {
	h.logger = ctx.Logger()
	if h.InactiveTimeout == 0 {
		h.InactiveTimeout = caddy.Duration(30 * time.Minute)
	}
	if h.FinalTimeout == 0 {
		h.FinalTimeout = caddy.Duration(8 * time.Hour)
	}
	if h.Cookie.Path == "" {
		h.Cookie.Path = "/"
	}
	h.redisClient = redis.NewClient(&redis.Options{
		Addr: h.Redis.Address, Password: h.Redis.Password, DB: h.Redis.DB,
	})
	h.store = store.NewRedis(h.redisClient, h.Redis.KeyPrefix)
	h.filter = filter.New(h.Forward, h.Store)
	h.manager = session.NewManager(h.store, session.RealClock{}, session.Config{
		Inactive:       time.Duration(h.InactiveTimeout),
		Final:          time.Duration(h.FinalTimeout),
		Synchronize:    h.Synchronize,
		RotateOnLogin:  h.RotateOnLogin == nil || *h.RotateOnLogin, // nil = default true (fail safe)
		RotateInterval: time.Duration(h.RotateInterval),
	}, nil)
	h.resolveRotateHeader()
	h.resolveRevokeHeader()
	h.labelsHeaderName = h.LabelsHeader
	if h.labelsHeaderName == "" {
		h.labelsHeaderName = defaultLabelsHeader
	}
	if h.Authz != nil {
		a, err := h.buildAuthz()
		if err != nil {
			return fmt.Errorf("session_store: %w", err)
		}
		h.authz = a
	}
	// Expose this manager to the admin revoke endpoint (admin.api.gosestor).
	registerRevoker(h)
	return nil
}

// buildAuthz compiles the user-facing authz config; shared by Provision
// (to store the compiled policy) and Validate (to surface errors at load).
func (h *Handler) buildAuthz() (*authz.Authz, error) {
	rules := make([]authz.Rule, len(h.Authz.Rules))
	for i, r := range h.Authz.Rules {
		rules[i] = authz.Rule{Path: r.Path, Label: r.Label}
	}
	return authz.New(authz.Config{
		Rules:         rules,
		DefaultLabel:  h.Authz.DefaultLabel,
		AuthEndpoints: h.Authz.AuthEndpoints,
		RedirectParam: h.Authz.RedirectParam,
	})
}

// resolveRotateHeader computes the effective rotation-header behavior from
// the user-facing RotateHeader value. Runs in Provision so raw-JSON configs
// get the same fail-safe default as Caddyfile ones.
func (h *Handler) resolveRotateHeader() {
	switch {
	case strings.EqualFold(h.RotateHeader, "off"):
		h.rotateHeaderName = defaultRotateHeader
		h.rotateEnabled = false
	case h.RotateHeader == "":
		h.rotateHeaderName = defaultRotateHeader
		h.rotateEnabled = true
	default:
		h.rotateHeaderName = h.RotateHeader
		h.rotateEnabled = true
	}
}

func (h *Handler) resolveRevokeHeader() {
	switch {
	case strings.EqualFold(h.RevokeHeader, "off"):
		h.revokeHeaderName = defaultRevokeHeader
		h.revokeEnabled = false
	case h.RevokeHeader == "":
		h.revokeHeaderName = defaultRevokeHeader
		h.revokeEnabled = true
	default:
		h.revokeHeaderName = h.RevokeHeader
		h.revokeEnabled = true
	}
}

// Cleanup deregisters this handler from the admin revoke registry when the
// config is unloaded — first, so a revoke can never race a closing client —
// then closes the Redis pool, which would otherwise leak connections and
// goroutines on every config reload.
func (h *Handler) Cleanup() error {
	unregisterRevoker(h)
	if h.redisClient != nil {
		if err := h.redisClient.Close(); err != nil {
			return fmt.Errorf("session_store: closing redis client: %w", err)
		}
	}
	return nil
}

func (h *Handler) Validate() error {
	if h.Redis.Address == "" {
		return fmt.Errorf("session_store: redis address is required")
	}
	if h.OnStoreError != "fail_closed" && h.OnStoreError != "fail_open" {
		return fmt.Errorf("session_store: on_store_error must be fail_closed or fail_open")
	}
	// SameSite=None requires Secure; browsers reject a None cookie without it,
	// and accepting it would remove the CSRF protection Lax/Strict provide.
	if strings.EqualFold(h.Cookie.SameSite, "none") && h.Cookie.Insecure {
		return fmt.Errorf("session_store: cookie same_site none requires a secure cookie (remove insecure)")
	}
	// Negative durations parse fine but silently disable the feature they
	// configure — reject them so a typo can't turn off a timeout or rotation.
	if h.InactiveTimeout < 0 || h.FinalTimeout < 0 || h.RotateInterval < 0 {
		return fmt.Errorf("session_store: inactive_timeout, final_timeout, and rotate_interval must not be negative")
	}
	// Every managed response header is stripped even when its trigger is off, so
	// their effective names must remain distinct or one feature would silently
	// consume another's value.
	effRotate := h.RotateHeader
	if effRotate == "" || strings.EqualFold(effRotate, "off") {
		effRotate = defaultRotateHeader
	}
	effRevoke := h.RevokeHeader
	if effRevoke == "" || strings.EqualFold(effRevoke, "off") {
		effRevoke = defaultRevokeHeader
	}
	effLabels := h.LabelsHeader
	if effLabels == "" {
		effLabels = defaultLabelsHeader
	}
	headers := []struct {
		kind string
		name string
	}{
		{"identity_header", h.IdentityHeader},
		{"rotate_header", effRotate},
		{"revoke_header", effRevoke},
		{"labels_header", effLabels},
	}
	for i := range headers {
		for j := i + 1; j < len(headers); j++ {
			if strings.EqualFold(headers[i].name, headers[j].name) {
				return fmt.Errorf("session_store: %s %q collides with %s", headers[i].kind, headers[i].name, headers[j].kind)
			}
		}
	}
	if h.Authz != nil {
		if _, err := h.buildAuthz(); err != nil {
			return fmt.Errorf("session_store: %w", err)
		}
	}
	return nil
}

// interface guards
var (
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddy.Validator             = (*Handler)(nil)
	_ caddy.CleanerUpper          = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
	_ caddyfile.Unmarshaler       = (*Handler)(nil)
)

type trailerScrubbingBody struct {
	io.ReadCloser
	trailer http.Header
	names   []string
}

func (b *trailerScrubbingBody) scrub() {
	for _, name := range b.names {
		b.trailer.Del(name)
	}
}

func (b *trailerScrubbingBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	// net/http populates request trailers as the body reaches EOF. Scrub after
	// every read so late-arriving control trailers cannot reach the backend.
	b.scrub()
	return n, err
}

func (b *trailerScrubbingBody) Close() error {
	err := b.ReadCloser.Close()
	b.scrub()
	return err
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	ctx := r.Context()

	// (0) Anti-spoof: backend control headers are response-only. Never trust
	// client-supplied copies, including trailers, because an echoing backend
	// could otherwise turn them into grants, rotations, or revocation signals.
	managedHeaders := []string{h.IdentityHeader, h.rotateHeaderName, h.revokeHeaderName, h.labelsHeaderName}
	for _, name := range managedHeaders {
		r.Header.Del(name)
		if r.Trailer != nil {
			r.Trailer.Del(name)
		}
	}
	if r.Body != nil && r.Trailer != nil {
		r.Body = &trailerScrubbingBody{ReadCloser: r.Body, trailer: r.Trailer, names: managedHeaders}
	}

	// (1-4) Resolve any existing session and inject cached cookies upstream.
	var live *session.Live
	var resolveErr error
	hadProxyCookie := false
	if c, err := r.Cookie(h.Cookie.Name); err == nil {
		hadProxyCookie = true
		l, err := h.manager.Resolve(ctx, c.Value)
		if err != nil {
			resolveErr = err
			h.logger.Error("session store error", zap.String("op", "resolve"), zap.Error(err))
			if h.OnStoreError == "fail_closed" {
				return caddyhttp.Error(http.StatusBadGateway, err)
			}
			// fail_open: proceed without a session (live stays nil)
		} else {
			live = l
		}
	}
	// (1b) Authorization: the required label must be provable BEFORE the
	// request reaches the backend. A store failure above leaves live == nil,
	// so a protected path fails CLOSED even under on_store_error fail_open —
	// only the session-caching behavior of anonymous paths degrades open.
	if h.authz != nil {
		if required := h.authz.Required(r.URL.Path); required != authz.Anonymous {
			if live == nil || !live.HasLabel(required) {
				return h.denyAuthz(w, r, required)
			}
		}
	}

	// Always rewrite the upstream Cookie header: strip the opaque proxy key and
	// any client-supplied store-managed cookie names (the server's cached values
	// are authoritative), then inject the cached values. Runs even without a
	// live session so a client cannot smuggle managed cookies to the backend.
	var cached map[string]string
	if live != nil {
		cached = live.Cookies
	}
	h.prepareUpstreamCookies(r, cached)

	// Response interception: process Set-Cookie + identity header before flush.
	ic := &interceptor{
		ResponseWriter: w, h: h, live: live, ctx: ctx,
		hadProxyCookie: hadProxyCookie, resolveErr: resolveErr,
		responseHeader: w.Header().Clone(),
	}
	defer func() { _ = ic.body.Close() }()
	err := next.ServeHTTP(ic, r)
	if err != nil {
		// Nothing has reached the client yet: discard the staged body and every
		// backend control/cookie without applying a session mutation.
		ic.body.Reset()
		ic.discardBackendMetadata()
		clearHeaders(w.Header())
		return err
	}
	if ic.hijacked {
		return nil
	}
	ic.ensureProcessed()
	if ic.failed {
		ic.body.Reset()
		clearHeaders(w.Header())
		w.WriteHeader(http.StatusBadGateway)
		return nil
	}
	ic.commitInformational(w)
	copyHeaders(w.Header(), ic.Header())
	if !ic.wroteHeader {
		return nil
	}
	status := ic.status
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
	if ic.body.Len() > 0 {
		if err := ic.body.FlushTo(w); err != nil {
			return err
		}
	}
	return nil
}

func clearHeaders(h http.Header) {
	for name := range h {
		h.Del(name)
	}
}

func stripManagedTrailerDeclarations(h http.Header, names ...string) {
	managed := make(map[string]struct{}, len(names))
	for _, name := range names {
		managed[http.CanonicalHeaderKey(name)] = struct{}{}
	}
	var kept []string
	for _, declaration := range h.Values("Trailer") {
		for _, name := range strings.Split(declaration, ",") {
			name = strings.TrimSpace(name)
			if _, blocked := managed[http.CanonicalHeaderKey(name)]; blocked {
				h.Del(name)
			} else if name != "" {
				kept = append(kept, name)
			}
		}
	}
	h.Del("Trailer")
	if len(kept) > 0 {
		h.Set("Trailer", strings.Join(kept, ", "))
	}
	for key := range h {
		if strings.HasPrefix(strings.ToLower(key), strings.ToLower(http.TrailerPrefix)) {
			name := key[len(http.TrailerPrefix):]
			if _, blocked := managed[http.CanonicalHeaderKey(name)]; blocked {
				h.Del(key)
			}
		}
	}
}

// discardBackendMetadata prevents an errored downstream handler from leaking
// response-only controls or cookies through Caddy's error response. It does not
// apply any session mutation.
func (ic *interceptor) discardBackendMetadata() {
	ic.once.Do(func() {
		h := ic.Header()
		h.Del("Set-Cookie")
		h.Del(ic.h.IdentityHeader)
		h.Del(ic.h.rotateHeaderName)
		h.Del(ic.h.revokeHeaderName)
		h.Del(ic.h.labelsHeaderName)
		stripManagedTrailerDeclarations(h, "Set-Cookie", ic.h.IdentityHeader, ic.h.rotateHeaderName, ic.h.revokeHeaderName, ic.h.labelsHeaderName)
	})
}

// splitLabels tokenizes a labels header value on commas and whitespace.
func splitLabels(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == ',' || unicode.IsSpace(r) })
}

// prepareUpstreamCookies rewrites the inbound Cookie header the backend will
// see. It removes (a) the opaque proxy cookie — the KEY_ID must never cross the
// proxy boundary — and (b) any client-supplied cookie whose name the plugin
// stores, since the server-held value is authoritative and a client must not be
// able to smuggle or override a managed cookie to the backend. It then injects
// the cached (server-held) values so the backend sees its own session cookies.
func (h *Handler) prepareUpstreamCookies(r *http.Request, cached map[string]string) {
	var kept []string
	for _, c := range r.Cookies() {
		if c.Name == h.Cookie.Name {
			continue // never forward the proxy KEY_ID upstream
		}
		if h.filter.Decide(c.Name) == filter.Store {
			continue // stored cookies are server-authoritative; drop client copies
		}
		kept = append(kept, c.Name+"="+c.Value)
	}
	for name, val := range cached {
		kept = append(kept, name+"="+val)
	}
	if len(kept) == 0 {
		r.Header.Del("Cookie")
		return
	}
	r.Header.Set("Cookie", strings.Join(kept, "; "))
}

// denyAuthz answers a request whose session lacks the required label:
// browsers (Accept contains text/html) get a 302 to the label's auth
// endpoint carrying the original path+query in the redirect parameter;
// everything else gets a 401 with the endpoint in X-Auth-Endpoint. The
// redirect target is built exclusively from server config and the request's
// own path+query — never from client-controlled parameters — so it cannot
// become an open redirect.
func (h *Handler) denyAuthz(w http.ResponseWriter, r *http.Request, required string) error {
	endpoint := h.authz.Endpoint(required)
	h.logger.Debug("authz denied",
		zap.String("path", r.URL.Path), zap.String("required", required))
	if strings.Contains(r.Header.Get("Accept"), "text/html") {
		rd := r.URL.Path
		if r.URL.RawQuery != "" {
			rd += "?" + r.URL.RawQuery
		}
		sep := "?"
		if strings.Contains(endpoint, "?") {
			sep = "&"
		}
		w.Header().Set("Location", endpoint+sep+h.authz.RedirectParam()+"="+url.QueryEscape(rd))
		w.WriteHeader(http.StatusFound)
		return nil
	}
	w.Header().Set("X-Auth-Endpoint", endpoint)
	w.WriteHeader(http.StatusUnauthorized)
	return nil
}

// interceptor interface guards: streaming and upgrades must keep working
// through the wrapper (reverse_proxy probes for these).
var (
	_ http.Flusher  = (*interceptor)(nil)
	_ http.Hijacker = (*interceptor)(nil)
)

type stagedInformationalResponse struct {
	status int
	header http.Header
}

// interceptor stages normal HTTP responses until the downstream result is known.
const stagedResponseMemoryLimit = 1 << 20

type stagedBody struct {
	memory bytes.Buffer
	file   *os.File
	size   int64
}

func (b *stagedBody) Write(p []byte) (int, error) {
	if b.file == nil && b.memory.Len()+len(p) <= stagedResponseMemoryLimit {
		n, err := b.memory.Write(p)
		b.size += int64(n)
		return n, err
	}
	if b.file == nil {
		f, err := os.CreateTemp("", "gosestor-response-*")
		if err != nil {
			return 0, err
		}
		b.file = f
		if _, err := f.Write(b.memory.Bytes()); err != nil {
			_ = b.Close()
			return 0, err
		}
		b.memory.Reset()
	}
	n, err := b.file.Write(p)
	b.size += int64(n)
	return n, err
}

func (b *stagedBody) FlushTo(w io.Writer) error {
	if b.file == nil {
		_, err := w.Write(b.memory.Bytes())
		return err
	}
	if _, err := b.file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	_, err := io.Copy(w, b.file)
	return err
}

func (b *stagedBody) Len() int { return int(b.size) }
func (b *stagedBody) String() string {
	if b.file == nil {
		return b.memory.String()
	}
	return fmt.Sprintf("<%d staged bytes>", b.size)
}
func (b *stagedBody) Reset() {
	b.memory.Reset()
	b.size = 0
	if b.file != nil {
		name := b.file.Name()
		_ = b.file.Close()
		_ = os.Remove(name)
		b.file = nil
	}
}
func (b *stagedBody) Close() error {
	if b.file == nil {
		return nil
	}
	name := b.file.Name()
	err := b.file.Close()
	removeErr := os.Remove(name)
	b.file = nil
	if err != nil {
		return err
	}
	return removeErr
}

type interceptor struct {
	http.ResponseWriter
	h               *Handler
	live            *session.Live
	ctx             context.Context
	once            sync.Once
	failed          bool
	wroteHeader     bool
	status          int
	body            stagedBody
	responseHeader  http.Header
	informational   []stagedInformationalResponse
	hijacked        bool
	storeErr        error
	revokeRequested bool
	hadProxyCookie  bool
	resolveErr      error
}

func copyHeaders(dst, src http.Header) {
	clearHeaders(dst)
	for name, values := range src {
		dst[name] = append([]string(nil), values...)
	}
}

func (ic *interceptor) Header() http.Header { return ic.responseHeader }

func (ic *interceptor) WriteHeader(status int) {
	if ic.wroteHeader {
		return
	}
	if status < 100 || status > 999 {
		panic(fmt.Sprintf("invalid WriteHeader code %v", status))
	}
	if status >= 100 && status < 200 && status != http.StatusSwitchingProtocols {
		ic.informational = append(ic.informational, stagedInformationalResponse{
			status: status,
			header: ic.Header().Clone(),
		})
		return
	}
	ic.wroteHeader = true
	ic.status = status
}

func (ic *interceptor) Write(b []byte) (int, error) {
	if !ic.wroteHeader {
		ic.WriteHeader(http.StatusOK)
	}
	if ic.status == http.StatusNoContent || ic.status == http.StatusNotModified || (ic.status >= 100 && ic.status < 200) {
		return 0, http.ErrBodyNotAllowed
	}
	return ic.body.Write(b)
}

// Flush records an implicit 200 but deliberately defers the actual flush until
// the downstream handler returns successfully. This lets a later downstream
// error discard all body, metadata, and session mutations.
func (ic *interceptor) Flush() {
	if !ic.wroteHeader {
		ic.WriteHeader(http.StatusOK)
	}
}

func (ic *interceptor) scrubManagedResponseHeader(h http.Header) {
	stripManagedTrailerDeclarations(h, "Set-Cookie", ic.h.IdentityHeader, ic.h.rotateHeaderName, ic.h.revokeHeaderName, ic.h.labelsHeaderName)
	h.Del("Set-Cookie")
	h.Del(ic.h.IdentityHeader)
	h.Del(ic.h.rotateHeaderName)
	h.Del(ic.h.revokeHeaderName)
	h.Del(ic.h.labelsHeaderName)
}

func (ic *interceptor) commitInformational(w http.ResponseWriter) {
	for _, info := range ic.informational {
		ic.scrubManagedResponseHeader(info.header)
		copyHeaders(w.Header(), info.header)
		w.WriteHeader(info.status)
	}
}

// Hijacked responses cannot be buffered or rolled back. Refuse all managed
// response metadata and session mutations, then delegate the raw connection.
func (ic *interceptor) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := ic.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("session_store: underlying ResponseWriter does not support hijacking")
	}
	ic.discardBackendMetadata()
	ic.hijacked = true
	ic.commitInformational(ic.ResponseWriter)
	copyHeaders(ic.ResponseWriter.Header(), ic.Header())
	if ic.wroteHeader {
		ic.ResponseWriter.WriteHeader(ic.status)
	}
	if ic.body.Len() > 0 {
		if err := ic.body.FlushTo(ic.ResponseWriter); err != nil {
			return nil, nil, err
		}
	}
	return hj.Hijack()
}

func (ic *interceptor) ensureProcessed() {
	ic.once.Do(func() {
		err := ic.process()
		if err == nil {
			return
		}
		// On ANY response-path failure — including a contended lock that skips
		// processLocked entirely — never leak backend secrets: drop every
		// Set-Cookie and the identity header regardless of on_store_error. Under
		// fail_open the request still completes (no 502), just without a managed
		// session; under fail_closed we additionally serve 502.
		h := ic.Header()
		h.Del("Set-Cookie")
		h.Del(ic.h.IdentityHeader)
		h.Del(ic.h.rotateHeaderName)
		h.Del(ic.h.revokeHeaderName)
		h.Del(ic.h.labelsHeaderName)
		fields := []zap.Field{zap.String("op", "response"), zap.Error(err)}
		if ic.live != nil {
			fields = append(fields, zap.String("sid", hashID(ic.live.SessionID)))
		}
		ic.h.logger.Error("session store error", fields...)
		// An explicit logout must never appear successful if its server-side
		// revocation failed, even when ordinary cache operations are fail_open.
		if ic.h.OnStoreError == "fail_closed" || ic.revokeRequested {
			ic.failed = true
			ic.storeErr = err
		}
	})
}

// process runs the response-path logic under an optional per-session lock.
func (ic *interceptor) process() error {
	// Parse and strip the revoke signal before lock acquisition so a contended
	// logout is still recognized as security-critical and fails closed.
	hdr := ic.Header()
	stripManagedTrailerDeclarations(hdr, "Set-Cookie", ic.h.IdentityHeader, ic.h.rotateHeaderName, ic.h.revokeHeaderName, ic.h.labelsHeaderName)
	rawRevoke := hdr.Values(ic.h.revokeHeaderName)
	hdr.Del(ic.h.revokeHeaderName)
	if ic.h.revokeEnabled {
		for _, raw := range rawRevoke {
			want, err := strconv.ParseBool(raw)
			if err != nil {
				ic.h.logger.Warn("invalid revoke header value",
					zap.String("op", "response"), zap.String("value", raw))
				continue
			}
			ic.revokeRequested = ic.revokeRequested || want
		}
	}

	if ic.revokeRequested && ic.resolveErr != nil {
		return fmt.Errorf("cannot revoke unresolved presented session: %w", ic.resolveErr)
	}

	run := func() error { return ic.processLocked() }
	if ic.live != nil {
		return ic.h.manager.WithLock(ic.ctx, ic.live.SessionID, run)
	}
	return run()
}

func (ic *interceptor) processLocked() error {
	hdr := ic.Header()

	// Capture and remove ALL backend Set-Cookie first, so no secret cookie can
	// survive an early return during owner binding or storage.
	setCookies := hdr.Values("Set-Cookie")
	hdr.Del("Set-Cookie")

	// An explicit current-session revocation takes precedence over every other
	// response mutation. Strip all backend controls and cookies, delete the
	// server-side session, and expire the opaque client key.
	if ic.revokeRequested {
		hdr.Del(ic.h.IdentityHeader)
		hdr.Del(ic.h.rotateHeaderName)
		hdr.Del(ic.h.labelsHeaderName)
		if ic.live != nil {
			if err := ic.live.Revoke(ic.ctx); err != nil {
				return err
			}
			ic.live = nil
		}
		if ic.hadProxyCookie {
			hdr.Add("Set-Cookie", ic.h.buildExpiredProxyCookie())
		}
		return nil
	}

	// (5) Owner binding from the backend's identity header, then strip it. The
	// header is deleted unconditionally (even when empty) so it never reaches
	// the client.
	var ownerControl *int64
	raw := hdr.Get(ic.h.IdentityHeader)
	hdr.Del(ic.h.IdentityHeader)
	if raw != "" {
		ownerID, err := strconv.ParseInt(raw, 10, 64)
		// Owner ids are positive integers; 0 is the anonymous sentinel.
		if err == nil && ownerID > 0 {
			ownerControl = &ownerID
		}
	}

	// (5b) Backend-requested rotation: read + strip the rotation header. Like
	// the identity header it is deleted unconditionally — even when empty,
	// invalid, or with the feature off — so it never reaches the client. A
	// request with no live session triggers nothing: we never mint a session
	// just to rotate it.
	rotateRequested := false
	rawRotate := hdr.Get(ic.h.rotateHeaderName)
	hdr.Del(ic.h.rotateHeaderName)
	if ic.h.rotateEnabled && rawRotate != "" {
		want, err := strconv.ParseBool(rawRotate)
		if err != nil {
			// Explicit failure over guessing: an unparseable value is a backend
			// bug worth surfacing, not a rotation.
			ic.h.logger.Warn("invalid rotation header value",
				zap.String("op", "response"), zap.String("value", rawRotate))
		}
		rotateRequested = err == nil && want
	}

	// (5c) Label grants: header presence (even empty) REPLACES the session's
	// label set; absence changes nothing. Stripped unconditionally so backend
	// grants never reach the client. The reserved "anonymous" label is a
	// sentinel, not a privilege — grants naming it are dropped with a warning.
	var labelsControl *[]string
	rawLabels := hdr.Values(ic.h.labelsHeaderName)
	hdr.Del(ic.h.labelsHeaderName)
	if len(rawLabels) > 0 {
		labels := splitLabels(strings.Join(rawLabels, ","))
		kept := labels[:0]
		for _, lab := range labels {
			if lab == authz.Anonymous {
				ic.h.logger.Warn("ignoring reserved label in grant", zap.String("label", lab))
				continue
			}
			kept = append(kept, lab)
		}
		labelsControl = &kept
	}

	// (6) Parse and filter each captured Set-Cookie. Malformed headers are
	// rejected rather than treated as empty stored cookies. Stored mutations are
	// batched into the final old-key-CAS transition below.
	var cookieMutations []session.CookieMutation
	for _, sc := range setCookies {
		cookie, err := http.ParseSetCookie(sc)
		if err != nil {
			ic.h.logger.Warn("invalid backend Set-Cookie", zap.Error(err))
			continue
		}
		switch ic.h.filter.Decide(cookie.Name) {
		case filter.Forward:
			hdr.Add("Set-Cookie", sc) // reaches the client unchanged
		case filter.Store:
			if cookieDeletesNow(sc, cookie, time.Now()) {
				if ic.live != nil {
					cookieMutations = append(cookieMutations, session.CookieMutation{Name: cookie.Name, Delete: true})
				}
				continue
			}
			if err := ic.ensureLive(); err != nil {
				return err
			}
			cookieMutations = append(cookieMutations, session.CookieMutation{Name: cookie.Name, Value: cookie.Value})
		case filter.Drop:
			// omit entirely
		}
	}

	// (6b) Commit owner, labels, and any requested/due rotation in one atomic
	// transition after all cookie persistence. This is the final fallible step:
	// a key swap cannot be followed by a cookie-store failure, and a CAS loser
	// cannot partially change owner, labels, timestamps, or cascade TTLs.
	if ic.live == nil && (ownerControl != nil || (labelsControl != nil && len(*labelsControl) > 0)) {
		if err := ic.ensureLive(); err != nil {
			return err
		}
	}
	if ic.live != nil {
		if err := ic.live.ApplyResponse(ic.ctx, ownerControl, labelsControl, rotateRequested, cookieMutations); err != nil {
			return err
		}
	}

	// (7) Emit/refresh the proxy cookie if the session is new or rotated.
	if ic.live != nil {
		if val, changed := ic.live.NewProxyCookie(); changed {
			hdr.Add("Set-Cookie", ic.h.buildProxyCookie(val))
		}
	}
	return nil
}

// ensureLive lazily creates a session the first time a store/bind is needed.
func (ic *interceptor) ensureLive() error {
	if ic.live != nil {
		return nil
	}
	l, err := ic.h.manager.Begin(ic.ctx)
	if err != nil {
		return err
	}
	ic.live = l
	return nil
}

func (h *Handler) proxyCookiePath() string {
	if h.Cookie.Path == "" {
		return "/"
	}
	return h.Cookie.Path
}

func (h *Handler) buildProxyCookie(value string) string {
	c := &http.Cookie{
		Name:     h.Cookie.Name,
		Value:    value,
		Path:     h.proxyCookiePath(),
		HttpOnly: true,
		Secure:   !h.Cookie.Insecure,
	}
	switch strings.ToLower(h.Cookie.SameSite) {
	case "strict":
		c.SameSite = http.SameSiteStrictMode
	case "none":
		c.SameSite = http.SameSiteNoneMode
	default:
		c.SameSite = http.SameSiteLaxMode
	}
	return c.String()
}

func (h *Handler) buildExpiredProxyCookie() string {
	c := &http.Cookie{
		Name:     h.Cookie.Name,
		Value:    "",
		Path:     h.proxyCookiePath(),
		HttpOnly: true,
		Secure:   !h.Cookie.Insecure,
		MaxAge:   -1,
		Expires:  time.Unix(1, 0).UTC(),
	}
	switch strings.ToLower(h.Cookie.SameSite) {
	case "strict":
		c.SameSite = http.SameSiteStrictMode
	case "none":
		c.SameSite = http.SameSiteNoneMode
	default:
		c.SameSite = http.SameSiteLaxMode
	}
	return c.String()
}

// cookieDeletesNow reports whether a parsed Set-Cookie instructs the client to
// remove the cookie. The raw header is inspected because net/http intentionally
// normalizes Max-Age more strictly than RFC 6265's user-agent algorithm.
func cookieDeletesNow(raw string, c *http.Cookie, now time.Time) bool {
	if deletes, ok := maxAgeDeletes(raw); ok {
		return deletes
	}
	return !c.Expires.IsZero() && !c.Expires.After(now)
}

// maxAgeDeletes returns the deletion decision from the last syntactically valid
// Max-Age attribute. RFC 6265 accepts leading zeroes, rejects a leading plus,
// and ignores invalid attributes. A valid non-positive value deletes now.
func maxAgeDeletes(raw string) (deletes, ok bool) {
	parts := strings.Split(raw, ";")
	for _, part := range parts[1:] {
		name, value, found := strings.Cut(part, "=")
		if !found || !strings.EqualFold(strings.TrimSpace(name), "Max-Age") {
			continue
		}
		value = strings.TrimSpace(value)
		negative := strings.HasPrefix(value, "-")
		digits := value
		if negative {
			digits = value[1:]
		}
		if digits == "" {
			continue
		}
		allZero := true
		valid := true
		for _, ch := range digits {
			if ch < '0' || ch > '9' {
				valid = false
				break
			}
			if ch != '0' {
				allZero = false
			}
		}
		if !valid {
			continue
		}
		ok = true
		deletes = negative || allZero
	}
	return deletes, ok
}

// hashID returns a short, non-reversible tag for logging ids safely.
func hashID(id string) string {
	sum := sha256.Sum256([]byte(id))
	return hex.EncodeToString(sum[:6])
}
