package gosestor

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

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
	Path     string `json:"path,omitempty"` // empty => no Path attribute
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
	Synchronize  bool   `json:"synchronize_sessions,omitempty"`
	OnStoreError string `json:"on_store_error,omitempty"`

	filter           *filter.Filter
	manager          *session.Manager
	store            store.Store
	redisClient      *redis.Client
	logger           *zap.Logger
	rotateHeaderName string // effective header to read + strip
	rotateEnabled    bool
}

// defaultRotateHeader is the backend-facing rotation-request header name.
const defaultRotateHeader = "X-Session-Rotate"

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
	// Expose this manager to the admin revoke endpoint (admin.api.gosestor).
	registerRevoker(h)
	return nil
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
	// The rotation header and identity header must differ: one carries a
	// boolean, the other an owner id — a shared name would make the backend's
	// value ambiguous and one feature would silently eat the other's header.
	effRotate := h.RotateHeader
	if effRotate == "" {
		effRotate = defaultRotateHeader
	}
	if !strings.EqualFold(effRotate, "off") && strings.EqualFold(effRotate, h.IdentityHeader) {
		return fmt.Errorf("session_store: rotate_header %q collides with identity_header", effRotate)
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

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	ctx := r.Context()

	// (0) Anti-spoof: never trust a client-supplied identity header. Trailers
	// too — a trailer-borne copy would bypass the header strip and could reach
	// a backend that reads trailers.
	r.Header.Del(h.IdentityHeader)
	if r.Trailer != nil {
		r.Trailer.Del(h.IdentityHeader)
	}

	// (1-4) Resolve any existing session and inject cached cookies upstream.
	var live *session.Live
	if c, err := r.Cookie(h.Cookie.Name); err == nil {
		l, err := h.manager.Resolve(ctx, c.Value)
		if err != nil {
			h.logger.Error("session store error", zap.String("op", "resolve"), zap.Error(err))
			if h.OnStoreError == "fail_closed" {
				return caddyhttp.Error(http.StatusBadGateway, err)
			}
			// fail_open: proceed without a session (live stays nil)
		} else {
			live = l
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
	ic := &interceptor{ResponseWriter: w, h: h, r: r, live: live, ctx: ctx}
	err := next.ServeHTTP(ic, r)
	if err != nil {
		return err
	}
	// If body was never written (e.g. 0-length), ensure headers are processed.
	ic.ensureProcessed()
	if ic.storeErr != nil {
		if ic.wroteHeader {
			return nil // 502 already committed to the client by WriteHeader
		}
		return caddyhttp.Error(http.StatusBadGateway, ic.storeErr)
	}
	return nil
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

// interceptor interface guards: streaming and upgrades must keep working
// through the wrapper (reverse_proxy probes for these).
var (
	_ http.Flusher  = (*interceptor)(nil)
	_ http.Hijacker = (*interceptor)(nil)
)

// interceptor rewrites response headers (Set-Cookie, identity) exactly once,
// just before the first Write/WriteHeader.
type interceptor struct {
	http.ResponseWriter
	h           *Handler
	r           *http.Request
	live        *session.Live
	ctx         context.Context
	once        sync.Once
	failed      bool
	wroteHeader bool
	storeErr    error
}

func (ic *interceptor) WriteHeader(status int) {
	ic.ensureProcessed()
	ic.wroteHeader = true
	if ic.failed {
		ic.ResponseWriter.WriteHeader(http.StatusBadGateway)
		return
	}
	ic.ResponseWriter.WriteHeader(status)
}

func (ic *interceptor) Write(b []byte) (int, error) {
	ic.ensureProcessed()
	if ic.failed {
		return len(b), nil // swallow upstream body on fail_closed
	}
	return ic.ResponseWriter.Write(b)
}

// Flush implements http.Flusher so streaming responses (SSE) work through the
// handler. Headers are processed first — deliberately no Unwrap() is offered,
// since http.ResponseController reaching the underlying writer directly would
// commit headers before the fail-safe scrub had a chance to run.
func (ic *interceptor) Flush() {
	ic.ensureProcessed()
	if ic.failed {
		return // don't stream a body the fail_closed path is swallowing
	}
	if f, ok := ic.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack implements http.Hijacker so proxied WebSocket upgrades work. Headers
// are processed first so managed cookies and the identity header are filtered
// before the connection leaves HTTP's control.
func (ic *interceptor) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	ic.ensureProcessed()
	if ic.failed {
		return nil, nil, fmt.Errorf("session_store: refusing hijack after response-path store failure")
	}
	hj, ok := ic.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("session_store: underlying ResponseWriter does not support hijacking")
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
		h := ic.ResponseWriter.Header()
		h.Del("Set-Cookie")
		h.Del(ic.h.IdentityHeader)
		fields := []zap.Field{zap.String("op", "response"), zap.Error(err)}
		if ic.live != nil {
			fields = append(fields, zap.String("sid", hashID(ic.live.SessionID)))
		}
		ic.h.logger.Error("session store error", fields...)
		if ic.h.OnStoreError == "fail_closed" {
			ic.failed = true
			ic.storeErr = err
		}
	})
}

// process runs the response-path logic under an optional per-session lock.
func (ic *interceptor) process() error {
	run := func() error { return ic.processLocked() }
	if ic.live != nil {
		return ic.h.manager.WithLock(ic.ctx, ic.live.SessionID, run)
	}
	return run()
}

func (ic *interceptor) processLocked() error {
	hdr := ic.ResponseWriter.Header()

	// Capture and remove ALL backend Set-Cookie first, so no secret cookie can
	// survive an early return during owner binding or storage.
	setCookies := hdr.Values("Set-Cookie")
	hdr.Del("Set-Cookie")

	// (5) Owner binding from the backend's identity header, then strip it. The
	// header is deleted unconditionally (even when empty) so it never reaches
	// the client.
	raw := hdr.Get(ic.h.IdentityHeader)
	hdr.Del(ic.h.IdentityHeader)
	if raw != "" {
		ownerID, err := strconv.ParseInt(raw, 10, 64)
		// Owner ids are positive integers; 0 is the anonymous sentinel. Guarding
		// here (BindOwner also refuses) avoids minting a session just to no-op.
		if err == nil && ownerID > 0 {
			if err := ic.ensureLive(); err != nil {
				return err
			}
			if _, err := ic.live.BindOwner(ic.ctx, ownerID); err != nil {
				return err
			}
		}
	}

	// (6) Filter each captured Set-Cookie: forward / store / drop.
	for _, sc := range setCookies {
		name, value := parseSetCookie(sc)
		switch ic.h.filter.Decide(name) {
		case filter.Forward:
			hdr.Add("Set-Cookie", sc) // reaches the client unchanged
		case filter.Store:
			if err := ic.ensureLive(); err != nil {
				return err
			}
			if err := ic.live.StoreCookie(ic.ctx, name, value); err != nil {
				return err
			}
		case filter.Drop:
			// omit entirely
		}
	}

	// (6b) Interval rotation, decided in Resolve but executed only here — after
	// the upstream completed, as the LAST fallible step, under the session lock.
	// Any earlier failure returns before the old KEY_ID is touched, so the
	// client's cookie is never invalidated without its replacement being
	// guaranteed a spot in this response.
	if ic.live != nil {
		if err := ic.live.MaybeRotate(ic.ctx); err != nil {
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

func (h *Handler) buildProxyCookie(value string) string {
	c := &http.Cookie{
		Name:     h.Cookie.Name,
		Value:    value,
		HttpOnly: true,
		Secure:   !h.Cookie.Insecure,
	}
	if h.Cookie.Path != "" { // no default Path
		c.Path = h.Cookie.Path
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

// parseSetCookie extracts the name and value from a Set-Cookie header value.
func parseSetCookie(sc string) (name, value string) {
	first := sc
	if i := strings.IndexByte(sc, ';'); i >= 0 {
		first = sc[:i]
	}
	if eq := strings.IndexByte(first, '='); eq >= 0 {
		return strings.TrimSpace(first[:eq]), strings.TrimSpace(first[eq+1:])
	}
	return strings.TrimSpace(first), ""
}

// hashID returns a short, non-reversible tag for logging ids safely.
func hashID(id string) string {
	sum := sha256.Sum256([]byte(id))
	return hex.EncodeToString(sum[:6])
}
