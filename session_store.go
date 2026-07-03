package gosestor

import (
	"fmt"
	"net/http"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"gosestor/internal/filter"
	"gosestor/internal/session"
	"gosestor/internal/store"
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
	RotateOnLogin   bool           `json:"rotate_on_login,omitempty"`
	RotateInterval  caddy.Duration `json:"rotate_interval,omitempty"`
	RotateGrace     caddy.Duration `json:"rotate_grace,omitempty"`
	Synchronize     bool           `json:"synchronize_sessions,omitempty"`
	OnStoreError    string         `json:"on_store_error,omitempty"`

	filter  *filter.Filter
	manager *session.Manager
	store   store.Store
	logger  *zap.Logger
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
	h.Cookie.SameSite = "lax"
	h.IdentityHeader = "X-Auth-User"
	h.OnStoreError = "fail_closed"
	h.Redis.KeyPrefix = "gs:"
	h.RotateOnLogin = true // default: rotate KEY_ID on OWNER_ID transition

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
						fmt.Sscanf(d.Val(), "%d", &h.Redis.DB)
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
				// v1 always rotates on an OWNER_ID transition; accepted for
				// forward-compat. `false` disables identity-change rotation.
				if !d.NextArg() {
					return d.ArgErr()
				}
				h.RotateOnLogin = d.Val() == "true"
			case "rotate_interval":
				// Deferred groundwork: parsed and stored, not yet wired to
				// periodic rotation. Zero = off.
				if !d.NextArg() {
					return d.ArgErr()
				}
				dur, err := time.ParseDuration(d.Val())
				if err != nil {
					return err
				}
				h.RotateInterval = caddy.Duration(dur)
			case "rotate_grace":
				if !d.NextArg() {
					return d.ArgErr()
				}
				dur, err := time.ParseDuration(d.Val())
				if err != nil {
					return err
				}
				h.RotateGrace = caddy.Duration(dur)
			case "synchronize_sessions":
				if !d.NextArg() {
					return d.ArgErr()
				}
				h.Synchronize = d.Val() == "true"
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
	if h.RotateGrace == 0 {
		h.RotateGrace = caddy.Duration(60 * time.Second)
	}
	client := redis.NewClient(&redis.Options{
		Addr: h.Redis.Address, Password: h.Redis.Password, DB: h.Redis.DB,
	})
	h.store = store.NewRedis(client, h.Redis.KeyPrefix)
	h.filter = filter.New(h.Forward, h.Store)
	h.manager = session.NewManager(h.store, session.RealClock{}, session.Config{
		Inactive:    time.Duration(h.InactiveTimeout),
		Final:       time.Duration(h.FinalTimeout),
		Grace:       time.Duration(h.RotateGrace),
		Synchronize: h.Synchronize,
	}, nil)
	return nil
}

func (h *Handler) Validate() error {
	if h.Redis.Address == "" {
		return fmt.Errorf("session_store: redis address is required")
	}
	if h.OnStoreError != "fail_closed" && h.OnStoreError != "fail_open" {
		return fmt.Errorf("session_store: on_store_error must be fail_closed or fail_open")
	}
	return nil
}

// interface guards
var (
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddy.Validator             = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
	_ caddyfile.Unmarshaler       = (*Handler)(nil)
)

// ServeHTTP is implemented in Task 9; temporary stub keeps this task compiling.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	return next.ServeHTTP(w, r)
}
