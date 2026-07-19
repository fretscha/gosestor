package gosestor

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/fretscha/gosestor/internal/filter"
	"github.com/fretscha/gosestor/internal/session"
	"github.com/fretscha/gosestor/internal/store"
)

// testClock is a manually-advanced session.Clock for handler-level tests.
type testClock struct{ t time.Time }

func (c *testClock) Now() time.Time          { return c.t }
func (c *testClock) advance(d time.Duration) { c.t = c.t.Add(d) }

// newRotationTestHandler wires a Handler over an in-memory store with interval
// rotation enabled, bypassing Provision (no Redis needed).
func newRotationTestHandler(clk session.Clock) (*Handler, *session.Manager, *store.Memory) {
	st := store.NewMemory()
	mgr := session.NewManager(st, clk, session.Config{
		Inactive:       30 * time.Minute,
		Final:          8 * time.Hour,
		RotateOnLogin:  true,
		RotateInterval: 10 * time.Minute,
	}, nil)
	h := &Handler{
		Cookie:         CookieConfig{Name: "__gosestor"},
		IdentityHeader: "X-Auth-User",
		OnStoreError:   "fail_closed",
		manager:        mgr,
		store:          st,
		filter:         filter.New(nil, []string{"JSESSIONID"}),
		logger:         zap.NewNop(),
	}
	return h, mgr, st
}

// TestUpstreamErrorAtRotationBoundaryKeepsOldKey is the session-loss regression
// guard for interval rotation: if the upstream fails on the very request that
// crosses the rotation boundary, the client's KEY_ID must remain valid — the
// rotated cookie could never have reached them.
func TestUpstreamErrorAtRotationBoundaryKeepsOldKey(t *testing.T) {
	ctx := context.Background()
	clk := &testClock{t: time.Unix(1_000_000, 0)}
	h, mgr, _ := newRotationTestHandler(clk)

	live, err := mgr.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	key := live.KeyID

	clk.advance(11 * time.Minute) // past the 10m rotation interval

	req := httptest.NewRequest(http.MethodGet, "http://x/", nil)
	req.Header.Set("Cookie", "__gosestor="+key)
	rec := httptest.NewRecorder()
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return fmt.Errorf("backend blew up")
	})
	if err := h.ServeHTTP(rec, req, next); err == nil {
		t.Fatal("upstream error must propagate")
	}

	// The client still holds `key` and never saw a replacement — it must resolve.
	if got, err := mgr.Resolve(ctx, key); err != nil || got == nil {
		t.Fatalf("old key stranded after failed request at rotation boundary: got=%+v err=%v", got, err)
	}
}

// TestRotationSurvivesSuccessfulResponse: on a healthy request past the
// boundary, the response carries the rotated cookie and the old key dies.
func TestRotationSurvivesSuccessfulResponse(t *testing.T) {
	ctx := context.Background()
	clk := &testClock{t: time.Unix(1_000_000, 0)}
	h, mgr, _ := newRotationTestHandler(clk)

	live, err := mgr.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	key := live.KeyID

	clk.advance(11 * time.Minute)

	req := httptest.NewRequest(http.MethodGet, "http://x/", nil)
	req.Header.Set("Cookie", "__gosestor="+key)
	rec := httptest.NewRecorder()
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(http.StatusOK)
		return nil
	})
	if err := h.ServeHTTP(rec, req, next); err != nil {
		t.Fatal(err)
	}

	// The response must carry the new proxy cookie...
	var newKey string
	for _, c := range rec.Result().Cookies() {
		if c.Name == "__gosestor" {
			newKey = c.Value
		}
	}
	if newKey == "" || newKey == key {
		t.Fatalf("rotated cookie not delivered: %q", newKey)
	}
	// ...the new key resolves, the old one is gone.
	if got, _ := mgr.Resolve(ctx, newKey); got == nil {
		t.Fatal("rotated key does not resolve")
	}
	if got, _ := mgr.Resolve(ctx, key); got != nil {
		t.Fatal("old key survived a delivered rotation")
	}
}

func TestUnmarshalCaddyfile(t *testing.T) {
	input := `session_store {
		redis {
			address localhost:6379
			key_prefix gs:
		}
		cookie {
			name __gosestor
			same_site lax
		}
		forward XSRF-TOKEN
		store JSESSIONID sessionid
		inactive_timeout 30m
		final_timeout 8h
		identity_header X-Auth-User
		synchronize_sessions false
		on_store_error fail_closed
	}`
	d := caddyfile.NewTestDispenser(input)
	var h Handler
	if err := h.UnmarshalCaddyfile(d); err != nil {
		t.Fatal(err)
	}
	if h.Cookie.Name != "__gosestor" {
		t.Errorf("cookie name = %q", h.Cookie.Name)
	}
	if len(h.Store) != 2 || h.Store[0] != "JSESSIONID" {
		t.Errorf("store list = %v", h.Store)
	}
	if h.Forward[0] != "XSRF-TOKEN" {
		t.Errorf("forward list = %v", h.Forward)
	}
	if h.IdentityHeader != "X-Auth-User" {
		t.Errorf("identity header = %q", h.IdentityHeader)
	}
	if h.OnStoreError != "fail_closed" {
		t.Errorf("on_store_error = %q", h.OnStoreError)
	}
}

// TestPrepareUpstreamCookiesStripsManagedAndProxy is the cookie-smuggling
// regression guard: the client must not be able to send the proxy KEY_ID or a
// store-managed cookie to the backend; the server-held value is authoritative.
func TestPrepareUpstreamCookiesStripsManagedAndProxy(t *testing.T) {
	h := &Handler{Cookie: CookieConfig{Name: "__gosestor"}}
	h.filter = filter.New([]string{"XSRF-TOKEN"}, []string{"JSESSIONID"})

	req, _ := http.NewRequest("GET", "http://x/", nil)
	// Client sends the proxy key, a forged managed cookie, and a normal one.
	req.Header.Set("Cookie", "__gosestor=KEY123; JSESSIONID=forged; other=keep")

	h.prepareUpstreamCookies(req, map[string]string{"JSESSIONID": "server-authoritative"})

	got := req.Header.Get("Cookie")
	if strings.Contains(got, "__gosestor") || strings.Contains(got, "KEY123") {
		t.Fatalf("proxy KEY_ID leaked upstream: %q", got)
	}
	if strings.Contains(got, "forged") {
		t.Fatalf("client smuggled a managed cookie upstream: %q", got)
	}
	if !strings.Contains(got, "JSESSIONID=server-authoritative") {
		t.Fatalf("server-held managed cookie not injected: %q", got)
	}
	if !strings.Contains(got, "other=keep") {
		t.Fatalf("non-managed client cookie dropped: %q", got)
	}
}

func TestValidateRejectsSameSiteNoneInsecure(t *testing.T) {
	h := &Handler{OnStoreError: "fail_closed"}
	h.Redis.Address = "localhost:6379"
	h.Cookie.SameSite = "none"
	h.Cookie.Insecure = true
	if err := h.Validate(); err == nil {
		t.Fatal("same_site none + insecure must be rejected by Validate")
	}
}

func TestValidateRejectsNegativeDurations(t *testing.T) {
	for _, tc := range []struct {
		name string
		mut  func(*Handler)
	}{
		{"inactive_timeout", func(h *Handler) { h.InactiveTimeout = caddy.Duration(-time.Minute) }},
		{"final_timeout", func(h *Handler) { h.FinalTimeout = caddy.Duration(-time.Hour) }},
		{"rotate_interval", func(h *Handler) { h.RotateInterval = caddy.Duration(-time.Minute) }},
	} {
		h := &Handler{OnStoreError: "fail_closed"}
		h.Redis.Address = "localhost:6379"
		tc.mut(h)
		if err := h.Validate(); err == nil {
			t.Errorf("negative %s must be rejected by Validate", tc.name)
		}
	}
}

// TestUnmarshalCaddyfileBooleans: boolean directives must reject anything
// strconv.ParseBool doesn't understand — `synchronize_sessions yes` silently
// meaning false would disable the lock the operator asked for.
func TestUnmarshalCaddyfileBooleans(t *testing.T) {
	for _, tc := range []struct {
		input   string
		wantErr bool
	}{
		{"session_store {\n synchronize_sessions yes \n}", true},
		{"session_store {\n synchronize_sessions on \n}", true},
		{"session_store {\n rotate_on_login enabled \n}", true},
		{"session_store {\n synchronize_sessions true \n}", false},
		{"session_store {\n rotate_on_login false \n}", false},
	} {
		var h Handler
		err := h.UnmarshalCaddyfile(caddyfile.NewTestDispenser(tc.input))
		if tc.wantErr && err == nil {
			t.Errorf("%q: expected a parse error", tc.input)
		}
		if !tc.wantErr && err != nil {
			t.Errorf("%q: unexpected error %v", tc.input, err)
		}
	}
	// rotate_on_login false must land as an explicit *bool, not be dropped.
	var h Handler
	_ = h.UnmarshalCaddyfile(caddyfile.NewTestDispenser("session_store {\n rotate_on_login false \n}"))
	if h.RotateOnLogin == nil || *h.RotateOnLogin {
		t.Fatalf("rotate_on_login false not captured: %v", h.RotateOnLogin)
	}
	// Omitted → nil → Provision resolves to true (fail-safe default).
	var h2 Handler
	_ = h2.UnmarshalCaddyfile(caddyfile.NewTestDispenser("session_store {\n}"))
	if h2.RotateOnLogin != nil {
		t.Fatalf("omitted rotate_on_login must stay nil (fail-safe), got %v", *h2.RotateOnLogin)
	}
}

// TestIdentityTrailerStripped: a client smuggling the identity header as an
// HTTP trailer must not get it past the anti-spoof strip.
func TestIdentityTrailerStripped(t *testing.T) {
	clk := &testClock{t: time.Unix(1_000_000, 0)}
	h, _, _ := newRotationTestHandler(clk)

	req := httptest.NewRequest(http.MethodPost, "http://x/", strings.NewReader("body"))
	req.Header.Set("X-Auth-User", "666")
	req.Trailer = http.Header{"X-Auth-User": []string{"666"}}
	rec := httptest.NewRecorder()

	var seenHeader, seenTrailer string
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		seenHeader = r.Header.Get("X-Auth-User")
		if r.Trailer != nil {
			seenTrailer = r.Trailer.Get("X-Auth-User")
		}
		return nil
	})
	if err := h.ServeHTTP(rec, req, next); err != nil {
		t.Fatal(err)
	}
	if seenHeader != "" || seenTrailer != "" {
		t.Fatalf("identity leaked upstream: header=%q trailer=%q", seenHeader, seenTrailer)
	}
}

// hijackableRecorder wraps httptest.ResponseRecorder with a Hijack that
// records the call, standing in for a real hijackable connection.
type hijackableRecorder struct {
	*httptest.ResponseRecorder
	hijacked bool
}

func (h *hijackableRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h.hijacked = true
	return nil, nil, nil
}

// TestInterceptorFlushProcessesHeadersFirst: an early Flush (SSE) must run the
// header pipeline before bytes hit the wire — a store-managed Set-Cookie must
// already be swallowed, not leaked by the flush.
func TestInterceptorFlushProcessesHeadersFirst(t *testing.T) {
	clk := &testClock{t: time.Unix(1_000_000, 0)}
	h, _, _ := newRotationTestHandler(clk)

	req := httptest.NewRequest(http.MethodGet, "http://x/", nil)
	rec := httptest.NewRecorder()
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Add("Set-Cookie", "JSESSIONID=secret; Path=/")
		f, ok := w.(http.Flusher)
		if !ok {
			t.Fatal("interceptor does not implement http.Flusher")
		}
		f.Flush() // stream start — headers commit NOW
		_, _ = w.Write([]byte("data: hi\n\n"))
		return nil
	})
	if err := h.ServeHTTP(rec, req, next); err != nil {
		t.Fatal(err)
	}
	if !rec.Flushed {
		t.Fatal("flush was not forwarded to the underlying writer")
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == "JSESSIONID" {
			t.Fatal("store-managed cookie leaked to the client via early flush")
		}
	}
}

// TestInterceptorHijackProcessesHeadersFirst: a WebSocket upgrade must filter
// managed cookies before the connection is hijacked away from HTTP.
func TestInterceptorHijackProcessesHeadersFirst(t *testing.T) {
	clk := &testClock{t: time.Unix(1_000_000, 0)}
	h, _, _ := newRotationTestHandler(clk)

	req := httptest.NewRequest(http.MethodGet, "http://x/", nil)
	rec := &hijackableRecorder{ResponseRecorder: httptest.NewRecorder()}
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Add("Set-Cookie", "JSESSIONID=secret; Path=/")
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Fatal("interceptor does not implement http.Hijacker")
		}
		if _, _, err := hj.Hijack(); err != nil {
			t.Fatalf("hijack failed: %v", err)
		}
		return nil
	})
	if err := h.ServeHTTP(rec, req, next); err != nil {
		t.Fatal(err)
	}
	if !rec.hijacked {
		t.Fatal("hijack was not delegated to the underlying writer")
	}
	if got := rec.Header().Values("Set-Cookie"); len(got) != 0 {
		for _, sc := range got {
			if strings.Contains(sc, "JSESSIONID") {
				t.Fatal("store-managed cookie survived until hijack")
			}
		}
	}
}

// TestCleanupClosesRedisClient: config reloads must not leak connection pools.
func TestCleanupClosesRedisClient(t *testing.T) {
	client := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"}) // never dialed
	h := &Handler{redisClient: client}
	if err := h.Cleanup(); err != nil {
		t.Fatal(err)
	}
	// A closed client refuses new commands immediately.
	if err := client.Ping(context.Background()).Err(); err == nil || !strings.Contains(err.Error(), "closed") {
		t.Fatalf("client not closed after Cleanup: %v", err)
	}
}

// TestUnmarshalRotateHeader: the rotate_header directive accepts a custom
// name or the literal "off"; absent leaves the field empty (resolved to the
// default in Provision).
func TestUnmarshalRotateHeader(t *testing.T) {
	cases := []struct{ name, config, want string }{
		{"default", "session_store {\n}", ""},
		{"custom", "session_store {\n\trotate_header X-Rotate-Now\n}", "X-Rotate-Now"},
		{"off", "session_store {\n\trotate_header off\n}", "off"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := caddyfile.NewTestDispenser(tc.config)
			var h Handler
			if err := h.UnmarshalCaddyfile(d); err != nil {
				t.Fatal(err)
			}
			if h.RotateHeader != tc.want {
				t.Fatalf("RotateHeader = %q, want %q", h.RotateHeader, tc.want)
			}
		})
	}
}

// TestResolveRotateHeader: "" enables the default name; a custom name enables
// itself; "off" disables triggering but keeps the default name for stripping,
// so a disabled deployment still never leaks the header to clients.
func TestResolveRotateHeader(t *testing.T) {
	cases := []struct {
		name, configured, wantName string
		wantEnabled                bool
	}{
		{"default-on", "", "X-Session-Rotate", true},
		{"custom-on", "X-Rotate-Now", "X-Rotate-Now", true},
		{"off-still-strips-default", "off", "X-Session-Rotate", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := &Handler{RotateHeader: tc.configured}
			h.resolveRotateHeader()
			if h.rotateHeaderName != tc.wantName || h.rotateEnabled != tc.wantEnabled {
				t.Fatalf("got (%q, %v), want (%q, %v)",
					h.rotateHeaderName, h.rotateEnabled, tc.wantName, tc.wantEnabled)
			}
		})
	}
}

// TestValidateRejectsRotateIdentityCollision: one header carries a boolean,
// the other an owner id — a shared name would make the backend's value
// ambiguous and one feature would silently eat the other's header.
func TestValidateRejectsRotateIdentityCollision(t *testing.T) {
	h := &Handler{
		Redis:          RedisConfig{Address: "localhost:6379"},
		OnStoreError:   "fail_closed",
		IdentityHeader: "X-Session-Rotate", // collides with the rotate default
	}
	if err := h.Validate(); err == nil {
		t.Fatal("rotate_header colliding with identity_header must be rejected")
	}
}
