package gosestor

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/fretscha/gosestor/internal/authz"
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
		Cookie:           CookieConfig{Name: "__gosestor"},
		IdentityHeader:   "X-Auth-User",
		OnStoreError:     "fail_closed",
		manager:          mgr,
		store:            st,
		filter:           filter.New(nil, []string{"JSESSIONID"}),
		logger:           zap.NewNop(),
		rotateHeaderName: defaultRotateHeader,
		rotateEnabled:    true,
		revokeHeaderName: defaultRevokeHeader,
		revokeEnabled:    true,
		labelsHeaderName: defaultLabelsHeader,
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
		w.Header().Add("Set-Cookie", "JSESSIONID=must-not-leak; Path=/")
		w.Header().Set("X-Auth-User", "42")
		w.Header().Set(defaultRotateHeader, "1")
		w.Header().Set(defaultRevokeHeader, "1")
		w.Header().Set(defaultLabelsHeader, "adm")
		w.Header().Set("X-Backend-Secret", "must-not-leak")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("must-not-leak"))
		w.(http.Flusher).Flush()
		return fmt.Errorf("backend blew up")
	})
	if err := h.ServeHTTP(rec, req, next); err == nil {
		t.Fatal("upstream error must propagate")
	}

	// The client still holds `key` and never saw a replacement — it must resolve.
	if got, err := mgr.Resolve(ctx, key); err != nil || got == nil {
		t.Fatalf("old key stranded after failed request at rotation boundary: got=%+v err=%v", got, err)
	}
	if rec.Body.Len() != 0 {
		t.Fatalf("downstream error leaked staged body: %q", rec.Body.String())
	}
	for _, name := range []string{"Set-Cookie", "X-Auth-User", defaultRotateHeader, defaultRevokeHeader, defaultLabelsHeader, "X-Backend-Secret"} {
		if got := rec.Header().Values(name); len(got) != 0 {
			t.Fatalf("downstream error leaked %s: %v", name, got)
		}
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
		revoke_header X-Revoke-Now
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
	if h.RevokeHeader != "X-Revoke-Now" {
		t.Errorf("revoke header = %q", h.RevokeHeader)
	}
	if h.OnStoreError != "fail_closed" {
		t.Errorf("on_store_error = %q", h.OnStoreError)
	}
}

// TestPrepareUpstreamCookiesStripsManagedAndProxy is the cookie-smuggling
// regression guard: the client must not be able to send the proxy KEY_ID or a
// store-managed cookie to the backend; the server-held value is authoritative.
func TestPrepareUpstreamStripsAllManagedControlHeaders(t *testing.T) {
	h := &Handler{
		Cookie:           CookieConfig{Name: "__gosestor"},
		IdentityHeader:   "X-Auth-User",
		rotateHeaderName: defaultRotateHeader,
		revokeHeaderName: defaultRevokeHeader,
		labelsHeaderName: defaultLabelsHeader,
		logger:           zap.NewNop(),
	}
	req := httptest.NewRequest(http.MethodGet, "http://x/", nil)
	req.Trailer = make(http.Header)
	managed := []string{h.IdentityHeader, h.rotateHeaderName, h.revokeHeaderName, h.labelsHeaderName}
	for _, name := range managed {
		req.Header.Set(name, "forged")
		req.Trailer.Set(name, "forged-trailer")
	}
	rec := httptest.NewRecorder()
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		for _, name := range managed {
			if got := r.Header.Get(name); got != "" {
				t.Errorf("managed request header %s reached backend: %q", name, got)
			}
			if got := r.Trailer.Get(name); got != "" {
				t.Errorf("managed request trailer %s reached backend: %q", name, got)
			}
		}
		return nil
	})
	if err := h.ServeHTTP(rec, req, next); err != nil {
		t.Fatal(err)
	}
}

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

type lateTrailerBody struct {
	trailer http.Header
	names   []string
	done    bool
}

func (b *lateTrailerBody) Read(p []byte) (int, error) {
	if b.done {
		return 0, io.EOF
	}
	b.done = true
	for _, name := range b.names {
		b.trailer.Set(name, "forged-late")
	}
	p[0] = 'x'
	return 1, io.EOF
}

func (*lateTrailerBody) Close() error { return nil }

func TestLateManagedTrailersAreStrippedAfterBodyRead(t *testing.T) {
	clk := &testClock{t: time.Unix(1_000_000, 0)}
	h, _, _ := newRotationTestHandler(clk)
	managed := []string{h.IdentityHeader, h.rotateHeaderName, h.revokeHeaderName, h.labelsHeaderName}
	trailers := make(http.Header)
	req := httptest.NewRequest(http.MethodPost, "http://x/", nil)
	req.Trailer = trailers
	req.Body = &lateTrailerBody{trailer: trailers, names: managed}
	rec := httptest.NewRecorder()
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		if _, err := io.ReadAll(r.Body); err != nil {
			return err
		}
		for _, name := range managed {
			if got := r.Trailer.Get(name); got != "" {
				t.Errorf("late managed trailer %s reached backend: %q", name, got)
			}
		}
		return nil
	})
	if err := h.ServeHTTP(rec, req, next); err != nil {
		t.Fatal(err)
	}
}

func TestInterceptorPreservesStagedStatusSemantics(t *testing.T) {
	ic := &interceptor{responseHeader: make(http.Header)}
	ic.Header().Set("Link", "</style.css>; rel=preload")
	ic.WriteHeader(http.StatusEarlyHints)
	if ic.wroteHeader {
		t.Fatal("informational response became the final response")
	}
	ic.WriteHeader(http.StatusCreated)
	if !ic.wroteHeader || ic.status != http.StatusCreated {
		t.Fatalf("final status = %d, wrote=%v", ic.status, ic.wroteHeader)
	}
	if len(ic.informational) != 1 || ic.informational[0].status != http.StatusEarlyHints {
		t.Fatalf("informational responses = %+v", ic.informational)
	}

	for _, status := range []int{http.StatusNoContent, http.StatusNotModified} {
		bodyless := &interceptor{responseHeader: make(http.Header)}
		bodyless.WriteHeader(status)
		if n, err := bodyless.Write([]byte("forbidden")); n != 0 || !errors.Is(err, http.ErrBodyNotAllowed) {
			t.Fatalf("status %d body write = (%d, %v)", status, n, err)
		}
	}

	invalid := &interceptor{responseHeader: make(http.Header)}
	defer func() {
		if recover() == nil {
			t.Fatal("invalid status did not panic")
		}
	}()
	invalid.WriteHeader(42)
}

func TestStagedBodySpillsToPrivateTemporaryFileAndCleansUp(t *testing.T) {
	var body stagedBody
	payload := strings.Repeat("x", stagedResponseMemoryLimit+1)
	if _, err := body.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	if body.file == nil {
		t.Fatal("response larger than memory limit did not spill")
	}
	name := body.file.Name()
	if info, err := body.file.Stat(); err != nil || info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("staged file permissions are not private: info=%v err=%v", info, err)
	}
	var got strings.Builder
	if err := body.FlushTo(&got); err != nil {
		t.Fatal(err)
	}
	if got.String() != payload {
		t.Fatalf("staged payload mismatch: got %d bytes", got.Len())
	}
	if err := body.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(name); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("staged file remains after close: %v", err)
	}
}

func TestLateManagedResponseTrailersAreDiscarded(t *testing.T) {
	clk := &testClock{t: time.Unix(1_000_000, 0)}
	h, _, _ := newRotationTestHandler(clk)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://x/", nil)
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) error {
		w.Header().Add("Trailer", defaultRevokeHeader+", "+defaultLabelsHeader+", Set-Cookie, X-Trace")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
		w.Header().Set(defaultRevokeHeader, "1")
		w.Header().Set(defaultLabelsHeader, "adm")
		w.Header().Set("Set-Cookie", "JSESSIONID=late-secret; Path=/")
		w.Header().Set("X-Trace", "kept")
		return nil
	})
	if err := h.ServeHTTP(rec, req, next); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{defaultRevokeHeader, defaultLabelsHeader, "Set-Cookie"} {
		if got := rec.Header().Values(name); len(got) != 0 {
			t.Fatalf("late managed trailer %s leaked: %v", name, got)
		}
	}
	if got := rec.Header().Get("Trailer"); got != "X-Trace" {
		t.Fatalf("Trailer declaration = %q, want X-Trace", got)
	}
	if got := rec.Header().Get("X-Trace"); got != "kept" {
		t.Fatalf("unmanaged trailer = %q", got)
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

// TestInterceptorFlushDefersCommit: an early Flush (SSE) is staged until the
// downstream handler returns, so a later error can still discard all metadata,
// body bytes, and session mutations.
func TestInterceptorFlushDefersCommit(t *testing.T) {
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
	if rec.Flushed {
		t.Fatal("flush reached the underlying writer before downstream completion")
	}
	if got := rec.Body.String(); got != "data: hi\n\n" {
		t.Fatalf("body = %q", got)
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
		w.Header().Set("Upgrade", "websocket")
		w.Header().Set("Connection", "Upgrade")
		w.WriteHeader(http.StatusSwitchingProtocols)
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
	if rec.Code != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade status = %d, want 101", rec.Code)
	}
	if rec.Header().Get("Upgrade") != "websocket" || rec.Header().Get("Connection") != "Upgrade" {
		t.Fatalf("upgrade handshake headers were not committed: %v", rec.Header())
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

func TestResolveRevokeHeader(t *testing.T) {
	cases := []struct {
		name, configured, wantName string
		wantEnabled                bool
	}{
		{"default-on", "", "X-Session-Revoke", true},
		{"custom-on", "X-Revoke-Now", "X-Revoke-Now", true},
		{"off-still-strips-default", "off", "X-Session-Revoke", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := &Handler{RevokeHeader: tc.configured}
			h.resolveRevokeHeader()
			if h.revokeHeaderName != tc.wantName || h.revokeEnabled != tc.wantEnabled {
				t.Fatalf("got (%q, %v), want (%q, %v)",
					h.revokeHeaderName, h.revokeEnabled, tc.wantName, tc.wantEnabled)
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

func TestValidateRejectsRevokeHeaderCollisions(t *testing.T) {
	for _, tc := range []struct {
		name string
		h    Handler
	}{
		{
			name: "identity",
			h:    Handler{IdentityHeader: defaultRevokeHeader},
		},
		{
			name: "rotation",
			h:    Handler{IdentityHeader: "X-Auth-User", RotateHeader: "X-Control", RevokeHeader: "X-Control"},
		},
		{
			name: "labels",
			h:    Handler{IdentityHeader: "X-Auth-User", LabelsHeader: "X-Control", RevokeHeader: "X-Control"},
		},
		{
			name: "disabled trigger still strips",
			h:    Handler{IdentityHeader: "X-Auth-User", LabelsHeader: defaultRevokeHeader, RevokeHeader: "off"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.h.Redis.Address = "localhost:6379"
			tc.h.OnStoreError = "fail_closed"
			if err := tc.h.Validate(); err == nil {
				t.Fatal("revoke_header collision must be rejected")
			}
		})
	}
}

// TestRotateHeaderRotatesAndStrips: X-Session-Rotate: 1 from the backend
// swaps the proxy cookie, kills the old key, and never reaches the client.
func TestRotateHeaderRotatesAndStrips(t *testing.T) {
	ctx := context.Background()
	clk := &testClock{t: time.Unix(1_000_000, 0)}
	h, mgr, _ := newRotationTestHandler(clk)

	live, err := mgr.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	key := live.KeyID

	req := httptest.NewRequest(http.MethodGet, "http://x/", nil)
	req.Header.Set("Cookie", "__gosestor="+key)
	rec := httptest.NewRecorder()
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("X-Session-Rotate", "1")
		w.WriteHeader(http.StatusOK)
		return nil
	})
	if err := h.ServeHTTP(rec, req, next); err != nil {
		t.Fatal(err)
	}

	if got := rec.Result().Header.Get("X-Session-Rotate"); got != "" {
		t.Fatalf("rotation header leaked to client: %q", got)
	}
	var newKey string
	for _, c := range rec.Result().Cookies() {
		if c.Name == "__gosestor" {
			newKey = c.Value
		}
	}
	if newKey == "" || newKey == key {
		t.Fatalf("expected a rotated proxy cookie, got %q", newKey)
	}
	if old, _ := mgr.Resolve(ctx, key); old != nil {
		t.Fatal("old key survived a backend-requested rotation")
	}
	if fresh, _ := mgr.Resolve(ctx, newKey); fresh == nil {
		t.Fatal("rotated key does not resolve")
	}
}

// TestRotateHeaderDisabledStillStrips: with rotate_header off the value is
// ignored — no rotation — but the header is still stripped so backend
// signaling never leaks to the client.
func TestRotateHeaderDisabledStillStrips(t *testing.T) {
	ctx := context.Background()
	clk := &testClock{t: time.Unix(1_000_000, 0)}
	h, mgr, _ := newRotationTestHandler(clk)
	h.rotateEnabled = false

	live, err := mgr.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	key := live.KeyID

	req := httptest.NewRequest(http.MethodGet, "http://x/", nil)
	req.Header.Set("Cookie", "__gosestor="+key)
	rec := httptest.NewRecorder()
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("X-Session-Rotate", "1")
		w.WriteHeader(http.StatusOK)
		return nil
	})
	if err := h.ServeHTTP(rec, req, next); err != nil {
		t.Fatal(err)
	}

	if got := rec.Result().Header.Get("X-Session-Rotate"); got != "" {
		t.Fatalf("rotation header leaked with feature disabled: %q", got)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == "__gosestor" {
			t.Fatalf("rotation ran despite rotate_header off: new cookie %q", c.Value)
		}
	}
	if r, _ := mgr.Resolve(ctx, key); r == nil {
		t.Fatal("key must survive when rotation is disabled")
	}
}

// TestRotateHeaderInvalidValueNoRotate: an unparseable value must not rotate
// (explicit failure over guessing) and must still be stripped.
func TestRotateHeaderInvalidValueNoRotate(t *testing.T) {
	ctx := context.Background()
	clk := &testClock{t: time.Unix(1_000_000, 0)}
	h, mgr, _ := newRotationTestHandler(clk)

	live, err := mgr.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	key := live.KeyID

	req := httptest.NewRequest(http.MethodGet, "http://x/", nil)
	req.Header.Set("Cookie", "__gosestor="+key)
	rec := httptest.NewRecorder()
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("X-Session-Rotate", "banana")
		w.WriteHeader(http.StatusOK)
		return nil
	})
	if err := h.ServeHTTP(rec, req, next); err != nil {
		t.Fatal(err)
	}

	if got := rec.Result().Header.Get("X-Session-Rotate"); got != "" {
		t.Fatalf("invalid rotation header leaked to client: %q", got)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == "__gosestor" {
			t.Fatalf("rotation ran on invalid value: new cookie %q", c.Value)
		}
	}
	if r, _ := mgr.Resolve(ctx, key); r == nil {
		t.Fatal("key must survive an invalid rotation value")
	}
}

// TestRotateHeaderWithoutSessionMintsNothing: a rotation request with no live
// session is a no-op — we never mint a session just to rotate it (mirrors the
// identity-header guard).
func TestRotateHeaderWithoutSessionMintsNothing(t *testing.T) {
	clk := &testClock{t: time.Unix(1_000_000, 0)}
	h, _, _ := newRotationTestHandler(clk)

	req := httptest.NewRequest(http.MethodGet, "http://x/", nil) // no cookie
	rec := httptest.NewRecorder()
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("X-Session-Rotate", "1")
		w.WriteHeader(http.StatusOK)
		return nil
	})
	if err := h.ServeHTTP(rec, req, next); err != nil {
		t.Fatal(err)
	}

	if got := rec.Result().Header.Get("X-Session-Rotate"); got != "" {
		t.Fatalf("rotation header leaked to client: %q", got)
	}
	if scs := rec.Result().Header["Set-Cookie"]; len(scs) != 0 {
		t.Fatalf("session minted for a bare rotation request: %v", scs)
	}
}

// TestUnmarshalAuthzBlock: the authz block parses into the public config
// verbatim; interpretation (defaults, validation) happens later.
func TestUnmarshalAuthzBlock(t *testing.T) {
	input := `session_store {
		labels_header X-My-Labels
		authz {
			require /auth anonymous
			require /admin adm
			require_default default
			auth_endpoint default /auth/login
			auth_endpoint adm /auth/mfa
			redirect_param next
		}
	}`
	var h Handler
	if err := h.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input)); err != nil {
		t.Fatal(err)
	}
	if h.LabelsHeader != "X-My-Labels" {
		t.Fatalf("LabelsHeader = %q", h.LabelsHeader)
	}
	if h.Authz == nil {
		t.Fatal("authz block not parsed")
	}
	if len(h.Authz.Rules) != 2 || h.Authz.Rules[1] != (AuthzRule{Path: "/admin", Label: "adm"}) {
		t.Fatalf("rules = %+v", h.Authz.Rules)
	}
	if h.Authz.DefaultLabel != "default" || h.Authz.RedirectParam != "next" {
		t.Fatalf("default/param = %q/%q", h.Authz.DefaultLabel, h.Authz.RedirectParam)
	}
	if h.Authz.AuthEndpoints["adm"] != "/auth/mfa" {
		t.Fatalf("endpoints = %v", h.Authz.AuthEndpoints)
	}
}

// TestUnmarshalNoAuthzMeansOff: absent block leaves Authz nil — the feature
// is entirely off and existing configs behave unchanged.
func TestUnmarshalNoAuthzMeansOff(t *testing.T) {
	var h Handler
	if err := h.UnmarshalCaddyfile(caddyfile.NewTestDispenser("session_store {\n}")); err != nil {
		t.Fatal(err)
	}
	if h.Authz != nil {
		t.Fatalf("Authz should be nil when the block is absent, got %+v", h.Authz)
	}
}

// TestValidateLabelsHeaderCollision: the labels header must not collide with
// the identity or rotation headers — a shared name would make one feature
// silently eat another's grants.
func TestValidateLabelsHeaderCollision(t *testing.T) {
	for _, tc := range []struct {
		name string
		mut  func(*Handler)
	}{
		{"identity", func(h *Handler) { h.IdentityHeader = "X-Session-Labels" }},
		{"rotate", func(h *Handler) { h.RotateHeader = "X-Session-Labels" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := &Handler{Redis: RedisConfig{Address: "localhost:6379"}, OnStoreError: "fail_closed"}
			tc.mut(h)
			if err := h.Validate(); err == nil {
				t.Fatal("labels header collision must be rejected")
			}
		})
	}
}

// TestValidateAuthzRedirectLoop: authz config errors surface in Validate —
// most importantly an auth endpoint living under a protected prefix.
func TestValidateAuthzRedirectLoop(t *testing.T) {
	h := &Handler{
		Redis:        RedisConfig{Address: "localhost:6379"},
		OnStoreError: "fail_closed",
		Authz: &AuthzConfig{
			Rules:         []AuthzRule{{Path: "/admin", Label: "adm"}},
			AuthEndpoints: map[string]string{"adm": "/admin/login"},
		},
	}
	if err := h.Validate(); err == nil || !strings.Contains(err.Error(), "redirect loop") {
		t.Fatalf("redirect loop not caught: %v", err)
	}
}

// newAuthzTestHandler layers the reference authz policy over the rotation
// test handler: /auth anonymous, /admin -> adm, everything else -> default.
func newAuthzTestHandler(t *testing.T, clk session.Clock) (*Handler, *session.Manager, *store.Memory) {
	t.Helper()
	h, mgr, st := newRotationTestHandler(clk)
	a, err := authz.New(authz.Config{
		Rules: []authz.Rule{
			{Path: "/auth", Label: authz.Anonymous},
			{Path: "/admin", Label: "adm"},
		},
		DefaultLabel:  "default",
		AuthEndpoints: map[string]string{"default": "/auth/login", "adm": "/auth/mfa"},
	})
	if err != nil {
		t.Fatal(err)
	}
	h.authz = a
	h.labelsHeaderName = "X-Session-Labels"
	return h, mgr, st
}

// okBackend is a next-handler that records whether it was reached.
func okBackend(reached *bool) caddyhttp.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		*reached = true
		w.WriteHeader(http.StatusOK)
		return nil
	}
}

// TestAuthzAnonymousPathNeedsNoSession: an anonymous path proxies with no
// session at all — the login endpoints themselves must be reachable.
func TestAuthzAnonymousPathNeedsNoSession(t *testing.T) {
	clk := &testClock{t: time.Unix(1_000_000, 0)}
	h, _, _ := newAuthzTestHandler(t, clk)
	var reached bool
	req := httptest.NewRequest(http.MethodGet, "http://x/auth/login", nil)
	rec := httptest.NewRecorder()
	if err := h.ServeHTTP(rec, req, okBackend(&reached)); err != nil {
		t.Fatal(err)
	}
	if !reached || rec.Code != http.StatusOK {
		t.Fatalf("anonymous path blocked: reached=%v code=%d", reached, rec.Code)
	}
}

// TestAuthzBrowserRedirect: a browser (Accept: text/html) lacking the label
// gets a 302 to that label's endpoint with the original path+query in rd —
// and the backend is NEVER called for a denied request.
func TestAuthzBrowserRedirect(t *testing.T) {
	clk := &testClock{t: time.Unix(1_000_000, 0)}
	h, _, _ := newAuthzTestHandler(t, clk)
	var reached bool
	req := httptest.NewRequest(http.MethodGet, "http://x/admin/users?tab=1", nil)
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	rec := httptest.NewRecorder()
	if err := h.ServeHTTP(rec, req, okBackend(&reached)); err != nil {
		t.Fatal(err)
	}
	if reached {
		t.Fatal("denied request reached the backend")
	}
	if rec.Code != http.StatusFound {
		t.Fatalf("code = %d, want 302", rec.Code)
	}
	if got, want := rec.Header().Get("Location"), "/auth/mfa?rd=%2Fadmin%2Fusers%3Ftab%3D1"; got != want {
		t.Fatalf("Location = %q, want %q", got, want)
	}
}

// TestAuthzAPIGets401: non-browser clients get a clean 401 plus the endpoint
// in X-Auth-Endpoint so SPAs can redirect client-side.
func TestAuthzAPIGets401(t *testing.T) {
	clk := &testClock{t: time.Unix(1_000_000, 0)}
	h, _, _ := newAuthzTestHandler(t, clk)
	var reached bool
	req := httptest.NewRequest(http.MethodGet, "http://x/admin", nil)
	req.Header.Set("Accept", "application/json")
	rec := httptest.NewRecorder()
	if err := h.ServeHTTP(rec, req, okBackend(&reached)); err != nil {
		t.Fatal(err)
	}
	if reached || rec.Code != http.StatusUnauthorized {
		t.Fatalf("reached=%v code=%d, want unreached 401", reached, rec.Code)
	}
	if got := rec.Header().Get("X-Auth-Endpoint"); got != "/auth/mfa" {
		t.Fatalf("X-Auth-Endpoint = %q", got)
	}
}

// TestAuthzLabeledSessionPasses: a session holding the required label is
// proxied; one lacking it (but holding others) is not.
func TestAuthzLabeledSessionPasses(t *testing.T) {
	ctx := context.Background()
	clk := &testClock{t: time.Unix(1_000_000, 0)}
	h, mgr, _ := newAuthzTestHandler(t, clk)
	live, _ := mgr.Begin(ctx)
	if _, err := live.SetLabels(ctx, []string{"default", "adm"}); err != nil {
		t.Fatal(err)
	}
	key := live.KeyID

	var reached bool
	req := httptest.NewRequest(http.MethodGet, "http://x/admin", nil)
	req.Header.Set("Cookie", "__gosestor="+key)
	rec := httptest.NewRecorder()
	if err := h.ServeHTTP(rec, req, okBackend(&reached)); err != nil {
		t.Fatal(err)
	}
	if !reached {
		t.Fatal("labeled session denied")
	}

	// default-only session must be bounced from /admin to the mfa endpoint.
	live2, _ := mgr.Begin(ctx)
	if _, err := live2.SetLabels(ctx, []string{"default"}); err != nil {
		t.Fatal(err)
	}
	reached = false
	req2 := httptest.NewRequest(http.MethodGet, "http://x/admin", nil)
	req2.Header.Set("Cookie", "__gosestor="+live2.KeyID)
	req2.Header.Set("Accept", "text/html")
	rec2 := httptest.NewRecorder()
	if err := h.ServeHTTP(rec2, req2, okBackend(&reached)); err != nil {
		t.Fatal(err)
	}
	if reached || rec2.Code != http.StatusFound {
		t.Fatalf("under-labeled session passed: reached=%v code=%d", reached, rec2.Code)
	}
}

// errKeyStore makes session resolution fail, simulating a store outage.
type errKeyStore struct{ store.Store }

func (errKeyStore) GetKey(context.Context, string) (string, error) {
	return "", errors.New("store down")
}

// TestAuthzFailsClosedUnderFailOpen: with on_store_error fail_open and the
// store down, anonymous paths still proxy (caching degrades gracefully) but
// protected paths are DENIED — a label that can't be proven doesn't exist.
func TestAuthzFailsClosedUnderFailOpen(t *testing.T) {
	clk := &testClock{t: time.Unix(1_000_000, 0)}
	h, _, st := newAuthzTestHandler(t, clk)
	h.OnStoreError = "fail_open"
	h.store = errKeyStore{Store: st}
	h.manager = session.NewManager(errKeyStore{Store: st}, clk, session.Config{
		Inactive: 30 * time.Minute, Final: 8 * time.Hour, RotateOnLogin: true,
	}, nil)

	var reached bool
	req := httptest.NewRequest(http.MethodGet, "http://x/admin", nil)
	req.Header.Set("Cookie", "__gosestor=somekey")
	req.Header.Set("Accept", "application/json")
	rec := httptest.NewRecorder()
	if err := h.ServeHTTP(rec, req, okBackend(&reached)); err != nil {
		t.Fatal(err)
	}
	if reached || rec.Code != http.StatusUnauthorized {
		t.Fatalf("authz failed OPEN: reached=%v code=%d", reached, rec.Code)
	}

	reached = false
	reqAnon := httptest.NewRequest(http.MethodGet, "http://x/auth/login", nil)
	reqAnon.Header.Set("Cookie", "__gosestor=somekey")
	recAnon := httptest.NewRecorder()
	if err := h.ServeHTTP(recAnon, reqAnon, okBackend(&reached)); err != nil {
		t.Fatal(err)
	}
	if !reached {
		t.Fatal("fail_open must still proxy anonymous paths with the store down")
	}
}

func TestDefaultProxyCookieScopeSurvivesCrossPathLogout(t *testing.T) {
	h := &Handler{Cookie: CookieConfig{Name: "__gosestor", Insecure: true}}
	issued := (&http.Response{Header: http.Header{"Set-Cookie": {h.buildProxyCookie("key")}}}).Cookies()
	if len(issued) != 1 || issued[0].Path != "/" {
		t.Fatalf("default issuance cookie = %+v, want Path=/", issued)
	}
	loginURL, _ := url.Parse("http://example.test/app/login")
	logoutURL, _ := url.Parse("http://example.test/logout")
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	jar.SetCookies(loginURL, issued)
	if got := jar.Cookies(logoutURL); len(got) != 1 || got[0].Name != "__gosestor" || got[0].Value != "key" {
		t.Fatalf("root logout did not receive nested-route cookie: %+v", got)
	}
	expired := (&http.Response{Header: http.Header{"Set-Cookie": {h.buildExpiredProxyCookie()}}}).Cookies()
	if len(expired) != 1 || expired[0].Path != "/" {
		t.Fatalf("default deletion cookie = %+v, want Path=/", expired)
	}
	jar.SetCookies(logoutURL, expired)
	if got := jar.Cookies(loginURL); len(got) != 0 {
		t.Fatalf("deletion from /logout left nested-route cookie: %+v", got)
	}
}

func TestBuildExpiredProxyCookiePreservesScopeAndSecurity(t *testing.T) {
	h := &Handler{Cookie: CookieConfig{
		Name: "__gosestor", Path: "/app", SameSite: "strict", Insecure: false,
	}}
	resp := &http.Response{Header: http.Header{"Set-Cookie": {h.buildExpiredProxyCookie()}}}
	cookies := resp.Cookies()
	if len(cookies) != 1 {
		t.Fatalf("parsed deletion cookies = %+v", cookies)
	}
	got := cookies[0]
	if got.Name != "__gosestor" || got.Value != "" || got.Path != "/app" ||
		got.MaxAge >= 0 || !got.HttpOnly || !got.Secure || got.SameSite != http.SameSiteStrictMode {
		t.Fatalf("unsafe or mismatched deletion cookie: %+v", got)
	}
}

// TestRevokeHeaderDeletesCurrentSessionAndExpiresProxyCookie verifies that a
// backend logout signal wins over all competing response mutations.
func TestRevokeHeaderDeletesCurrentSessionAndExpiresProxyCookie(t *testing.T) {
	ctx := context.Background()
	clk := &testClock{t: time.Unix(1_000_000, 0)}
	h, mgr, st := newRotationTestHandler(clk)
	h.revokeHeaderName = defaultRevokeHeader
	h.revokeEnabled = true
	h.labelsHeaderName = defaultLabelsHeader
	live, err := mgr.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := live.BindOwner(ctx, 7); err != nil {
		t.Fatal(err)
	}
	key := live.KeyID

	req := httptest.NewRequest(http.MethodPost, "http://x/logout", nil)
	req.Header.Set("Cookie", "__gosestor="+key)
	rec := httptest.NewRecorder()
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set(defaultRevokeHeader, "1")
		// Revocation takes precedence over every other response mutation.
		w.Header().Set("X-Auth-User", "8")
		w.Header().Set("X-Session-Rotate", "1")
		w.Header().Set("X-Session-Labels", "adm")
		w.Header().Add("Set-Cookie", "JSESSIONID=recreated; Path=/")
		w.Header().Add("Set-Cookie", "XSRF-TOKEN=must-not-leak; Path=/")
		w.WriteHeader(http.StatusOK)
		return nil
	})
	if err := h.ServeHTTP(rec, req, next); err != nil {
		t.Fatal(err)
	}
	result := rec.Result()
	for _, name := range []string{defaultRevokeHeader, "X-Auth-User", "X-Session-Rotate", "X-Session-Labels"} {
		if got := result.Header.Get(name); got != "" {
			t.Fatalf("managed header %s leaked: %q", name, got)
		}
	}
	var deletion *http.Cookie
	for _, cookie := range result.Cookies() {
		if cookie.Name == "__gosestor" {
			deletion = cookie
		}
		if cookie.Name == "JSESSIONID" || cookie.Name == "XSRF-TOKEN" {
			t.Fatalf("backend cookie leaked during revoke: %+v", cookie)
		}
	}
	if deletion == nil || deletion.Value != "" || deletion.MaxAge >= 0 {
		t.Fatalf("proxy-cookie deletion missing: cookie=%+v headers=%v", deletion, result.Header.Values("Set-Cookie"))
	}
	if got, err := mgr.Resolve(ctx, key); err != nil || got != nil {
		t.Fatalf("revoked key still resolves: live=%+v err=%v", got, err)
	}
	if sids, _ := st.OwnerSessions(ctx, 7); len(sids) != 0 {
		t.Fatalf("owner index survived revoke: %v", sids)
	}
}

func TestRevokeHeaderAnyTruthyFieldValueWins(t *testing.T) {
	for _, values := range [][]string{{"false", "true"}, {"true", "false"}, {"invalid", "1"}} {
		t.Run(strings.Join(values, "_then_"), func(t *testing.T) {
			ctx := context.Background()
			clk := &testClock{t: time.Unix(1_000_000, 0)}
			h, mgr, _ := newRotationTestHandler(clk)
			live, _ := mgr.Begin(ctx)
			key := live.KeyID
			req := httptest.NewRequest(http.MethodPost, "http://x/logout", nil)
			req.Header.Set("Cookie", "__gosestor="+key)
			rec := httptest.NewRecorder()
			next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
				for _, value := range values {
					w.Header().Add(defaultRevokeHeader, value)
				}
				return nil
			})
			if err := h.ServeHTTP(rec, req, next); err != nil {
				t.Fatal(err)
			}
			if got, err := mgr.Resolve(ctx, key); err != nil || got != nil {
				t.Fatalf("truthy revoke field was ignored: live=%+v err=%v", got, err)
			}
		})
	}
}

func TestConcurrentStaleResponseCannotReviveRevokedSession(t *testing.T) {
	ctx := context.Background()
	clk := &testClock{t: time.Unix(1_000_000, 0)}
	h, mgr, st := newRotationTestHandler(clk)
	h.revokeHeaderName = defaultRevokeHeader
	h.revokeEnabled = true
	h.labelsHeaderName = defaultLabelsHeader
	live, _ := mgr.Begin(ctx)
	key := live.KeyID

	bEntered := make(chan struct{})
	releaseB := make(chan struct{})
	bDone := make(chan error, 1)
	bRec := httptest.NewRecorder()
	go func() {
		req := httptest.NewRequest(http.MethodGet, "http://x/concurrent", nil)
		req.Header.Set("Cookie", "__gosestor="+key)
		next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			close(bEntered)
			<-releaseB
			w.Header().Set("Set-Cookie", "JSESSIONID=must-not-revive; Path=/")
			w.WriteHeader(http.StatusOK)
			return nil
		})
		bDone <- h.ServeHTTP(bRec, req, next)
	}()
	<-bEntered // B resolved the live session before A revokes it.

	aReq := httptest.NewRequest(http.MethodPost, "http://x/logout", nil)
	aReq.Header.Set("Cookie", "__gosestor="+key)
	aRec := httptest.NewRecorder()
	aNext := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set(defaultRevokeHeader, "1")
		w.WriteHeader(http.StatusOK)
		return nil
	})
	if err := h.ServeHTTP(aRec, aReq, aNext); err != nil {
		t.Fatal(err)
	}
	close(releaseB)
	if err := <-bDone; err != nil {
		t.Fatal(err)
	}
	if bRec.Code != http.StatusBadGateway {
		t.Fatalf("stale response status = %d, want 502", bRec.Code)
	}
	if _, err := st.GetSession(ctx, live.SessionID); err != store.ErrNotFound {
		t.Fatalf("stale response revived session: %v", err)
	}
	if cookies, _ := st.GetCookies(ctx, live.SessionID); len(cookies) != 0 {
		t.Fatalf("stale response created orphan cookie: %v", cookies)
	}
	if got, err := mgr.Resolve(ctx, key); err != nil || got != nil {
		t.Fatalf("revoked key resolves after stale response: live=%+v err=%v", got, err)
	}
}

func TestRevokeHeaderWithoutLiveSessionDoesNotMint(t *testing.T) {
	for _, tc := range []struct {
		name        string
		proxyCookie string
		wantDelete  bool
	}{
		{name: "anonymous"},
		{name: "stale proxy cookie", proxyCookie: "missing-key", wantDelete: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clk := &testClock{t: time.Unix(1_000_000, 0)}
			h, _, _ := newRotationTestHandler(clk)
			h.revokeHeaderName = defaultRevokeHeader
			h.revokeEnabled = true
			req := httptest.NewRequest(http.MethodPost, "http://x/logout", nil)
			if tc.proxyCookie != "" {
				req.Header.Set("Cookie", "__gosestor="+tc.proxyCookie)
			}
			rec := httptest.NewRecorder()
			next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
				w.Header().Set(defaultRevokeHeader, "true")
				w.Header().Set("X-Auth-User", "99")
				w.Header().Add("Set-Cookie", "JSESSIONID=must-not-mint; Path=/")
				return nil
			})
			if err := h.ServeHTTP(rec, req, next); err != nil {
				t.Fatal(err)
			}
			cookies := rec.Result().Cookies()
			if tc.wantDelete {
				if len(cookies) != 1 || cookies[0].Name != "__gosestor" || cookies[0].MaxAge >= 0 {
					t.Fatalf("stale proxy cookie was not expired: %+v", cookies)
				}
			} else if len(cookies) != 0 {
				t.Fatalf("anonymous revoke minted a cookie: %+v", cookies)
			}
		})
	}
}

func TestRevokeHeaderDisabledFalseOrInvalidOnlyStrips(t *testing.T) {
	for _, tc := range []struct {
		name    string
		enabled bool
		value   string
	}{
		{name: "disabled", enabled: false, value: "1"},
		{name: "false", enabled: true, value: "false"},
		{name: "invalid", enabled: true, value: "logout"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			clk := &testClock{t: time.Unix(1_000_000, 0)}
			h, mgr, _ := newRotationTestHandler(clk)
			h.revokeHeaderName = defaultRevokeHeader
			h.revokeEnabled = tc.enabled
			live, _ := mgr.Begin(ctx)
			key := live.KeyID
			req := httptest.NewRequest(http.MethodPost, "http://x/logout", nil)
			req.Header.Set("Cookie", "__gosestor="+key)
			rec := httptest.NewRecorder()
			next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
				w.Header().Set(defaultRevokeHeader, tc.value)
				return nil
			})
			if err := h.ServeHTTP(rec, req, next); err != nil {
				t.Fatal(err)
			}
			if got := rec.Header().Get(defaultRevokeHeader); got != "" {
				t.Fatalf("revoke header leaked: %q", got)
			}
			if got, err := mgr.Resolve(ctx, key); err != nil || got == nil {
				t.Fatalf("non-triggering revoke changed session: live=%+v err=%v", got, err)
			}
		})
	}
}

// TestLabelsGrantStoresRotatesAndStrips: a grant on an established session
// replaces the set, rotates the proxy cookie (privilege change), and the
// header never reaches the client.
func TestLabelsGrantStoresRotatesAndStrips(t *testing.T) {
	ctx := context.Background()
	clk := &testClock{t: time.Unix(1_000_000, 0)}
	h, mgr, _ := newAuthzTestHandler(t, clk)
	live, _ := mgr.Begin(ctx)
	key := live.KeyID

	req := httptest.NewRequest(http.MethodGet, "http://x/auth/login", nil)
	req.Header.Set("Cookie", "__gosestor="+key)
	rec := httptest.NewRecorder()
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("X-Session-Labels", "default, adm")
		w.WriteHeader(http.StatusOK)
		return nil
	})
	if err := h.ServeHTTP(rec, req, next); err != nil {
		t.Fatal(err)
	}

	if got := rec.Result().Header.Get("X-Session-Labels"); got != "" {
		t.Fatalf("labels header leaked to client: %q", got)
	}
	var newKey string
	for _, c := range rec.Result().Cookies() {
		if c.Name == "__gosestor" {
			newKey = c.Value
		}
	}
	if newKey == "" || newKey == key {
		t.Fatalf("grant must rotate the proxy cookie, got %q", newKey)
	}
	r, _ := mgr.Resolve(ctx, newKey)
	if r == nil || !r.HasLabel("adm") || !r.HasLabel("default") {
		t.Fatalf("labels not stored: %+v", r)
	}
	if old, _ := mgr.Resolve(ctx, key); old != nil {
		t.Fatal("old key survived a grant rotation")
	}
}

// TestLabelsGrantMintsSession: a grant on a session-less response mints a
// session to hold it — the backend said this client is something; that
// statement needs a session to live in.
func TestLabelsGrantMintsSession(t *testing.T) {
	ctx := context.Background()
	clk := &testClock{t: time.Unix(1_000_000, 0)}
	h, mgr, _ := newAuthzTestHandler(t, clk)

	req := httptest.NewRequest(http.MethodGet, "http://x/auth/login", nil) // no cookie
	rec := httptest.NewRecorder()
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("X-Session-Labels", "default")
		w.WriteHeader(http.StatusOK)
		return nil
	})
	if err := h.ServeHTTP(rec, req, next); err != nil {
		t.Fatal(err)
	}
	var key string
	for _, c := range rec.Result().Cookies() {
		if c.Name == "__gosestor" {
			key = c.Value
		}
	}
	if key == "" {
		t.Fatal("no session minted for a label grant")
	}
	if r, _ := mgr.Resolve(ctx, key); r == nil || !r.HasLabel("default") {
		t.Fatalf("minted session lacks granted label: %+v", r)
	}
}

// TestLabelsEmptyGrantWithoutSessionMintsNothing: clearing labels on a
// session-less response is a no-op, not a session — otherwise a backend that
// clears on every response would inflate Redis with empty sessions.
func TestLabelsEmptyGrantWithoutSessionMintsNothing(t *testing.T) {
	clk := &testClock{t: time.Unix(1_000_000, 0)}
	h, _, _ := newAuthzTestHandler(t, clk)

	req := httptest.NewRequest(http.MethodGet, "http://x/auth/login", nil)
	rec := httptest.NewRecorder()
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("X-Session-Labels", "")
		w.WriteHeader(http.StatusOK)
		return nil
	})
	if err := h.ServeHTTP(rec, req, next); err != nil {
		t.Fatal(err)
	}
	if scs := rec.Result().Header["Set-Cookie"]; len(scs) != 0 {
		t.Fatalf("empty grant minted a session: %v", scs)
	}
	if got := rec.Result().Header.Get("X-Session-Labels"); got != "" {
		t.Fatalf("labels header leaked: %q", got)
	}
}

// TestLabelsAnonymousGrantIgnored: "anonymous" is the no-auth sentinel, not a
// privilege — a grant naming it keeps the rest and drops it with a warning.
func TestLabelsAnonymousGrantIgnored(t *testing.T) {
	ctx := context.Background()
	clk := &testClock{t: time.Unix(1_000_000, 0)}
	h, mgr, _ := newAuthzTestHandler(t, clk)
	live, _ := mgr.Begin(ctx)
	key := live.KeyID

	req := httptest.NewRequest(http.MethodGet, "http://x/auth/login", nil)
	req.Header.Set("Cookie", "__gosestor="+key)
	rec := httptest.NewRecorder()
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("X-Session-Labels", "anonymous default")
		w.WriteHeader(http.StatusOK)
		return nil
	})
	if err := h.ServeHTTP(rec, req, next); err != nil {
		t.Fatal(err)
	}
	var newKey string
	for _, c := range rec.Result().Cookies() {
		if c.Name == "__gosestor" {
			newKey = c.Value
		}
	}
	r, _ := mgr.Resolve(ctx, newKey)
	if r == nil || !r.HasLabel("default") || r.HasLabel("anonymous") {
		t.Fatalf("anonymous slipped into the label set: %+v", r)
	}
}

func TestCookieDeletesNow(t *testing.T) {
	now := time.Date(2026, time.July, 21, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name string
		raw  string
		want bool
	}{
		{name: "max age zero", raw: "JSESSIONID=; Max-Age=0", want: true},
		{name: "negative max age", raw: "JSESSIONID=; Max-Age=-1", want: true},
		{name: "past expires", raw: "JSESSIONID=; Expires=Thu, 01 Jan 1970 00:00:00 GMT", want: true},
		{name: "future expires", raw: "JSESSIONID=; Expires=Wed, 21 Jul 2038 00:00:00 GMT", want: false},
		{name: "positive max age overrides past expires", raw: "JSESSIONID=kept; Max-Age=60; Expires=Thu, 01 Jan 1970 00:00:00 GMT", want: false},
		{name: "leading-zero max age overrides past expires", raw: "JSESSIONID=kept; Max-Age=01; Expires=Thu, 01 Jan 1970 00:00:00 GMT", want: false},
		{name: "plus-signed max age is ignored", raw: "JSESSIONID=; Max-Age=+1; Expires=Thu, 01 Jan 1970 00:00:00 GMT", want: true},
		{name: "last valid max age wins set", raw: "JSESSIONID=kept; Max-Age=0; Max-Age=60", want: false},
		{name: "last valid max age wins delete", raw: "JSESSIONID=; Max-Age=60; Max-Age=0", want: true},
		{name: "invalid later max age is ignored", raw: "JSESSIONID=kept; Max-Age=60; Max-Age=+1; Expires=Thu, 01 Jan 1970 00:00:00 GMT", want: false},
		{name: "empty value without expiry", raw: "JSESSIONID=", want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cookie, err := http.ParseSetCookie(tc.raw)
			if err != nil {
				t.Fatal(err)
			}
			if got := cookieDeletesNow(tc.raw, cookie, now); got != tc.want {
				t.Fatalf("cookieDeletesNow(%q) = %v, want %v", tc.raw, got, tc.want)
			}
		})
	}
}

func TestStoredCookieExpiryDeletesAndStopsReinjection(t *testing.T) {
	for _, tc := range []struct {
		name      string
		setCookie string
	}{
		{name: "max age zero", setCookie: "JSESSIONID=; Max-Age=0; Path=/"},
		{name: "past expires", setCookie: "JSESSIONID=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			clk := &testClock{t: time.Unix(1_000_000, 0)}
			h, mgr, st := newRotationTestHandler(clk)
			live, err := mgr.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if err := live.StoreCookie(ctx, "JSESSIONID", "secret"); err != nil {
				t.Fatal(err)
			}
			key := live.KeyID

			req := httptest.NewRequest(http.MethodGet, "http://x/logout", nil)
			req.Header.Set("Cookie", "__gosestor="+key)
			rec := httptest.NewRecorder()
			next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
				if c, err := r.Cookie("JSESSIONID"); err != nil || c.Value != "secret" {
					t.Fatalf("stored cookie not injected before deletion: cookie=%+v err=%v", c, err)
				}
				w.Header().Set("Set-Cookie", tc.setCookie)
				w.WriteHeader(http.StatusOK)
				return nil
			})
			if err := h.ServeHTTP(rec, req, next); err != nil {
				t.Fatal(err)
			}
			resolved, err := mgr.Resolve(ctx, key)
			if err != nil || resolved == nil {
				t.Fatalf("session lost while deleting cookie: live=%+v err=%v", resolved, err)
			}
			if _, ok := resolved.Cookies["JSESSIONID"]; ok {
				t.Fatalf("expired cookie remained cached: %v", resolved.Cookies)
			}
			if shas, err := st.CookieSHAs(ctx, resolved.SessionID); err != nil || shas["JSESSIONID"] != "" {
				t.Fatalf("expired cookie SHA remained: shas=%v err=%v", shas, err)
			}

			req2 := httptest.NewRequest(http.MethodGet, "http://x/after-logout", nil)
			req2.Header.Set("Cookie", "__gosestor="+key)
			rec2 := httptest.NewRecorder()
			next2 := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
				if c, err := r.Cookie("JSESSIONID"); err != http.ErrNoCookie {
					t.Fatalf("deleted cookie reinjected: cookie=%+v err=%v", c, err)
				}
				w.WriteHeader(http.StatusOK)
				return nil
			})
			if err := h.ServeHTTP(rec2, req2, next2); err != nil {
				t.Fatal(err)
			}
		})
	}
}

type revokeFailStore struct{ store.Store }

func (s *revokeFailStore) DeleteSession(context.Context, string) error {
	return errors.New("revoke failed")
}

func TestRevokeAfterFailOpenResolveErrorStillFailsClosed(t *testing.T) {
	clk := &testClock{t: time.Unix(1_000_000, 0)}
	h, _, st := newRotationTestHandler(clk)
	broken := errKeyStore{Store: st}
	h.store = broken
	h.manager = session.NewManager(broken, clk, session.Config{
		Inactive: 30 * time.Minute, Final: 8 * time.Hour, RotateOnLogin: true,
	}, nil)
	h.OnStoreError = "fail_open"

	req := httptest.NewRequest(http.MethodPost, "http://x/logout", nil)
	req.Header.Set("Cookie", "__gosestor=unresolved-key")
	rec := httptest.NewRecorder()
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set(defaultRevokeHeader, "1")
		w.Header().Set(defaultLabelsHeader, "adm")
		w.Header().Add("Set-Cookie", "JSESSIONID=must-not-leak; Path=/")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("logout succeeded"))
		return nil
	})
	if err := h.ServeHTTP(rec, req, next); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusBadGateway || rec.Body.Len() != 0 {
		t.Fatalf("unresolved revoke did not fail closed: code=%d body=%q", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Values("Set-Cookie"); len(got) != 0 {
		t.Fatalf("unresolved revoke leaked cookies: %v", got)
	}
	for _, name := range []string{defaultRevokeHeader, defaultLabelsHeader} {
		if got := rec.Header().Get(name); got != "" {
			t.Fatalf("unresolved revoke leaked %s: %q", name, got)
		}
	}
}

func TestRevokeFailureAlwaysFailsClosedAndScrubs(t *testing.T) {
	for _, mode := range []string{"fail_open", "fail_closed"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			clk := &testClock{t: time.Unix(1_000_000, 0)}
			base := store.NewMemory()
			failing := &revokeFailStore{Store: base}
			mgr := session.NewManager(failing, clk, session.Config{
				Inactive: 30 * time.Minute, Final: 8 * time.Hour, RotateOnLogin: true,
			}, nil)
			h := &Handler{
				Cookie:           CookieConfig{Name: "__gosestor"},
				IdentityHeader:   "X-Auth-User",
				OnStoreError:     mode,
				manager:          mgr,
				store:            failing,
				filter:           filter.New([]string{"XSRF-TOKEN"}, []string{"JSESSIONID"}),
				logger:           zap.NewNop(),
				rotateHeaderName: defaultRotateHeader,
				rotateEnabled:    true,
				revokeHeaderName: defaultRevokeHeader,
				revokeEnabled:    true,
				labelsHeaderName: defaultLabelsHeader,
			}
			live, err := mgr.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			key := live.KeyID
			req := httptest.NewRequest(http.MethodPost, "http://x/logout", nil)
			req.Header.Set("Cookie", "__gosestor="+key)
			rec := httptest.NewRecorder()
			next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
				w.Header().Set(defaultRevokeHeader, "1")
				w.Header().Set("X-Auth-User", "9")
				w.Header().Set(defaultRotateHeader, "1")
				w.Header().Set(defaultLabelsHeader, "adm")
				w.Header().Add("Set-Cookie", "JSESSIONID=secret; Path=/")
				w.Header().Add("Set-Cookie", "XSRF-TOKEN=secret; Path=/")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("upstream body"))
				return nil
			})
			if err := h.ServeHTTP(rec, req, next); err != nil {
				t.Fatal(err)
			}
			result := rec.Result()
			if result.StatusCode != http.StatusBadGateway {
				t.Fatalf("status = %d, want 502", result.StatusCode)
			}
			if rec.Body.Len() != 0 {
				t.Fatalf("upstream body leaked on failed revoke: %q", rec.Body.String())
			}
			if got := result.Header.Values("Set-Cookie"); len(got) != 0 {
				t.Fatalf("Set-Cookie leaked on failed revoke: %v", got)
			}
			for _, name := range []string{defaultRevokeHeader, "X-Auth-User", defaultRotateHeader, defaultLabelsHeader} {
				if got := result.Header.Get(name); got != "" {
					t.Fatalf("managed header %s leaked: %q", name, got)
				}
			}
			if got, err := mgr.Resolve(ctx, key); err != nil || got == nil {
				t.Fatalf("failed revoke unexpectedly destroyed session: live=%+v err=%v", got, err)
			}
		})
	}
}

type contendedRevokeStore struct{ store.Store }

func (s *contendedRevokeStore) Lock(context.Context, string, time.Duration) (func(context.Context) error, bool, error) {
	return nil, false, nil
}

func TestRevokeLockContentionFailsClosedUnderFailOpen(t *testing.T) {
	ctx := context.Background()
	clk := &testClock{t: time.Unix(1_000_000, 0)}
	base := store.NewMemory()
	contended := &contendedRevokeStore{Store: base}
	mgr := session.NewManager(contended, clk, session.Config{
		Inactive: 30 * time.Minute, Final: 8 * time.Hour, Synchronize: true,
	}, nil)
	h := &Handler{
		Cookie:           CookieConfig{Name: "__gosestor"},
		IdentityHeader:   "X-Auth-User",
		OnStoreError:     "fail_open",
		manager:          mgr,
		store:            contended,
		filter:           filter.New(nil, []string{"JSESSIONID"}),
		logger:           zap.NewNop(),
		rotateHeaderName: defaultRotateHeader,
		revokeHeaderName: defaultRevokeHeader,
		revokeEnabled:    true,
		labelsHeaderName: defaultLabelsHeader,
	}
	live, _ := mgr.Begin(ctx)
	key := live.KeyID
	req := httptest.NewRequest(http.MethodPost, "http://x/logout", nil)
	req.Header.Set("Cookie", "__gosestor="+key)
	rec := httptest.NewRecorder()
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set(defaultRevokeHeader, "1")
		w.Header().Add("Set-Cookie", "JSESSIONID=secret; Path=/")
		w.WriteHeader(http.StatusOK)
		return nil
	})
	if err := h.ServeHTTP(rec, req, next); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", rec.Code)
	}
	if got := rec.Header().Get(defaultRevokeHeader); got != "" {
		t.Fatalf("revoke header leaked: %q", got)
	}
	if got := rec.Header().Values("Set-Cookie"); len(got) != 0 {
		t.Fatalf("Set-Cookie leaked: %v", got)
	}
}

type deleteCookieFailStore struct{ store.Store }

func (s *deleteCookieFailStore) ApplySessionControls(ctx context.Context, id string, controls store.SessionControls, ttl, ownerTTL time.Duration) error {
	for _, cookie := range controls.Cookies {
		if cookie.Delete {
			return errors.New("delete cookie failed")
		}
	}
	return s.Store.ApplySessionControls(ctx, id, controls, ttl, ownerTTL)
}

func TestDeleteCookieFailureScrubsResponseHeaders(t *testing.T) {
	for _, mode := range []string{"fail_open", "fail_closed"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			clk := &testClock{t: time.Unix(1_000_000, 0)}
			base := store.NewMemory()
			failing := &deleteCookieFailStore{Store: base}
			mgr := session.NewManager(failing, clk, session.Config{
				Inactive: 30 * time.Minute,
				Final:    8 * time.Hour,
			}, nil)
			h := &Handler{
				Cookie:           CookieConfig{Name: "__gosestor"},
				IdentityHeader:   "X-Auth-User",
				OnStoreError:     mode,
				manager:          mgr,
				store:            failing,
				filter:           filter.New([]string{"XSRF-TOKEN"}, []string{"JSESSIONID"}),
				logger:           zap.NewNop(),
				rotateHeaderName: "X-Session-Rotate",
				labelsHeaderName: "X-Session-Labels",
			}
			live, err := mgr.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if err := live.StoreCookie(ctx, "JSESSIONID", "secret"); err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(http.MethodGet, "http://x/logout", nil)
			req.Header.Set("Cookie", "__gosestor="+live.KeyID)
			rec := httptest.NewRecorder()
			next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
				w.Header().Add("Set-Cookie", "JSESSIONID=; Max-Age=0")
				w.Header().Add("Set-Cookie", "XSRF-TOKEN=forward-secret")
				w.Header().Set("X-Auth-User", "42")
				w.Header().Set("X-Session-Rotate", "1")
				w.Header().Set("X-Session-Labels", "adm")
				w.WriteHeader(http.StatusOK)
				return nil
			})
			if err := h.ServeHTTP(rec, req, next); err != nil {
				t.Fatal(err)
			}
			result := rec.Result()
			wantStatus := http.StatusOK
			if mode == "fail_closed" {
				wantStatus = http.StatusBadGateway
			}
			if result.StatusCode != wantStatus {
				t.Fatalf("status = %d, want %d", result.StatusCode, wantStatus)
			}
			if got := result.Header.Values("Set-Cookie"); len(got) != 0 {
				t.Fatalf("Set-Cookie leaked after delete failure: %v", got)
			}
			for _, name := range []string{"X-Auth-User", "X-Session-Rotate", "X-Session-Labels"} {
				if got := result.Header.Get(name); got != "" {
					t.Fatalf("%s leaked after delete failure: %q", name, got)
				}
			}
			resolved, err := mgr.Resolve(ctx, live.KeyID)
			if err != nil || resolved == nil {
				t.Fatalf("cookie failure stranded old key: live=%+v err=%v", resolved, err)
			}
			if resolved.OwnerID != 0 || len(resolved.Labels) != 0 {
				t.Fatalf("controls applied before cookie failure: owner=%d labels=%v", resolved.OwnerID, resolved.Labels)
			}
		})
	}
}

func TestDuplicateStoredSetCookieHeadersApplyInOrder(t *testing.T) {
	for _, tc := range []struct {
		name    string
		headers []string
		want    string
		present bool
	}{
		{
			name:    "set then delete",
			headers: []string{"JSESSIONID=new; Path=/", "JSESSIONID=; Max-Age=0; Path=/"},
			present: false,
		},
		{
			name:    "delete then set",
			headers: []string{"JSESSIONID=; Max-Age=0; Path=/", "JSESSIONID=new; Path=/"},
			want:    "new",
			present: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			clk := &testClock{t: time.Unix(1_000_000, 0)}
			h, mgr, _ := newRotationTestHandler(clk)
			live, err := mgr.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if err := live.StoreCookie(ctx, "JSESSIONID", "old"); err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(http.MethodGet, "http://x/", nil)
			req.Header.Set("Cookie", "__gosestor="+live.KeyID)
			rec := httptest.NewRecorder()
			next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
				for _, header := range tc.headers {
					w.Header().Add("Set-Cookie", header)
				}
				w.WriteHeader(http.StatusOK)
				return nil
			})
			if err := h.ServeHTTP(rec, req, next); err != nil {
				t.Fatal(err)
			}
			resolved, err := mgr.Resolve(ctx, live.KeyID)
			if err != nil || resolved == nil {
				t.Fatalf("session did not resolve: live=%+v err=%v", resolved, err)
			}
			got, present := resolved.Cookies["JSESSIONID"]
			if present != tc.present || got != tc.want {
				t.Fatalf("final cookie = %q present=%v, want %q present=%v", got, present, tc.want, tc.present)
			}
		})
	}
}

func TestExpiredStoredCookieWithoutSessionMintsNothing(t *testing.T) {
	clk := &testClock{t: time.Unix(1_000_000, 0)}
	h, _, _ := newRotationTestHandler(clk)
	req := httptest.NewRequest(http.MethodGet, "http://x/logout", nil)
	rec := httptest.NewRecorder()
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Set-Cookie", "JSESSIONID=; Max-Age=0; Path=/")
		w.WriteHeader(http.StatusOK)
		return nil
	})
	if err := h.ServeHTTP(rec, req, next); err != nil {
		t.Fatal(err)
	}
	if got := rec.Result().Header.Values("Set-Cookie"); len(got) != 0 {
		t.Fatalf("expiry without a live session minted one: %v", got)
	}
}

func TestEmptyStoredCookieWithoutExpiryIsStored(t *testing.T) {
	ctx := context.Background()
	clk := &testClock{t: time.Unix(1_000_000, 0)}
	h, mgr, _ := newRotationTestHandler(clk)
	req := httptest.NewRequest(http.MethodGet, "http://x/", nil)
	rec := httptest.NewRecorder()
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Set-Cookie", "JSESSIONID=; Path=/")
		w.WriteHeader(http.StatusOK)
		return nil
	})
	if err := h.ServeHTTP(rec, req, next); err != nil {
		t.Fatal(err)
	}
	var key string
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == "__gosestor" {
			key = cookie.Value
		}
	}
	if key == "" {
		t.Fatal("empty non-expiring stored cookie did not mint a session")
	}
	live, err := mgr.Resolve(ctx, key)
	if err != nil || live == nil {
		t.Fatalf("minted session does not resolve: live=%+v err=%v", live, err)
	}
	value, ok := live.Cookies["JSESSIONID"]
	if !ok || value != "" {
		t.Fatalf("empty non-expiring cookie not stored: %v", live.Cookies)
	}
}

func TestMalformedStoredSetCookieIsDroppedWithoutMintingSession(t *testing.T) {
	clk := &testClock{t: time.Unix(1_000_000, 0)}
	h, _, _ := newRotationTestHandler(clk)
	req := httptest.NewRequest(http.MethodGet, "http://x/", nil)
	rec := httptest.NewRecorder()
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Set-Cookie", "JSESSIONID") // invalid: no '='
		w.WriteHeader(http.StatusOK)
		return nil
	})
	if err := h.ServeHTTP(rec, req, next); err != nil {
		t.Fatal(err)
	}
	if got := rec.Result().Header.Values("Set-Cookie"); len(got) != 0 {
		t.Fatalf("malformed stored cookie minted or leaked a session: %v", got)
	}
}

// TestLabelsHeaderAbsentNoChange: a response without the header leaves the
// set untouched and triggers no rotation.
func TestLabelsHeaderAbsentNoChange(t *testing.T) {
	ctx := context.Background()
	clk := &testClock{t: time.Unix(1_000_000, 0)}
	h, mgr, _ := newAuthzTestHandler(t, clk)
	live, _ := mgr.Begin(ctx)
	if _, err := live.SetLabels(ctx, []string{"default"}); err != nil {
		t.Fatal(err)
	}
	key := live.KeyID

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
	for _, c := range rec.Result().Cookies() {
		if c.Name == "__gosestor" {
			t.Fatalf("absent header caused a rotation: %q", c.Value)
		}
	}
	if r, _ := mgr.Resolve(ctx, key); r == nil || !r.HasLabel("default") {
		t.Fatalf("labels changed without a header: %+v", r)
	}
}
