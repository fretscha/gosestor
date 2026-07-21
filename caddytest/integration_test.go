package caddytest_test

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/caddyserver/caddy/v2/caddytest"

	_ "github.com/fretscha/gosestor" // register the session_store handler
)

// stubBackend echoes control headers so tests can assert proxy behavior.
func stubBackend(t *testing.T) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/upgrade" {
			hj, ok := w.(http.Hijacker)
			if !ok {
				t.Error("backend writer is not hijackable")
				return
			}
			conn, rw, err := hj.Hijack()
			if err != nil {
				t.Errorf("backend hijack: %v", err)
				return
			}
			defer conn.Close()
			_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: gosestor-test\r\nSet-Cookie: JSESSIONID=secret; Path=/\r\nX-Session-Revoke: 1\r\n\r\n")
			if err := rw.Flush(); err != nil {
				return
			}
			line, err := rw.ReadString('\n')
			if err == nil {
				_, _ = rw.WriteString("echo:" + line)
				_ = rw.Flush()
			}
			return
		}
		// Report the Cookie header the backend received (for re-injection test).
		w.Header().Set("X-Seen-Cookie", r.Header.Get("Cookie"))
		// Echo the request's identity header into a differently-named response
		// header so the anti-spoof test can verify it was stripped before arrival.
		w.Header().Set("X-Seen-Auth", r.Header.Get("X-Auth-User"))
		if r.URL.Path == "/login" {
			w.Header().Set("Set-Cookie", "JSESSIONID=secret-sess; Path=/")
			w.Header().Set("X-Auth-User", "42")
		}
		if r.URL.Path == "/logout" {
			w.Header().Set("Set-Cookie", "JSESSIONID=; Max-Age=0; Path=/")
		}
		if r.URL.Path == "/session-logout" {
			w.Header().Set("Set-Cookie", "JSESSIONID=; Max-Age=0; Path=/")
			w.Header().Set("X-Session-Revoke", "1")
		}
		if r.URL.Path == "/tracker" {
			w.Header().Set("Set-Cookie", "adtrack=noisy; Path=/") // unlisted → dropped
		}
		if r.URL.Path == "/csrf" {
			w.Header().Set("Set-Cookie", "XSRF-TOKEN=t0ken; Path=/") // forwarded
		}
		if r.URL.Path == "/stepup" {
			w.Header().Set("X-Session-Rotate", "1")
		}
		if r.URL.Path == "/rotate-and-store" {
			w.Header().Set("Set-Cookie", "JSESSIONID=elevated; Path=/")
			w.Header().Set("X-Session-Rotate", "1")
			w.Header().Set("X-Session-Labels", "adm")
		}
		if r.URL.Path == "/auth/login" {
			w.Header().Set("X-Session-Labels", "default")
		}
		if r.URL.Path == "/auth/mfa" {
			w.Header().Set("X-Session-Labels", "default adm")
		}
		if r.URL.Path == "/stepdown" {
			w.Header().Set("X-Session-Labels", "default")
		}
		fmt.Fprintln(w, "ok")
	}))
	t.Cleanup(srv.Close)
	return srv
}

func harness(t *testing.T) (*caddytest.Tester, *httptest.Server, *miniredis.Miniredis) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mr.Close)
	backend := stubBackend(t)

	tester := caddytest.NewTester(t)
	// Caddyfile requires a newline after every '{'; inline one-liner blocks are
	// rejected by the adapter, so redis/cookie blocks are expanded multi-line.
	config := fmt.Sprintf(`{
		admin localhost:2999
		order session_store before reverse_proxy
	}
	http://localhost:9080 {
		session_store {
			redis {
				address %s
			}
			cookie {
				name __gosestor
				insecure
			}
			forward XSRF-TOKEN
			store JSESSIONID
			identity_header X-Auth-User
			revoke_header X-Session-Revoke
			on_store_error fail_closed
		}
		reverse_proxy %s
	}`, mr.Addr(), strings.TrimPrefix(backend.URL, "http://"))
	tester.InitServer(config, "caddyfile")
	return tester, backend, mr
}

func TestStoredCookieHiddenAndReinjected(t *testing.T) {
	tester, _, _ := harness(t)

	// Login: backend sets JSESSIONID (stored) + X-Auth-User (stripped).
	resp, _ := tester.AssertGetResponse("http://localhost:9080/login", 200, "ok\n")
	if got := resp.Header.Get("Set-Cookie"); strings.Contains(got, "JSESSIONID") {
		t.Fatalf("stored cookie leaked to client: %q", got)
	}
	if resp.Header.Get("X-Auth-User") != "" {
		t.Fatal("identity header not stripped from response")
	}
	var proxy *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "__gosestor" {
			proxy = c
		}
	}
	if proxy == nil {
		t.Fatal("no proxy cookie issued")
	}

	// Second request carrying the proxy cookie must re-inject JSESSIONID upstream.
	req, _ := http.NewRequest("GET", "http://localhost:9080/", nil)
	req.AddCookie(proxy)
	r2, err := tester.Client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if seen := r2.Header.Get("X-Seen-Cookie"); !strings.Contains(seen, "JSESSIONID=secret-sess") {
		t.Fatalf("cached cookie not re-injected upstream: %q", seen)
	}

	// Backend expiry removes the server-held cookie while preserving the proxy
	// session. The expiry header itself stays hidden from the client.
	logoutReq, _ := http.NewRequest("GET", "http://localhost:9080/logout", nil)
	logoutReq.AddCookie(proxy)
	logoutResp, err := tester.Client.Do(logoutReq)
	if err != nil {
		t.Fatal(err)
	}
	if seen := logoutResp.Header.Get("X-Seen-Cookie"); !strings.Contains(seen, "JSESSIONID=secret-sess") {
		t.Fatalf("cached cookie not injected into logout request: %q", seen)
	}
	if got := logoutResp.Header.Get("Set-Cookie"); strings.Contains(got, "JSESSIONID") {
		t.Fatalf("stored-cookie expiry leaked to client: %q", got)
	}

	afterReq, _ := http.NewRequest("GET", "http://localhost:9080/", nil)
	afterReq.AddCookie(proxy)
	afterResp, err := tester.Client.Do(afterReq)
	if err != nil {
		t.Fatal(err)
	}
	if seen := afterResp.Header.Get("X-Seen-Cookie"); strings.Contains(seen, "JSESSIONID") {
		t.Fatalf("expired stored cookie was re-injected: %q", seen)
	}
}

func TestCurrentSessionLogoutRevokesProxySession(t *testing.T) {
	tester, _, mr := harness(t)
	login, _ := tester.AssertGetResponse("http://localhost:9080/login", 200, "ok\n")
	var proxy *http.Cookie
	for _, cookie := range login.Cookies() {
		if cookie.Name == "__gosestor" {
			proxy = cookie
		}
	}
	if proxy == nil {
		t.Fatal("login did not issue proxy cookie")
	}

	req, _ := http.NewRequest(http.MethodPost, "http://localhost:9080/session-logout", nil)
	req.AddCookie(proxy)
	resp, err := tester.Client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("logout status = %d", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Session-Revoke"); got != "" {
		t.Fatalf("revoke signal leaked: %q", got)
	}
	var expired bool
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "__gosestor" && cookie.MaxAge < 0 {
			expired = true
		}
		if cookie.Name == "JSESSIONID" {
			t.Fatalf("backend session cookie leaked: %+v", cookie)
		}
	}
	if !expired {
		t.Fatal("logout did not expire proxy cookie")
	}
	if mr.Exists("gs:key:" + proxy.Value) {
		t.Fatal("old proxy key survived current-session logout")
	}
	if mr.Exists("gs:owner:42") {
		t.Fatal("owner index survived current-session logout")
	}

	after, _ := http.NewRequest(http.MethodGet, "http://localhost:9080/", nil)
	after.AddCookie(proxy)
	afterResp, err := tester.Client.Do(after)
	if err != nil {
		t.Fatal(err)
	}
	if seen := afterResp.Header.Get("X-Seen-Cookie"); strings.Contains(seen, "JSESSIONID") {
		t.Fatalf("revoked session cookie was re-injected: %q", seen)
	}
}

func TestForwardAndDrop(t *testing.T) {
	tester, _, _ := harness(t)

	fwd, _ := tester.AssertGetResponse("http://localhost:9080/csrf", 200, "ok\n")
	if !cookiePresent(fwd, "XSRF-TOKEN") {
		t.Fatal("forward cookie did not reach the client")
	}

	drop, _ := tester.AssertGetResponse("http://localhost:9080/tracker", 200, "ok\n")
	if cookiePresent(drop, "adtrack") {
		t.Fatal("unlisted cookie should have been dropped")
	}
}

func TestClientSuppliedIdentityHeaderStripped(t *testing.T) {
	tester, _, _ := harness(t)
	req, _ := http.NewRequest("GET", "http://localhost:9080/", nil)
	req.Header.Set("X-Auth-User", "999") // forged
	r, err := tester.Client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	// The backend echoes whatever X-Auth-User it received into X-Seen-Auth.
	// If gosestor stripped the forged header before proxying, the backend never
	// saw it and X-Seen-Auth must be empty.
	if got := r.Header.Get("X-Seen-Auth"); got != "" {
		t.Fatalf("forged X-Auth-User reached the backend: X-Seen-Auth=%q", got)
	}
}

func TestFailClosedStoreDownReturns502(t *testing.T) {
	tester, _, mr := harness(t)

	// Warm up: ensure Caddy is fully ready by completing one successful request.
	tester.AssertGetResponse("http://localhost:9080/", 200, "ok\n")

	// Bring Redis down so the next store operation fails.
	mr.Close()

	// GET /login: backend will emit Set-Cookie: JSESSIONID + X-Auth-User.
	// With Redis down and fail_closed, gosestor must return 502 and must NOT
	// leak the JSESSIONID cookie to the client.
	req, _ := http.NewRequest("GET", "http://localhost:9080/login", nil)
	resp, err := tester.Client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected 502 Bad Gateway, got %d", resp.StatusCode)
	}
	for _, sc := range resp.Header["Set-Cookie"] {
		if strings.Contains(sc, "JSESSIONID") {
			t.Fatalf("JSESSIONID leaked in Set-Cookie with store down: %q", sc)
		}
	}
}

func cookiePresent(resp *http.Response, name string) bool {
	for _, c := range resp.Cookies() {
		if c.Name == name {
			return true
		}
	}
	return false
}

// TestBackendRequestedRotation: end-to-end step-up — the backend asks for a
// rotation, the client transparently receives a new proxy cookie, the old
// key dies, and the cached backend cookie survives under the new key.
func TestBackendRequestedRotation(t *testing.T) {
	tester, _, _ := harness(t)

	resp, _ := tester.AssertGetResponse("http://localhost:9080/login", 200, "ok\n")
	var oldCookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "__gosestor" {
			oldCookie = c
		}
	}
	if oldCookie == nil {
		t.Fatal("no proxy cookie issued at login")
	}

	// Plain client (no cookie jar) so exactly the cookie we attach is sent.
	plain := &http.Client{}

	req, _ := http.NewRequest("GET", "http://localhost:9080/stepup", nil)
	req.AddCookie(oldCookie)
	r2, err := plain.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if got := r2.Header.Get("X-Session-Rotate"); got != "" {
		t.Fatalf("rotation header leaked to client: %q", got)
	}
	var newCookie *http.Cookie
	for _, c := range r2.Cookies() {
		if c.Name == "__gosestor" {
			newCookie = c
		}
	}
	if newCookie == nil || newCookie.Value == oldCookie.Value {
		t.Fatal("step-up did not deliver a fresh proxy cookie")
	}

	// Old key: dead — no re-injection upstream. New key: still re-injects.
	reqOld, _ := http.NewRequest("GET", "http://localhost:9080/", nil)
	reqOld.AddCookie(oldCookie)
	rOld, err := plain.Do(reqOld)
	if err != nil {
		t.Fatal(err)
	}
	if seen := rOld.Header.Get("X-Seen-Cookie"); strings.Contains(seen, "JSESSIONID") {
		t.Fatalf("old key still re-injects after rotation: %q", seen)
	}
	reqNew, _ := http.NewRequest("GET", "http://localhost:9080/", nil)
	reqNew.AddCookie(newCookie)
	rNew, err := plain.Do(reqNew)
	if err != nil {
		t.Fatal(err)
	}
	if seen := rNew.Header.Get("X-Seen-Cookie"); !strings.Contains(seen, "JSESSIONID=secret-sess") {
		t.Fatalf("cached cookie lost across rotation: %q", seen)
	}
}

// TestStoreDownScrubsRotationHeader: on a response-path store failure the
// rotation header must be scrubbed alongside Set-Cookie and the identity
// header — fail_closed must never leak backend signaling to the client.
func TestStoreDownScrubsRotationHeader(t *testing.T) {
	tester, _, mr := harness(t)
	tester.AssertGetResponse("http://localhost:9080/", 200, "ok\n") // warm up

	mr.Close() // storing JSESSIONID will now fail on the response path

	req, _ := http.NewRequest("GET", "http://localhost:9080/rotate-and-store", nil)
	resp, err := tester.Client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected 502 with store down, got %d", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Session-Rotate"); got != "" {
		t.Fatalf("rotation header leaked on the error path: %q", got)
	}
	if got := resp.Header.Get("X-Session-Labels"); got != "" {
		t.Fatalf("labels header leaked on the error path: %q", got)
	}
	for _, sc := range resp.Header["Set-Cookie"] {
		if strings.Contains(sc, "JSESSIONID") {
			t.Fatalf("JSESSIONID leaked with store down: %q", sc)
		}
	}
}

// authzHarness is harness() plus the reference authz policy. Note unlisted
// paths now fall under require_default, so this harness is only used by
// authz tests.
func authzHarness(t *testing.T) (*caddytest.Tester, *miniredis.Miniredis) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mr.Close)
	backend := stubBackend(t)

	tester := caddytest.NewTester(t)
	config := fmt.Sprintf(`{
		admin localhost:2999
		order session_store before reverse_proxy
	}
	http://localhost:9080 {
		session_store {
			redis {
				address %s
			}
			cookie {
				name __gosestor
				insecure
			}
			store JSESSIONID
			identity_header X-Auth-User
			revoke_header X-Session-Revoke
			on_store_error fail_closed
			authz {
				require /auth anonymous
				require /admin adm
				require /stepdown default
				require_default default
				auth_endpoint default /auth/login
				auth_endpoint adm /auth/mfa
			}
		}
		reverse_proxy %s
	}`, mr.Addr(), strings.TrimPrefix(backend.URL, "http://"))
	tester.InitServer(config, "caddyfile")
	return tester, mr
}

// TestAuthzEndToEndJourney walks the full lifecycle through a real Caddy:
// denied anonymously → login grants default (mints + cookie) → default areas
// open, /admin still closed → MFA grants adm (cookie ROTATES) → /admin open →
// step-down revokes adm (rotates again) → /admin closed again.
func TestAuthzEndToEndJourney(t *testing.T) {
	_, _ = authzHarness(t)
	plain := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse // inspect 302s instead of following
		},
	}
	get := func(path string, cookie *http.Cookie, accept string) *http.Response {
		t.Helper()
		req, _ := http.NewRequest("GET", "http://localhost:9080"+path, nil)
		req.Header.Set("Accept", accept)
		if cookie != nil {
			req.AddCookie(cookie)
		}
		resp, err := plain.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	proxyCookie := func(resp *http.Response) *http.Cookie {
		for _, c := range resp.Cookies() {
			if c.Name == "__gosestor" {
				return c
			}
		}
		return nil
	}

	// 1. Anonymous browser on /admin → 302 to the adm endpoint with rd.
	r := get("/admin/panel", nil, "text/html")
	if r.StatusCode != http.StatusFound {
		t.Fatalf("step 1: code %d, want 302", r.StatusCode)
	}
	if loc := r.Header.Get("Location"); loc != "/auth/mfa?rd=%2Fadmin%2Fpanel" {
		t.Fatalf("step 1: Location = %q", loc)
	}

	// 2. Anonymous API client → 401 + endpoint hint.
	r = get("/admin/panel", nil, "application/json")
	if r.StatusCode != http.StatusUnauthorized || r.Header.Get("X-Auth-Endpoint") != "/auth/mfa" {
		t.Fatalf("step 2: code %d endpoint %q", r.StatusCode, r.Header.Get("X-Auth-Endpoint"))
	}

	// 3. Login (anonymous path) grants default → session minted.
	r = get("/auth/login", nil, "text/html")
	if r.StatusCode != http.StatusOK {
		t.Fatalf("step 3: code %d", r.StatusCode)
	}
	if got := r.Header.Get("X-Session-Labels"); got != "" {
		t.Fatalf("step 3: labels header leaked: %q", got)
	}
	c1 := proxyCookie(r)
	if c1 == nil {
		t.Fatal("step 3: no session minted on grant")
	}

	// 4. default-labeled session reaches a default path but not /admin.
	if r = get("/anything", c1, "text/html"); r.StatusCode != http.StatusOK {
		t.Fatalf("step 4a: code %d", r.StatusCode)
	}
	if r = get("/admin/panel", c1, "text/html"); r.StatusCode != http.StatusFound {
		t.Fatalf("step 4b: code %d, want 302", r.StatusCode)
	}

	// 5. MFA grants default+adm → privilege change rotates the cookie.
	r = get("/auth/mfa", c1, "text/html")
	if r.StatusCode != http.StatusOK {
		t.Fatalf("step 5: code %d", r.StatusCode)
	}
	c2 := proxyCookie(r)
	if c2 == nil || c2.Value == c1.Value {
		t.Fatal("step 5: label upgrade must rotate the proxy cookie")
	}

	// 6. adm session reaches /admin; the pre-upgrade cookie is dead.
	if r = get("/admin/panel", c2, "text/html"); r.StatusCode != http.StatusOK {
		t.Fatalf("step 6a: code %d", r.StatusCode)
	}
	if r = get("/admin/panel", c1, "text/html"); r.StatusCode != http.StatusFound {
		t.Fatalf("step 6b: pre-upgrade cookie still works (code %d)", r.StatusCode)
	}

	// 7. Step-down back to default → rotates again, /admin closed again.
	r = get("/stepdown", c2, "text/html")
	if r.StatusCode != http.StatusOK {
		t.Fatalf("step 7: code %d", r.StatusCode)
	}
	c3 := proxyCookie(r)
	if c3 == nil || c3.Value == c2.Value {
		t.Fatal("step 7: step-down must rotate")
	}
	if r = get("/admin/panel", c3, "text/html"); r.StatusCode != http.StatusFound {
		t.Fatalf("step 8: adm survived step-down (code %d)", r.StatusCode)
	}
}

func TestUpgradeHandshakeIsCommittedAndManagedHeadersAreScrubbed(t *testing.T) {
	_, _, _ = harness(t)
	conn, err := net.DialTimeout("tcp", "localhost:9080", 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := fmt.Fprint(conn, "GET /upgrade HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: gosestor-test\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	var handshake strings.Builder
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read upgrade handshake: %v", err)
		}
		handshake.WriteString(line)
		if line == "\r\n" {
			break
		}
	}
	raw := handshake.String()
	if !strings.HasPrefix(raw, "HTTP/1.1 101 ") || !strings.Contains(raw, "Upgrade: gosestor-test\r\n") {
		t.Fatalf("invalid upgrade handshake:\n%s", raw)
	}
	for _, forbidden := range []string{"JSESSIONID", "X-Session-Revoke"} {
		if strings.Contains(strings.ToLower(raw), strings.ToLower(forbidden)) {
			t.Fatalf("managed upgrade metadata %q leaked:\n%s", forbidden, raw)
		}
	}
	if _, err := fmt.Fprint(conn, "ping\n"); err != nil {
		t.Fatal(err)
	}
	if line, err := reader.ReadString('\n'); err != nil || line != "echo:ping\n" {
		t.Fatalf("upgraded connection exchange = %q, err=%v", line, err)
	}
}
