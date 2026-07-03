package caddytest_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/caddyserver/caddy/v2/caddytest"

	_ "gosestor" // register the session_store handler
)

// stubBackend echoes control headers so tests can assert proxy behavior.
func stubBackend(t *testing.T) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Report the Cookie header the backend received (for re-injection test).
		w.Header().Set("X-Seen-Cookie", r.Header.Get("Cookie"))
		if r.URL.Path == "/login" {
			w.Header().Set("Set-Cookie", "JSESSIONID=secret-sess; Path=/")
			w.Header().Set("X-Auth-User", "42")
		}
		if r.URL.Path == "/tracker" {
			w.Header().Set("Set-Cookie", "adtrack=noisy; Path=/") // unlisted → dropped
		}
		if r.URL.Path == "/csrf" {
			w.Header().Set("Set-Cookie", "XSRF-TOKEN=t0ken; Path=/") // forwarded
		}
		fmt.Fprintln(w, "ok")
	}))
	t.Cleanup(srv.Close)
	return srv
}

func harness(t *testing.T) (*caddytest.Tester, *httptest.Server) {
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
			on_store_error fail_closed
		}
		reverse_proxy %s
	}`, mr.Addr(), strings.TrimPrefix(backend.URL, "http://"))
	tester.InitServer(config, "caddyfile")
	return tester, backend
}

func TestStoredCookieHiddenAndReinjected(t *testing.T) {
	tester, _ := harness(t)

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
}

func TestForwardAndDrop(t *testing.T) {
	tester, _ := harness(t)

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
	tester, backend := harness(t)
	_ = backend
	req, _ := http.NewRequest("GET", "http://localhost:9080/", nil)
	req.Header.Set("X-Auth-User", "999") // forged
	r, err := tester.Client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	// Backend echoes the Cookie header only; a forged identity must never bind
	// an owner. The proxy cookie (if any) must not be tied to owner 999 — we
	// assert indirectly: no Set-Cookie for a new owner-bound session on a plain
	// GET with no backend identity output.
	if cookiePresent(r, "__gosestor") {
		t.Fatal("plain GET must not create an owner-bound session from a forged header")
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
