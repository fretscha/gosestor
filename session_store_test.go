package gosestor

import (
	"net/http"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"

	"gosestor/internal/filter"
)

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
		rotate_grace 60s
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
