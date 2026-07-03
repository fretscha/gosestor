package gosestor

import (
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
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
