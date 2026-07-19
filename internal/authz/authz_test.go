package authz

import (
	"strings"
	"testing"
)

func mustNew(t *testing.T, cfg Config) *Authz {
	t.Helper()
	a, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func policy(t *testing.T) *Authz {
	return mustNew(t, Config{
		Rules: []Rule{
			{Path: "/auth", Label: Anonymous},
			{Path: "/admin", Label: "adm"},
			{Path: "/admin/public", Label: Anonymous},
		},
		DefaultLabel: "default",
		AuthEndpoints: map[string]string{
			"default": "/auth/login",
			"adm":     "/auth/mfa",
		},
	})
}

// TestRequiredLongestPrefixWins: the most specific rule decides, regardless
// of declaration order — /admin/public is anonymous inside the adm-protected
// /admin subtree.
func TestRequiredLongestPrefixWins(t *testing.T) {
	a := policy(t)
	cases := map[string]string{
		"/admin":             "adm",
		"/admin/users":       "adm",
		"/admin/public":      Anonymous,
		"/admin/public/logo": Anonymous,
		"/auth/login":        Anonymous,
		"/":                  "default",
		"/anything/else":     "default",
	}
	for path, want := range cases {
		if got := a.Required(path); got != want {
			t.Errorf("Required(%q) = %q, want %q", path, got, want)
		}
	}
}

// TestRequiredSegmentBoundary: prefix matching is segment-aware — a rule for
// /admin must not leak onto /administrator.
func TestRequiredSegmentBoundary(t *testing.T) {
	a := policy(t)
	if got := a.Required("/administrator"); got != "default" {
		t.Fatalf("Required(/administrator) = %q, want default (segment boundary)", got)
	}
}

// TestRequiredCleansPath: traversal and duplicate slashes must be resolved
// BEFORE matching, so /admin/../auth can't demand the wrong label and
// //admin can't dodge the adm rule.
func TestRequiredCleansPath(t *testing.T) {
	a := policy(t)
	if got := a.Required("/admin/../auth/login"); got != Anonymous {
		t.Fatalf("cleaned traversal = %q, want anonymous", got)
	}
	if got := a.Required("//admin"); got != "adm" {
		t.Fatalf("duplicate-slash path = %q, want adm", got)
	}
}

// TestRequiredDefaults: no matching rule falls to DefaultLabel; an absent
// DefaultLabel means anonymous — a partial policy only protects what it lists.
func TestRequiredDefaults(t *testing.T) {
	a := mustNew(t, Config{
		Rules:         []Rule{{Path: "/admin", Label: "adm"}},
		AuthEndpoints: map[string]string{"adm": "/login"},
	})
	if got := a.Required("/open"); got != Anonymous {
		t.Fatalf("no default configured: Required(/open) = %q, want anonymous", got)
	}
}

// TestRedirectParamDefault: unset RedirectParam falls back to "rd".
func TestRedirectParamDefault(t *testing.T) {
	a := policy(t)
	if a.RedirectParam() != "rd" {
		t.Fatalf("RedirectParam = %q, want rd", a.RedirectParam())
	}
	if a.Endpoint("adm") != "/auth/mfa" {
		t.Fatalf("Endpoint(adm) = %q", a.Endpoint("adm"))
	}
}

// TestNewRejectsBadConfigs: every config error is caught at load time, most
// importantly the redirect loop (an auth endpoint that itself requires the
// label it grants would bounce browsers forever).
func TestNewRejectsBadConfigs(t *testing.T) {
	cases := []struct {
		name    string
		cfg     Config
		wantErr string
	}{
		{
			"missing endpoint for used label",
			Config{Rules: []Rule{{Path: "/admin", Label: "adm"}}},
			"no auth_endpoint",
		},
		{
			"missing endpoint for default label",
			Config{DefaultLabel: "default"},
			"no auth_endpoint",
		},
		{
			"redirect loop",
			Config{
				Rules:         []Rule{{Path: "/admin", Label: "adm"}},
				AuthEndpoints: map[string]string{"adm": "/admin/login"},
			},
			"redirect loop",
		},
		{
			"duplicate rule path",
			Config{
				Rules: []Rule{{Path: "/a", Label: Anonymous}, {Path: "/a/", Label: Anonymous}},
			},
			"duplicate",
		},
		{
			"relative rule path",
			Config{Rules: []Rule{{Path: "admin", Label: Anonymous}}},
			"must start with /",
		},
		{
			"empty label",
			Config{Rules: []Rule{{Path: "/a", Label: ""}}},
			"empty label",
		},
		{
			"relative endpoint",
			Config{
				Rules:         []Rule{{Path: "/admin", Label: "adm"}},
				AuthEndpoints: map[string]string{"adm": "login"},
			},
			"absolute path",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(tc.cfg)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want containing %q", err, tc.wantErr)
			}
		})
	}
}
