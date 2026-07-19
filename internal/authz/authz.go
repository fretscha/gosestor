// Package authz maps request paths to required session labels and knows where
// to send clients that lack them. Pure logic: no store or HTTP dependency.
package authz

import (
	"fmt"
	"maps"
	"path"
	"sort"
	"strings"
)

// Anonymous is the reserved label meaning "no session required". It can be
// required by a rule but never granted to a session.
const Anonymous = "anonymous"

// Rule maps a path prefix to a required label.
type Rule struct{ Path, Label string }

// Config is the raw user configuration; New validates and compiles it.
type Config struct {
	Rules         []Rule
	DefaultLabel  string            // "" = Anonymous: unlisted paths are public
	AuthEndpoints map[string]string // label -> absolute path of its auth endpoint
	RedirectParam string            // "" = "rd"
}

// Authz is a compiled, validated policy.
type Authz struct {
	rules         []Rule // cleaned paths, sorted longest-first
	defaultLabel  string
	endpoints     map[string]string
	redirectParam string
}

func New(cfg Config) (*Authz, error) {
	a := &Authz{
		defaultLabel:  cfg.DefaultLabel,
		endpoints:     map[string]string{},
		redirectParam: cfg.RedirectParam,
	}
	if a.defaultLabel == "" {
		a.defaultLabel = Anonymous
	}
	if a.redirectParam == "" {
		a.redirectParam = "rd"
	}
	maps.Copy(a.endpoints, cfg.AuthEndpoints)

	seen := map[string]bool{}
	for _, r := range cfg.Rules {
		if !strings.HasPrefix(r.Path, "/") {
			return nil, fmt.Errorf("authz: rule path %q must start with /", r.Path)
		}
		if r.Label == "" {
			return nil, fmt.Errorf("authz: rule for %q has an empty label", r.Path)
		}
		p := path.Clean(r.Path)
		if seen[p] {
			return nil, fmt.Errorf("authz: duplicate rule path %q", p)
		}
		seen[p] = true
		a.rules = append(a.rules, Rule{Path: p, Label: r.Label})
	}
	// Longest path first: the most specific rule wins without order dependence.
	sort.Slice(a.rules, func(i, j int) bool { return len(a.rules[i].Path) > len(a.rules[j].Path) })

	// Every enforced label needs somewhere to send a failing client.
	used := map[string]bool{a.defaultLabel: true}
	for _, r := range a.rules {
		used[r.Label] = true
	}
	for label := range used {
		if label == Anonymous {
			continue
		}
		if a.endpoints[label] == "" {
			return nil, fmt.Errorf("authz: label %q has no auth_endpoint", label)
		}
	}
	// An auth endpoint that itself requires a label would bounce clients
	// forever; catch the loop at config load, not in production.
	for label, ep := range a.endpoints {
		if !strings.HasPrefix(ep, "/") {
			return nil, fmt.Errorf("authz: auth_endpoint for %q must be an absolute path, got %q", label, ep)
		}
		epPath := ep
		if i := strings.IndexByte(epPath, '?'); i >= 0 {
			epPath = epPath[:i]
		}
		if req := a.Required(epPath); req != Anonymous {
			return nil, fmt.Errorf("authz: auth_endpoint %q for label %q itself requires label %q (redirect loop)", ep, label, req)
		}
	}
	return a, nil
}

// Required returns the label a request path must prove, matching the longest
// rule prefix segment-aware ("/admin" covers "/admin/users" but not
// "/administrator"). Matching operates on the lexically cleaned path so
// traversal or duplicate slashes cannot dodge or spoof a rule.
func (a *Authz) Required(reqPath string) string {
	p := path.Clean("/" + reqPath)
	for _, r := range a.rules {
		if r.Path == "/" || p == r.Path || strings.HasPrefix(p, r.Path+"/") {
			return r.Label
		}
	}
	return a.defaultLabel
}

// Endpoint returns the auth endpoint for a label ("" if none configured).
func (a *Authz) Endpoint(label string) string { return a.endpoints[label] }

// RedirectParam returns the query-parameter name carrying the return URL.
func (a *Authz) RedirectParam() string { return a.redirectParam }
