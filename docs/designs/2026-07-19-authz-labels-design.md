# Path-Based Authorization with Labels — Design

Date: 2026-07-19. Status: approved. The design uses enforcement inside the
`session_store` handler.

## Problem

gosestor caches session cookies but enforces nothing: any client can reach any
path, and authorization is entirely the backend's problem. This design makes
the proxy the enforcement point: paths map to required authentication labels,
and requests lacking the required label are sent to an authentication
endpoint. The backend is the authority that grants labels; gosestor is the
gate that enforces them.

Example policy:

- `/auth` → `anonymous` (public — the login endpoints themselves)
- `/admin` → `adm`
- everything else → `default`

## Model

- A **label** is an opaque string (e.g. `default`, `adm`). A session holds a
  set of labels, granted by the backend.
- `anonymous` is a **reserved label**: paths requiring it need no session at
  all. It can never be granted to a session (a grant naming it is ignored with
  a warning — it is the sentinel for "no auth required", not a privilege).
- The **backend is the authority**: it grants labels via a response header
  after verifying whatever it verifies (password, MFA, …). gosestor stores the
  set in the Redis session and enforces it on later requests. This separates
  backend authentication from proxy enforcement.

## Config surface

All inside the existing `session_store` block. **The feature is entirely off
when no `authz` block is present** — existing configs behave unchanged.

```caddyfile
session_store {
    ...
    labels_header X-Session-Labels        # default shown; like identity_header
    authz {
        require /auth   anonymous
        require /admin  adm
        require_default default           # label for unmatched paths; omitted = anonymous
        auth_endpoint default /auth/login
        auth_endpoint adm     /auth/mfa
        redirect_param rd                 # default shown
    }
}
```

JSON shape:

```go
// on Handler:
LabelsHeader string       `json:"labels_header,omitempty"` // "" = default "X-Session-Labels"
Authz        *AuthzConfig `json:"authz,omitempty"`         // nil = feature off

type AuthzConfig struct {
    Rules         []AuthzRule       `json:"rules,omitempty"`
    DefaultLabel  string            `json:"default_label,omitempty"`  // "" = anonymous
    AuthEndpoints map[string]string `json:"auth_endpoints,omitempty"` // label -> path
    RedirectParam string            `json:"redirect_param,omitempty"` // "" = "rd"
}

type AuthzRule struct {
    Path  string `json:"path"`
    Label string `json:"label"`
}
```

`labels_header` is parsed and stripped even without an `authz` block (grants
can be stored before enforcement is turned on), and follows the same naming
pattern as `identity_header`. Its name must differ from both the identity and
rotation headers (Validate).

## Path matching

Longest-prefix match over the `require` rules; a path matching no rule gets
`require_default` (or `anonymous` when omitted, so a partial policy only
protects what it lists). Prefix matching is segment-aware: `/admin` matches
`/admin` and `/admin/users` but NOT `/administrator`. Matching always operates on the
lexically cleaned path (`path.Clean`), so `/admin/../auth` or `//admin`
cannot dodge or spoof a rule regardless of what Caddy passed through.

## Validation (config-load time, in Validate)

1. Every label appearing in `require` or `require_default`, except
   `anonymous`, must have an `auth_endpoint` — otherwise a mismatch would
   have nowhere to send the client.
2. Every `auth_endpoint` path must itself resolve to `anonymous` under the
   rules — otherwise the login page demands the label it grants: a redirect
   loop, caught at load time instead of in production.
3. Rule paths must start with `/`; labels must be non-empty; duplicate rule
   paths are rejected.
4. `labels_header` must differ (case-insensitively) from `identity_header`
   and the effective rotation header.

## Request-path enforcement

New step after session resolution (the handler already has `live` in hand):

1. Compute `required := authz.Required(path)`. If `anonymous` → proceed.
2. If `live != nil` and `required ∈ live.Labels` → proceed.
3. Otherwise deny:
   - If the request's `Accept` header contains `text/html` → `302` to the
     label's auth endpoint with `<redirect_param>=<path?query>` appended.
     The return value is built by gosestor from the request URL — path and
     query only, never scheme/host, never a client-supplied parameter — so it
     cannot become an open redirect.
   - Otherwise (API clients: `Accept: application/json`, `*/*`, …) → `401`
     with header `X-Auth-Endpoint: <endpoint>` so SPAs/htmx can redirect
     client-side. No body beyond Caddy's default.

Fail-safe: when the store is down, a protected path cannot prove its label
and is denied — authz fails closed by construction even under
`on_store_error fail_open` (which continues to apply only to the
session-caching behavior of anonymous paths).

Enforcement happens before the upstream is called; a denied request never
reaches the backend.

## Response-path grants

New step 5c in `processLocked`, alongside the identity (5) and rotation (5b)
headers. The labels header is read and **unconditionally stripped** — enabled
or not, valid or not, including the `ensureProcessed` error scrub.

- Header **present** → its value is split on spaces and/or commas; the result
  **replaces** the session's label set. Replace semantics make downgrade
  (step-down, partial logout) the same operation as upgrade, with no separate
  revoke mechanism.
- Header present but **empty** → clears the label set.
- Header **absent** → no change.
- `anonymous` in a grant is dropped with a warning log; the rest of the grant
  applies.
- A grant on a response with no live session **mints one** (same `ensureLive`
  path as owner binding) — the backend explicitly said this client is
  something; that statement needs a session to live in.

## Session storage & rotation

- `store.Session` gains a `Labels` field, serialized space-joined in the Redis
  session hash. Existing sessions (no field) read as the empty set.
- New `Live.SetLabels(ctx, labels []string) (changed bool, err error)`:
  - Sorts + dedupes; compares against the current set; no-op when equal.
  - On change: persists the session (labels + `LastRotation = now`) FIRST,
    then rotates the KEY_ID via the existing `rotateKey` — hard delete, same
    crash-ordering as every other rotation (a partial failure leaves the
    client's old key valid).
  - Rotation is skipped when `l.rewrite` is already pending (Begin/BindOwner/
    ForceRotate already swapped this response) — labels still persist; only
    the redundant second swap is elided.
  - Rationale for auto-rotation: a label-set change IS the same-owner
    privilege change that `X-Session-Rotate` was built to cover blindly; here
    gosestor can see it, so OWASP's renew-on-privilege-change happens by
    default with zero backend effort. `X-Session-Rotate` remains for triggers
    labels don't capture.

## New package `internal/authz`

Compiled once in `Provision` from `AuthzConfig`:

```go
func New(cfg Config) (*Authz, error)      // validates + compiles rules
func (a *Authz) Required(path string) string   // longest-prefix, default, or "anonymous"
func (a *Authz) Endpoint(label string) string  // auth endpoint for a label
```

Pure logic, no store or HTTP dependency — unit-testable in isolation.
`session_store.go` only calls `Required`/`Endpoint` and implements the
302/401 mechanics.

## Interactions with existing behavior

- Identity binding, label grants, and rotation requests can arrive on the
  same response; processing order is 5 (owner) → 5b (rotate header) → 5c
  (labels) → 6 (cookie filtering) → 6b (rotation execution). At most ONE key
  swap happens per response regardless of how many triggers fire: BindOwner
  and SetLabels swap inline behind the `rewrite` guard, and 6b's
  ForceRotate/MaybeRotate skip when a swap is already pending.
- Labels are orthogonal to `OWNER_ID`: an anonymous-owner session can carry
  labels if the backend grants them, and binding an owner grants no labels.
- Admin revoke (`/gosestor/revoke/<owner>`) deletes sessions wholesale;
  labels die with the session. No new admin surface.

## Tests (TDD, written first; each elaborated to the user during implementation)

`internal/authz`:
- Longest-prefix wins (`/admin/users` → `adm` when `/` and `/admin` rules exist).
- Segment-aware boundaries (`/administrator` does NOT match `/admin`).
- Unmatched path → `require_default`; no default → `anonymous`.
- Compile errors: duplicate paths, missing `/` prefix, empty label, missing
  auth endpoint for a used label, auth endpoint under a protected prefix
  (redirect loop).

`internal/session` (+ `internal/store`):
- `SetLabels` persists and survives re-Resolve; replace and clear semantics.
- Same-set grant → `changed == false`, no rotation.
- Changed set → rotation: new key resolves with the new labels, old key dead.
- `SetLabels` after `BindOwner` in one response → labels persist, exactly one
  key swap.
- Legacy session without a labels field reads as empty set.

Handler:
- Browser request lacking a label → 302 to the right endpoint with correct
  `rd=` (path+query).
- API request (`Accept: application/json`) → 401 + `X-Auth-Endpoint`.
- `anonymous` path → passes with no session; protected path with valid label
  → proxied.
- Labels header stripped in all cases incl. the store-error scrub.
- Grant on a session-less response mints a session carrying the labels.
- Store down + protected path → denied (fail-closed) even with `fail_open`.
- Validate: header-name collisions, missing endpoint, redirect loop.

caddytest end-to-end:
- Full journey: `/admin` denied anonymously (302) → login grants `default
  adm` (proxy cookie rotates) → `/admin` proxied → step-down grant (`default`
  only) → `/admin` denied again.
- `/auth/login` reachable with no session.

## Docs

README (`authz` block, behavior section, label model), code-walkthrough
(enforcement step + grants + auto-rotation), backlog entry moved to shipped,
demo extension deferred to the backlog.

## Out of scope (YAGNI)

- Label hierarchies/ordering (a set is enough; `adm` implies nothing about
  `default` — grant both).
- Per-method or per-host rules; regex/glob matching.
- Configurable API-client detection (the `Accept: text/html` heuristic is
  documented; revisit only on real-world evidence it misfires).
- Remembering `rd` across the auth flow (the auth endpoint receives it and
  owns echoing it back).
