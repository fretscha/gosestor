# Demo: Authz Walkthrough — Design

Date: 2026-07-19. Status: approved. Implements the "Demo: authz
walkthrough" backlog item, demonstrating the feature shipped per
[the authz design spec](2026-07-19-authz-labels-design.md).

## Goal

Extend the Docker demo so `demo.sh` shows path-based authorization live:
deny → login → step-up → step-down, against the real Caddy+Redis stack.

## Approach

Additive policy without `require_default` (approach A): the two new protected
paths are listed explicitly and everything else stays anonymous, so the
existing steps 1–7 — several of which depend on `/` being reachable without a
session (step 2's echo, step 5's anonymous spoof) — keep working byte-for-byte.
The README's `require_default` variant stays documentation-only; the demo's
job is one concept per step.

## Changes

### `demo/Caddyfile`

Add inside the `session_store` block (after `rotate_interval`):

```caddyfile
# Path-based authorization: /account needs the default label, /admin needs
# adm. No require_default — every other path stays anonymous so the earlier
# demo steps keep working. The auth endpoints are anonymous by construction
# (unlisted), which the redirect-loop validation requires.
authz {
    require /account default
    require /admin   adm
    auth_endpoint default /login
    auth_endpoint adm     /mfa
}
```

`labels_header` stays at its default (`X-Session-Labels`).

### `demo/backend/main.go`

- `/login` additionally sets `X-Session-Labels: default` — one response now
  binds the owner AND grants a label, exercising the one-swap-per-response
  guard live.
- New `/mfa`: sets `X-Session-Labels: default adm` (step-up).
- New `/stepdown`: sets `X-Session-Labels: default` (revoke adm only).
- New `/account`: prints "account area — default label was accepted".
- New `/admin`: prints "admin area — adm label was accepted".

### `demo/demo.sh` — steps 8–11 (appended after step 7's revoke, where the
jar's session is conveniently dead)

- **8) AUTHZ DENY:** anonymous `/admin` with `Accept: text/html` → assert
  HTTP 302 and `Location: /mfa?rd=%2Fadmin`; with `Accept: application/json`
  → assert HTTP 401 and `X-Auth-Endpoint: /mfa`. Shows the browser/API split
  and that deep-linking picks the *adm* endpoint, not the login one.
- **9) LOGIN → DEFAULT TIER:** fresh jar; `/login` (grants `default`, binds
  owner). Assert `/account` → 200 with the account marker text, and `/admin`
  → 302 (logged in ≠ every label).
- **10) STEP-UP:** capture the proxy cookie, GET `/mfa`, assert the jar's
  cookie CHANGED (auto-rotation on privilege change), assert `/admin` → 200
  with the admin marker text. Also assert the labels header never appeared in
  any response (`grep -i x-session-labels` must find nothing).
- **11) STEP-DOWN:** GET `/stepdown`, assert the cookie changed again,
  `/admin` → 302 once more, `/account` still 200.

Assertions follow the existing style: `fail()` on mismatch, `proxy_cookie()`
for jar reads, `curl -si` + grep for headers.

### Docs

- `demo/README.md`: document steps 8–11 and a two-sentence label model
  (backend grants via `X-Session-Labels`, proxy enforces per path, label
  change rotates the cookie).
- `docs/backlog.md`: remove the "Demo: authz walkthrough" item; note it
  shipped ("(empty — see deferred items below)" returns to Next up).

## Verification

Rebuild and live-test: `docker compose up --build -d` in `demo/`, run
`./demo.sh`, expect all 11 steps to pass; `docker compose down` after. If the
Docker daemon is not running, stop and ask the user to start it. Unit/CI
verification is unchanged (`go test -race`, gofmt, vet — the backend stub is
its own module and must still build).

## Out of scope

- Demonstrating `require_default` (documented in the README, contradicts
  steps 1–7's anonymous access).
- Demonstrating the redirect-loop validation or invalid label values (unit
  and integration tests cover them; the demo shows happy paths plus deny).
