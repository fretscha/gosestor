# gosestor

A Caddy HTTP handler plugin that caches backend session cookies in a
Redis-compatible store and hands the client a single opaque, rotatable proxy
cookie. Backend session cookies remain server-side and are never exposed to
the client.

For the architecture, request lifecycle, Redis layout, and the reasoning behind
the security decisions, see the [code walkthrough](docs/code-walkthrough.md).
Planned and deferred work is tracked in the [backlog](docs/backlog.md).

## Build

    xcaddy build --with github.com/fretscha/gosestor

    # or, from a local clone:
    xcaddy build --with github.com/fretscha/gosestor=.

## Demo

A ready-to-run Docker demo (Caddy+gosestor built via `xcaddy`, Redis, and a stub
backend) lives in [`demo/`](demo/):

    cd demo
    docker compose up --build      # proxy on http://localhost:8080
    ./demo.sh                       # curl walkthrough

It shows cookie swallowing/re-injection, `forward`/drop filtering, and that a
client cannot spoof the identity header or smuggle managed cookies to the
backend. See [`demo/README.md`](demo/README.md).

## Example Caddyfile

    example.com {
        session_store {
            redis {
                address      localhost:6379
                password     {env.REDIS_PASSWORD}
                db           0
                key_prefix   gs:
            }
            cookie {
                name       __gosestor
                same_site  lax
            }
            forward  XSRF-TOKEN
            store    JSESSIONID sessionid csrftoken
            inactive_timeout  30m
            final_timeout     8h
            identity_header   X-Auth-User
            rotate_on_login   true
            rotate_interval   15m
            rotate_header     X-Session-Rotate
            labels_header     X-Session-Labels
            authz {
                require /auth   anonymous
                require /admin  adm
                require_default default
                auth_endpoint default /auth/login
                auth_endpoint adm     /auth/mfa
            }
            synchronize_sessions  false
            on_store_error    fail_closed
        }
        reverse_proxy backend:8080
    }

## Behavior

- `store` cookies are swallowed and kept server-side; `forward` cookies pass to
  the client; everything else is dropped.
- The client only receives an opaque `KEY_ID`; the internal `SESSION_ID` never
  leaves the server. On an authenticated identity change the `KEY_ID` rotates and
  the old key is **hard-deleted immediately** (session-fixation defense; no grace
  window). The proxy `KEY_ID` is also stripped from the upstream request so it
  never reaches the backend, and client-supplied copies of `store`-managed cookie
  names are dropped (the server-held value is authoritative).
- `rotate_on_login` (default `true`) toggles the identity-change rotation above.
  `rotate_interval` adds *periodic* rotation: on the first request after the
  interval elapses since the last rotation, the `KEY_ID` is minted afresh and the
  old one hard-deleted, bounding how long any single opaque key is valid. Rotation
  is lazy (request-driven, no background sweeper); zero disables it. The swap is
  decided on the request path but **executed only on the response path**, after
  the upstream succeeded — a failed request can never invalidate the client's
  cookie without its replacement being delivered in the same response.
- `rotate_on_login` only rotates on an owner-id *transition*. For privilege
  changes under the same owner (MFA step-up, sudo-mode, password change), the
  backend can set `X-Session-Rotate: 1` on any response: gosestor strips the
  header and hard-rotates the proxy cookie, per OWASP's "renew the session id
  on any privilege change". Enabled by default; `rotate_header off` disables
  triggering (the default header name is still stripped), and `rotate_header
  <name>` renames it. Values are parsed with `strconv.ParseBool`; unparseable
  values log a warning and do not rotate.
- With an `authz` block, gosestor enforces path-based authorization: `require`
  rules map path prefixes to labels (longest prefix wins, segment-aware,
  matched on the cleaned path), `require_default` covers unlisted paths, and
  `anonymous` marks public paths. The backend grants labels via
  `labels_header` (default `X-Session-Labels`; presence **replaces** the set,
  empty clears it, absent changes nothing — stripped from every response). A
  label-set change rotates the proxy cookie automatically. Requests lacking
  the required label never reach the backend: browsers get a 302 to that
  label's `auth_endpoint` with the original path in `?rd=`, other clients a
  401 plus `X-Auth-Endpoint`. Validation rejects auth endpoints that live
  under a protected prefix (redirect loop) at config load. With the store
  down, protected paths are denied even under `fail_open` — authz always
  fails closed.
- The backend signals identity via `identity_header` with a **positive integer**
  owner id; `0` is the anonymous sentinel and negative values are ignored.
- `identity_header` is stripped from both the request (anti-spoof) and response.
- `on_store_error fail_closed` returns 502 rather than leaking backend cookies
  when the store is unreachable. On **any** response-path failure (either mode),
  all `Set-Cookie`, the identity header, and the rotation header are scrubbed
  before flushing — so under
  `fail_open` a `forward`-listed cookie (e.g. a CSRF token) emitted during a
  transient store error is dropped rather than leaked.

## Admin API

The plugin registers an extension on Caddy's admin endpoint (localhost `:2019`
by default, already origin/host-checked) for logout-everywhere:

    # Revoke every session bound to owner 42, across all session_store sites:
    curl -X POST http://localhost:2019/gosestor/revoke/42

Returns `204 No Content` on success; owner ids must be positive integers.
Because it hangs off the admin endpoint it inherits Caddy's admin access
control — no separate secret to manage.

> **Warning:** never expose the Caddy admin endpoint on a non-loopback address
> without an additional authentication layer. A remotely reachable admin API
> would let anyone mass-logout users by enumerating small integer owner ids
> (and reconfigure Caddy itself, which is worse).

## Operational notes

- Any response carrying a `store`-listed `Set-Cookie` creates a session, even
  for clients that never present a proxy cookie. Backends should not emit
  managed session cookies on unauthenticated routes, or an attacker who ignores
  the returned cookie can inflate Redis with anonymous sessions; put a rate
  limiter in front of routes that mint sessions.
- Owner index sets (`<prefix>owner:<id>`) carry a TTL that slides on each login
  and are pruned on session delete/revoke, so they cannot grow unboundedly.
