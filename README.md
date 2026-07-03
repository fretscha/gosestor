# gosestor

A Caddy HTTP handler plugin that caches backend session cookies in a
Redis-compatible store and hands the client a single opaque, rotatable proxy
cookie. Backend session cookies remain server-side and are never exposed to
the client.

## Build

    xcaddy build --with gosestor=.

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
- `identity_header` is stripped from both the request (anti-spoof) and response.
- `on_store_error fail_closed` returns 502 rather than leaking backend cookies
  when the store is unreachable. On **any** response-path failure (either mode),
  all `Set-Cookie` and the identity header are scrubbed before flushing — so under
  `fail_open` a `forward`-listed cookie (e.g. a CSRF token) emitted during a
  transient store error is dropped rather than leaked.
