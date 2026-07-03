# gosestor

A Caddy HTTP handler plugin that caches backend session cookies in a
Redis-compatible store and hands the client a single opaque, rotatable proxy
cookie. Backend session cookies remain server-side and are never exposed to
the client.

## Build

    xcaddy build --with gosestor=.

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
            rotate_grace      60s
            synchronize_sessions  false
            on_store_error    fail_closed
        }
        reverse_proxy backend:8080
    }

## Behavior

- `store` cookies are swallowed and kept server-side; `forward` cookies pass to
  the client; everything else is dropped.
- The client only receives an opaque `KEY_ID`; the internal `SESSION_ID` never
  leaves the server. The `KEY_ID` rotates on authenticated identity changes.
- `identity_header` is stripped from both the request (anti-spoof) and response.
- `on_store_error fail_closed` returns 502 rather than leaking backend cookies
  when the store is unreachable.
