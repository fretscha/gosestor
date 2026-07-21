# gosestor Docker demo

A self-contained stack that shows the `session_store` plugin caching backend
session cookies server-side and handing the client only an opaque proxy cookie.

## Stack

| Service   | Role                                                                 |
|-----------|----------------------------------------------------------------------|
| `redis`   | Session store (`redis:7-alpine`).                                    |
| `backend` | Tiny stub origin (`demo/backend`) that sets cookies + identity header. |
| `proxy`   | Caddy built from local source with gosestor, via `xcaddy`.           |

The `proxy` image is built by compiling this repository's module into Caddy with
`xcaddy build --with github.com/fretscha/gosestor=.` inside a multi-stage Dockerfile (build context
is the repo root), so it always reflects your working tree.

## Run

```bash
cd demo
docker compose up --build
```

The proxy listens on <http://localhost:8080>. In another terminal:

```bash
./demo.sh
```

## What the walkthrough demonstrates

1. **Login** (`/login`) — the backend sets `JSESSIONID` (a `store` cookie) and
   `X-Auth-User: 42`. The response to the client contains **neither**: only the
   opaque `__gosestor` proxy cookie. The session cookie is held in Redis; the
   identity header is stripped after binding the owner.
2. **Authenticated request** (`/`) — replaying the proxy cookie makes the
   backend report `JSESSIONID PRESENT`: gosestor re-injected the cached cookie
   upstream, even though the client never possessed it.
3. **Forwarded cookie** (`/csrf`) — `XSRF-TOKEN` is on the `forward` list, so it
   reaches the client unchanged.
4. **Dropped cookie** (`/tracker`) — `adtrack` is unlisted, so deny-by-default
   drops it entirely.
5. **Spoof attempt** — a client that forges `X-Auth-User` and `JSESSIONID` gains
   nothing: the identity header is stripped before the backend sees it, and the
   forged `JSESSIONID` is removed from the upstream request (the server-held
   value is authoritative).
6. **Key rotation** — the demo sets `rotate_interval 15s`; after waiting past
   the interval, the next response carries a **new** `__gosestor` value while
   the session survives, and the pre-rotation key is hard-deleted (replaying it
   is an anonymous request). Rotation executes on the response path, so the old
   key is only destroyed when its replacement is delivered.
7. **Logout everywhere** — `POST http://localhost:2019/gosestor/revoke/42`
   (Caddy admin API) kills every session bound to owner 42; the previously
   authenticated jar goes anonymous. `revoke/0` is rejected with 400 (owner ids
   must be positive; 0 is the anonymous sentinel).
8. **Authorization deny** (`/admin`) — the `authz` block requires the `adm`
   label for `/admin` and `default` for `/account`. Without a session, a
   browser (`Accept: text/html`) is 302-redirected to `/mfa?rd=%2Fadmin` —
   the *adm* endpoint, so deep links land on the right login — while an API
   client gets a plain 401 with an `X-Auth-Endpoint` hint. Denied requests
   never reach the backend.
9. **Default tier** — `/login` now also grants the `default` label via
   `X-Session-Labels` (stripped, stored in the session). `/account` opens;
   `/admin` still redirects — being logged in is not the same as holding
   every label.
10. **Step-up** — `/mfa` grants `default adm`. A label change is a privilege
    change, so the proxy cookie rotates automatically; `/admin` then opens
    with the new cookie.
11. **Step-down** — `/stepdown` grants only `default`: `adm` is revoked by
    the same REPLACE mechanism that granted it, the cookie rotates again,
    and `/admin` closes while `/account` stays open.
12. **Current-session logout** — `/logout` expires the backend session cookie
    and returns `X-Session-Revoke: 1`. gosestor strips both, deletes the complete
    proxy session and owner-index membership, expires `__gosestor`, and rejects
    a replay of its former value.

## Notes

- The demo runs over plain HTTP, so the proxy cookie is configured `insecure`
  (otherwise the `Secure` attribute would stop it from being sent back over
  HTTP). **In production, serve over HTTPS and drop `insecure`.**
- The Caddy admin API is published on the **host's loopback only**
  (`127.0.0.1:2019`) for the revoke demo. Never expose the admin endpoint to
  other machines — it can mass-logout users and reconfigure Caddy itself.
- `rotate_interval 15s` is demo-short so you can watch a rotation live; use
  minutes-to-hours in production.
- `order session_store before reverse_proxy` in the Caddyfile global options is
  required for any custom handler directive.
- Labels are granted by the backend (`X-Session-Labels`, stripped from every
  response) and enforced by the proxy per path prefix; a label-set change
  rotates the proxy cookie automatically. The demo lists only `/account` and
  `/admin` — production configs usually add `require_default` to protect
  everything else too (see the top-level README).
- Tear down with `docker compose down` (add `-v` to also drop the Redis data).

## Manual poking

```bash
# Login and capture the proxy cookie into a jar.
curl -si -c jar.txt http://localhost:8080/login

# Reuse it; the backend sees JSESSIONID re-injected.
curl -s -b jar.txt http://localhost:8080/

# Revoke only this proxy session; the jar receives an expired __gosestor.
curl -si -X POST -b jar.txt -c jar.txt http://localhost:8080/logout
```
