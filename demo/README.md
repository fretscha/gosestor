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
`xcaddy build --with gosestor=.` inside a multi-stage Dockerfile (build context
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

## Notes

- The demo runs over plain HTTP, so the proxy cookie is configured `insecure`
  (otherwise the `Secure` attribute would stop it from being sent back over
  HTTP). **In production, serve over HTTPS and drop `insecure`.**
- `order session_store before reverse_proxy` in the Caddyfile global options is
  required for any custom handler directive.
- Tear down with `docker compose down` (add `-v` to also drop the Redis data).

## Manual poking

```bash
# Login and capture the proxy cookie into a jar.
curl -si -c jar.txt http://localhost:8080/login

# Reuse it; the backend sees JSESSIONID re-injected.
curl -s -b jar.txt http://localhost:8080/
```
