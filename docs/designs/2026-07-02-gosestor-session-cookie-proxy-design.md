# gosestor — Session Cookie Caching Proxy for Caddy

**Status:** Approved design
**Date:** 2026-07-02
**Module:** `gosestor` (Caddy HTTP handler plugin, directive `session_store`)

## 1. Overview

`gosestor` is a Caddy HTTP handler plugin (built via `xcaddy`) that sits between
the client and a backend application. It transparently **swallows configured
backend `Set-Cookie` headers**, persists them plus the authenticated owner
identity in a **Redis-compatible session store**, and hands the client a single
opaque, rotatable **proxy cookie**. On subsequent requests it re-hydrates the
backend's real cookies from the store and re-injects them toward the backend.

The persistence model reproduces this logical (Postgres-reference) schema over a
Redis-compatible store:

```sql
CREATE TABLE session (
    SESSION_ID       VARCHAR(255) PRIMARY KEY,
    CREATION_TIME    INTEGER NOT NULL,
    LAST_ACCESS_TIME INTEGER NOT NULL,
    INACTIVE_TIMEOUT INTEGER NOT NULL,
    FINAL_TIMEOUT    INTEGER NOT NULL,
    OWNER_ID         BIGINT  NOT NULL DEFAULT 0
);
CREATE INDEX owner_id ON session (OWNER_ID);

CREATE TABLE key_id_map (
    KEY_ID     VARCHAR(255) PRIMARY KEY,
    SESSION_ID VARCHAR(255) NOT NULL,
    FOREIGN KEY(SESSION_ID) REFERENCES session(SESSION_ID) ON DELETE CASCADE
);
CREATE INDEX session_id_idx_key_id_map ON key_id_map (SESSION_ID);

CREATE TABLE attribute (
    SESSION_ID VARCHAR(255) NOT NULL,
    NAME       VARCHAR(200) NOT NULL,
    VALUE      BYTEA,
    VALUE_SHA  BYTEA,
    FOREIGN KEY(SESSION_ID) REFERENCES session(SESSION_ID) ON DELETE CASCADE,
    CONSTRAINT uc_id_name UNIQUE (SESSION_ID, NAME)
);
```

## 2. Goals & Non-Goals

### Goals (v1)
- Caddy plugin exposing a `session_store` handler directive.
- Name-based cookie filter with **three outcomes, deny-by-default**: explicitly
  named cookies are **forwarded** (→ client) or **stored** (→ server-side); every
  other backend `Set-Cookie` is **dropped** (neither forwarded nor stored).
- Opaque proxy cookie holding a rotatable `KEY_ID`; stable internal `SESSION_ID`.
- KEY_ID rotation on identity change (fixation defense) with a grace window.
- Cached-cookie re-injection toward the backend on the request path.
- Owner binding: `OWNER_ID` = authenticated integer user id, sourced from a backend
  response header, stripped before reaching the client; revoke-by-owner supported.
- Anti-spoofing: the `identity_header` is stripped from the **inbound request** so a
  client can never forge identity — only the backend may assert it.
- Dual timeouts: sliding `INACTIVE_TIMEOUT` + absolute `FINAL_TIMEOUT`.
- Optional session synchronization (`synchronize_sessions`, default off): serialize
  concurrent requests within the same session to avoid cookie collisions.
- Pluggable `SessionStore` interface; Redis-compatible implementation (go-redis).
- `fail_closed` default when the store is unreachable.

### Non-Goals (v1)
- Postgres backend implementation (interface leaves the door open; not shipped).
- General read/write attribute API for other handlers (only cached cookies used).
- gosestor performing authentication itself (backend remains source of truth).
- Admin UI. Revoke-by-owner exists on the API; endpoint wiring is future work.

## 3. Architecture

```
                     ┌──────────────────── gosestor (Caddy handler) ─────────────────────┐
 Client ──request──► │ 1. read proxy cookie (KEY_ID)                                     │
  (browser)          │ 2. KEY_ID ─► key_id_map ─► SESSION_ID ─► load cached cookies      │──► Backend
                     │ 3. re-inject cached cookies as `Cookie:` header toward backend    │   (Django/app)
                     │                                                                   │
 Client ◄─response── │ 6. write/refresh proxy cookie ◄ 5. store swallowed cookies +      │◄── Set-Cookie
                     │    (rotate KEY_ID if triggered)   OWNER_ID; strip identity header ◄─── + X-Auth-User
                     └───────────────────────────────────────────────────────────────────┘
                                        │  ▲
                                        ▼  │
                              ┌───────────────────────┐
                              │  SessionStore (iface)  │
                              │  Redis impl (go-redis) │
                              └───────────────────────┘
```

### Components
1. **`Handler`** (`caddyhttp.MiddlewareHandler`) — the Caddy directive; orchestrates
   request-in / response-out. Holds config + a `SessionStore`. Thin; delegates.
2. **`CookieFilter`** — pure decision logic. Two configured lists only, `forward` and
   `store`; the outcome is `Forward` | `Store` | `Drop`, where `Drop` is the implicit
   default for any cookie in neither list (never configured explicitly). No I/O.
   Table-driven unit tests.
3. **`SessionManager`** — session/key lifecycle: create, resolve KEY_ID→SESSION_ID,
   rotate KEY_ID, set OWNER_ID, enforce timeouts, get/set/delete attributes. Depends
   only on `SessionStore` and an injected `Clock`.
4. **`SessionStore`** (interface) — persistence contract modeling the 3 tables. Redis
   implementation first; in-memory fake for tests; Postgres future.
5. **`ResponseInterceptor`** — wraps `http.ResponseWriter` to capture & rewrite
   `Set-Cookie` before flush (Caddy `responsewriter` pattern).

### Repo layout
```
gosestor/
├── session_store.go        # Caddy Handler + Caddyfile parsing (module registration)
├── internal/
│   ├── filter/             # CookieFilter
│   ├── session/            # SessionManager, Clock
│   └── store/              # SessionStore interface, redis impl, in-memory fake
├── caddytest/              # integration tests
├── docs/
└── go.mod                  # module: gosestor
```

## 4. Data Flow

### Request path (client → backend)
0. **Strip any client-supplied `identity_header`** (e.g. `X-Auth-User`) from the inbound
   request before anything else, so a browser can never forge owner identity. Only the
   backend may assert identity (response path, step 5).
1. Extract proxy cookie (config name, default `__gosestor`). Absent → no session; pass through.
2. Resolve `KEY_ID → SESSION_ID` via key_id_map. Miss/expired → treat as no session
   (optionally clear the client cookie).
3. Touch `LAST_ACCESS_TIME`; enforce inactive + final timeouts.
4. Load stored cookie attributes; merge into the outbound `Cookie:` header toward the
   backend (backend sees its own cookies as if it had set them).

### Response path (backend → client)
5. Read `identity_header` (e.g. `X-Auth-User`); if present, set/refresh `OWNER_ID`,
   `SADD` to the owner index, **strip the header**, and trigger KEY_ID rotation.
6. For each backend `Set-Cookie`: `CookieFilter` returns one of three outcomes —
   **Forward** (named in `forward`: leave it in the response), **Store** (named in
   `store`: write as attribute via `SessionManager`, remove from response), or **Drop**
   (default for any unlisted cookie: remove from response, do not store). `VALUE_SHA`
   skips rewriting unchanged stored values.
7. Ensure the client has a valid proxy cookie (create session + KEY_ID on first store;
   emit rotated KEY_ID if rotation triggered) with `HttpOnly; Secure; SameSite`.

## 5. Redis Data Model

Keys namespaced by a configurable prefix (default `gs:`). Times are Unix seconds.
`SESSION_ID` and `KEY_ID` are independent 256-bit `crypto/rand` values (base64url).
The client only ever sees a `KEY_ID`; `SESSION_ID` never leaves the server.

| Purpose | Key | Type | Fields / Value |
|---|---|---|---|
| session row | `gs:sess:{SESSION_ID}` | Hash | `creation`, `last_access`, `inactive_timeout`, `final_timeout`, `owner_id` |
| key_id_map row | `gs:key:{KEY_ID}` | String | `{SESSION_ID}` |
| key reverse set | `gs:sess:{SESSION_ID}:keys` | Set | `{KEY_ID}, …` |
| attributes (cached cookies) | `gs:sess:{SESSION_ID}:attr` | Hash | `{NAME}` → raw Set-Cookie `{VALUE}` |
| attribute change-detection | `gs:sess:{SESSION_ID}:sha` | Hash | `{NAME}` → `{VALUE_SHA}` |
| owner index | `gs:owner:{OWNER_ID}` | Set | `{SESSION_ID}, …` |

## 6. Timeouts

Two independent limits, both from the schema:

- **`INACTIVE_TIMEOUT`** — sliding idle window. Enforced as a **Redis TTL** on
  `gs:key:{KEY_ID}`, `gs:sess:{SESSION_ID}`, `:attr`, `:sha`, refreshed (`EXPIRE`) on
  every access. Redis evicts idle sessions; no sweeper needed.
- **`FINAL_TIMEOUT`** — absolute cap regardless of activity. Stored as
  `creation + final_timeout`; checked in code on each access. On refresh the applied
  TTL is `min(inactive_timeout, final_deadline − now)`, so Redis never keeps a session
  past its final deadline.

Defaults configurable (`inactive_timeout 30m`, `final_timeout 8h`), overridable per-site.
Timeout logic is driven by an injected `Clock` interface for deterministic tests.

## 7. KEY_ID Rotation

Rotation swaps the client-facing `KEY_ID` while keeping `SESSION_ID` and attributes intact:

1. Generate `KEY_ID₂`; `SET gs:key:{KEY_ID₂} = SESSION_ID`; add to the session key-set.
2. Emit the new proxy cookie to the client.
3. Old `KEY_ID₁` kept with a short **grace TTL** (default 60s, config) then deleted —
   absorbs in-flight concurrent requests still carrying the old cookie.

**Triggers (v1):**
- **Identity change** — `OWNER_ID` transitions 0→user or user→different-user
  (login / re-auth / privilege change). A pre-login KEY_ID is never reusable post-login.
- **Optional periodic** — rotate if `now − last_rotation ≥ rotate_interval` (default off).

## 8. Owner Binding & Revocation

- The `identity_header` is **stripped from the inbound request** (request path step 0)
  so only the backend can assert identity; a forged client header never reaches the app
  or gosestor's binding logic.
- On identity-header presence in the **response**, set `OWNER_ID` and
  `SADD gs:owner:{id} {SESSION_ID}`, then strip it from the response.
- `RevokeOwner(id)` deletes every session in `gs:owner:{id}` (keys/attrs included) — one
  call kills all of a user's sessions (logout-everywhere / breach response). Exposed on
  `SessionManager`; admin endpoint wiring deferred.

## 8a. Session Synchronization (`synchronize_sessions`)

Advanced, optional, and **disabled by default**. It serializes concurrent
backend requests belonging to the same session.

When two or more requests within the *same session* hit the backend concurrently, both
response paths may write cached cookies and/or rotate the KEY_ID at once, racing on the
same attribute hash — the classic "cookie collision" (a stale cookie value clobbering a
fresh one).

- **`false` (default)** — no locking. Writes rely on grouped writes + Redis per-op
  atomicity. Fine for the common case where a session rarely has truly simultaneous
  backend round-trips.
- **`true`** — gosestor takes a **per-session distributed lock** (Redis `SET NX PX`
  lock keyed `gs:lock:{SESSION_ID}`, released in a deferred step, with a bounded TTL so a
  crashed holder can't wedge the session) around the read-modify-write of session state,
  serializing concurrent same-session requests. Adds latency under contention; use only
  when the backend is sensitive to concurrent cookie churn.

Lock acquisition failure/timeout is governed by `on_store_error` (fail-closed by default).

## 9. Configuration (Caddyfile)

```caddyfile
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
            # path is optional: if omitted, NO Path attribute is written on the cookie
            same_site  lax            # lax | strict | none
            # http_only + secure ON by default; `insecure` disables secure (dev only)
        }

        # Deny-by-default cookie filter. Anything not named here is DROPPED
        # (neither forwarded to the client nor stored). There is no `drop` directive.
        forward  XSRF-TOKEN                        # backend Set-Cookie → passed to client
        store    JSESSIONID sessionid csrftoken    # backend Set-Cookie → swallowed + stored

        inactive_timeout  30m
        final_timeout     8h
        identity_header   X-Auth-User             # stripped from request AND response
        rotate_on_login   true
        rotate_interval   0                        # 0 = periodic rotation off
        rotate_grace      60s
        synchronize_sessions  false                # advanced: serialize concurrent same-session requests
        on_store_error    fail_closed              # fail_closed | fail_open
    }
    reverse_proxy backend:8080
}
```

Parsed via `UnmarshalCaddyfile` + `Provision`/`Validate`. Secrets come from env
placeholders, never inline.

## 10. Error Handling

- **Store unreachable** — governed by `on_store_error`:
  - `fail_closed` (**default**, security-first): do not pass raw backend cookies to the
    client and do not serve a half-session; return `502` (configurable status) + logged.
  - `fail_open`: pass the request through untouched (availability over cache guarantee).
- **Logging** — Caddy `zap` structured logs with context: **hashed** session/key ids
  (never raw secrets), operation, upstream error. No generic errors.
- **Partial writes** — a response's attribute writes are grouped so a mid-write failure
  never leaves some cookies stored and others leaked to the client (fail-closed on that
  response).
- **Malformed/oversized cookies** — bounded max size (config); rejected + logged; never
  stored unbounded.

## 11. Testing Strategy (TDD, behavior-focused)

- **`CookieFilter`** — table-driven unit tests: forward / store / drop-by-default across
  configs, including an unlisted cookie asserting `Drop`. Pure.
- **`SessionManager`** — tested against the in-memory `SessionStore` fake and against
  Redis via `miniredis`. Covers create, resolve, rotate (incl. grace), inactive vs final
  expiry, owner index, revoke-by-owner. Time advanced via injected `Clock`.
- **`RedisStore`** — contract tests against `miniredis` and (behind a build tag) a real
  containerized Redis for parity.
- **`Handler`** — `caddytest` integration in front of a stub backend emitting
  `Set-Cookie` + `X-Auth-User`. Asserts: (a) `store` cookies never reach the client,
  (b) `forward` cookies do reach the client, (c) unlisted cookies are dropped (neither
  forwarded nor stored), (d) client gets the proxy cookie, (e) second request re-injects
  cached cookies to the backend, (f) a client-supplied `X-Auth-User` is stripped from the
  request, (g) the backend's `X-Auth-User` is stripped from the response, (h) rotation
  emits a new KEY_ID on login, (i) fail-closed returns the error status when Redis is down.
- **Session synchronization** — with `synchronize_sessions true`, concurrent same-session
  requests serialize (no lost cookie write); lock TTL releases a crashed holder.

## 12. Dependencies

- `github.com/caddyserver/caddy/v2` — plugin framework, `caddytest`.
- `github.com/redis/go-redis/v9` — Redis-compatible client (Redis/Valkey/KeyDB/Dragonfly).
- `github.com/alicebob/miniredis/v2` — in-process Redis for tests.
- Build/distribution via `xcaddy`.
