# gosestor — Code Walkthrough

A guided tour of the codebase: architecture, request lifecycle, storage model,
and the reasoning behind the security decisions. Start with the short
[README](../README.md) and the
[session-cookie proxy design](designs/2026-07-02-gosestor-session-cookie-proxy-design.md).

## 1. The big picture

gosestor makes a backend's session cookies **never leave the server**. The
client gets one opaque, rotatable cookie; everything the backend sets is cached
in Redis and re-injected upstream on later requests. It implements server-side
session-cookie caching as Caddy middleware.

```
            ┌────────────────────────  what the CLIENT sees  ───────────────────────┐
            │  Set-Cookie: __gosestor=b6eCG...   (opaque 256-bit KEY_ID, HttpOnly)  │
            └────────────────────────────────────────────────────────────────────────┘

Client ──__gosestor=KEY──▶ ┌─────────── Caddy + session_store ───────────┐ ──JSESSIONID=secret──▶ Backend
                           │  KEY_ID ──▶ SESSION_ID ──▶ cached cookies   │
Client ◀──filtered────────  │            (Redis)                          │ ◀──Set-Cookie: JSESSIONID──
                           └──────────────────────────────────────────────┘        X-Auth-User: 42
```

Three IDs, deliberately separated:

| ID           | Who holds it          | Purpose                                              |
|--------------|-----------------------|------------------------------------------------------|
| `KEY_ID`     | client (cookie value) | opaque handle; **rotatable/disposable**              |
| `SESSION_ID` | server only           | stable anchor for cached data; never crosses the proxy |
| `OWNER_ID`   | server only           | integer user id from the backend, enables logout-everywhere |

Decoupling `KEY_ID` from `SESSION_ID` is what makes rotation cheap: you
re-point a new key at the same session instead of migrating data.

## 2. Package layout

```
session_store.go        Caddy handler: config, ServeHTTP pipeline, response interceptor
admin.go                admin.api.gosestor: POST /gosestor/revoke/{owner_id}
internal/
  filter/filter.go      deny-by-default cookie classifier (Forward/Store/Drop)
  session/manager.go    lifecycle brain: Manager (stateless ops) + Live (per-request handle)
  session/clock.go      Clock interface → deterministic time in tests
  store/store.go        Store interface (the persistence contract)
  store/redis.go        production impl (go-redis, pipelines)
  store/memory.go       test double (mutex + maps)
  store/contract.go     one test suite run against BOTH stores
caddytest/              end-to-end tests against real Caddy + miniredis
demo/                   live Docker stack (xcaddy build + Redis + stub backend)
```

Dependency direction is strictly downward — handler → session → store — with
interfaces at each seam (`store.Store`, `session.Clock`), which is why every
layer is testable without Redis or wall-clock time.

## 3. Request lifecycle

The heart of the plugin is `ServeHTTP` (`session_store.go`):

```
REQUEST PATH (read-mostly, never destroys client state)
──────────────────────────────────────────────────────────
(0) strip identity header from request + trailers      ← anti-spoof
(1) read __gosestor cookie
(2) Resolve(KEY_ID):                                     internal/session/manager.go
      key → sid → session row; enforce timeouts;
      slide TTLs; DECIDE rotateDue (touch nothing!)
(3) prepareUpstreamCookies:
      drop __gosestor + client copies of store-managed
      names, inject cached values
(4) call next handler (reverse_proxy → backend)

RESPONSE PATH (all mutations, wrapped in the interceptor)
──────────────────────────────────────────────────────────
ensureProcessed() — runs EXACTLY ONCE, just before the
first WriteHeader/Write/Flush/Hijack:
  capture + remove ALL Set-Cookie                 ┐
  (5) bind owner from identity header, strip      │ under per-session
  (6) parse + filter Set-Cookie: fwd/store/drop;  │ lock when
      stored expiries delete cached value + SHA   │ synchronize_sessions
  (6b) MaybeRotate — the KEY swap, LAST           │
  (7) emit new __gosestor if key changed          ┘
```

### The interceptor

Caddy hands us the `ResponseWriter` before the backend writes. The
`interceptor` wraps it and defers all header rewriting to a `sync.Once`:

```go
func (ic *interceptor) WriteHeader(status int) {
	ic.ensureProcessed()          // ← header pipeline fires here, once
	...
}
```

`Flush` and `Hijack` also call `ensureProcessed()` first — that's why SSE
streams and WebSocket upgrades can't smuggle an unfiltered `Set-Cookie` past
the pipeline. There is deliberately **no `Unwrap()`**: Go's
`http.ResponseController` would use it to reach the raw writer and commit
headers before our scrub.

The fail-safe in `ensureProcessed` is unconditional: on *any* response-path
error, **all** `Set-Cookie` and the identity header are deleted before anything
reaches the wire. `fail_closed` additionally turns the response into a 502;
`fail_open` lets it through, just session-less. Secrets never leak either way.

## 4. Session lifecycle — `internal/session/manager.go`

`Manager` holds config + store + clock; `Live` is the per-request handle
carrying pending state (`rotateDue`, `rewrite`, `newKey`).

**Timeouts.** Two windows, both enforced twice — logically in `expired()` and
physically via Redis TTL `min(inactive, remaining-until-final)` — so a session
can never outlive its absolute deadline even if the process dies.

**Rotation is two-phase**, and this is the most deliberate design point in the
codebase:

```go
// Resolve (request path):  DECIDE only
rotateDue = now - sess.LastRotation >= interval

// MaybeRotate (response path, step 6b): EXECUTE
GetSession → re-check still due   // concurrent request may have won
PutSession(LastRotation=now)      // BEFORE the swap ─┐ failure here = retry next interval,
rotateKey: PutKey(new) → DeleteKey(old)  //           ┘ client's key untouched
```

Why the ceremony? Ordering is everything:

```
BAD  (naive):   Resolve deletes K_old ──▶ upstream 502 ──▶ cookie never sent
                ──▶ client still holds K_old ──▶ silently logged out

GOOD (current): nothing touched until the response is being built;
                the swap is the LAST fallible step before the
                infallible hdr.Add of the new cookie
```

Both regression tests for this are **mutation-validated** — re-introducing
request-path rotation makes `TestUpstreamErrorAtRotationBoundaryKeepsOldKey`
fail.

**Login rotation** (`BindOwner`) hard-deletes the old key with *no grace
window*: a graced key still maps to the now-authenticated session, and since
`Resolve` slides TTLs on every use, a fixated pre-auth key could be renewed
forever. Hard delete closes session fixation completely. Interval rotation
reuses the same `rotateKey`, and `MaybeRotate` skips if `rewrite` is already
set — login + interval boundary in one request means exactly one swap.

Legacy sessions (created before `rotate_interval` existed) have
`last_rotation == 0`; `Resolve` backfills the clock instead of mass-rotating
the whole fleet on the first post-upgrade request.

**Backend-requested rotation** (`ForceRotate`) closes the gap the other two
triggers leave: `rotate_on_login` only fires on an owner-id *transition*, so a
privilege change under the same owner (MFA step-up, sudo-mode, password
change) never rotates — and gosestor cannot detect those events itself. The
backend signals instead, by setting `rotate_header` (default
`X-Session-Rotate`) truthy on any response. The handler reads and
unconditionally strips the header at step 5b — enabled, disabled, or invalid,
it never reaches the client, including via the `ensureProcessed` error scrub —
and executes at step 6b in place of `MaybeRotate`. `ForceRotate` follows the
same crash-ordering as interval rotation (`LastRotation` persisted before the
swap, so a partial failure leaves the client's key valid), hard-deletes the
old key via the shared `rotateKey` (every backend trigger is
security-motivated; the pre-trigger key must not keep resolving to the
now-elevated session), and no-ops when `rewrite` is already pending — login +
rotate request in one response means exactly one swap. Setting `LastRotation`
also resets the periodic clock, so an interval rotation never immediately
follows a requested one.

**Labels and path-based authorization** (`internal/authz` + steps 1b/5c) turn
the proxy into the authorization enforcement point. `internal/authz`
compiles `require` rules once at Provision: paths are `path.Clean`ed, sorted
longest-first, and matched segment-aware (`/admin` covers `/admin/users`, not
`/administrator`), so neither traversal nor duplicate slashes can dodge or
spoof a rule and declaration order never matters. Load-time validation
rejects a label with no `auth_endpoint` and — the important one — an auth
endpoint living under a protected prefix, which would be a redirect loop.

On the request path (step 1b, before the upstream is called) the required
label must be present in the session's label set; `anonymous` paths
short-circuit. A denied browser gets a 302 to the label's endpoint with the
original path+query in the redirect parameter (built only from server config
and the request's own URL — no open-redirect surface); other clients get a
401 with `X-Auth-Endpoint`. Because an unresolvable session has no provable
labels, authz fails CLOSED with the store down even under
`on_store_error fail_open`.

On the response path (step 5c) the labels header is read and unconditionally
stripped — including the `ensureProcessed` error scrub. Presence REPLACES the
session's set (downgrade is the same operation as upgrade), an empty value
clears it, absence changes nothing. A grant with no live session mints one
(unless the grant is empty); the reserved `anonymous` label is dropped from
grants with a warning. `SetLabels` persists the normalized set and rotates
the KEY_ID on change — a label change is a same-owner privilege change — via
the shared `rotateKey`, behind the same `rewrite` guard: login + grant in one
response still means exactly one swap.

## 5. Storage — `internal/store/`

Redis layout (all under a configurable prefix):

```
gs:key:<KEY_ID>        → SESSION_ID            (string, TTL)
gs:sess:<SID>          → {creation, last_access, timeouts, owner_id, last_rotation}  (hash, TTL)
gs:sess:<SID>:attr     → {JSESSIONID: value}   (cached cookies)
gs:sess:<SID>:sha      → {JSESSIONID: sha}     (companion value hash; deleted atomically)
gs:sess:<SID>:keys     → set of KEY_IDs        (reverse index for delete cascade)
gs:owner:<OWNER_ID>    → set of SIDs           (logout-everywhere; sliding TTL)
gs:lock:<SID>          → random token          (SET NX + compare-and-delete Lua unlock)
```

Hygiene invariants:

- `DeleteSession` prunes the owner set (reads `owner_id` before the hash dies).
- `DeleteKey` prunes the session's reverse key-set.
- Owner sets carry a TTL sliding on each login, so abandoned sets expire even
  though TTL-expired sessions never pass through `DeleteSession`.
- `RevokeOwner` sweeps every member it walks — including stale sids.
- Owner id `0` is the anonymous sentinel — refused at every entry point
  (`BindOwner`, the handler, the admin API) so an un-prunable `owner:0` set can
  never form.

`contract.go` runs one behavioral suite against both `Memory` and `Redis` — the
test double can't drift from production semantics.

## 6. The cookie filter — `internal/filter/`

Two allowlists, deny-by-default, and on overlap **Store wins over Forward** — a
misconfiguration fails toward "keep it server-side" rather than "leak it to the
client":

```
name ∈ store list    → swallow, cache in Redis     (JSESSIONID, sessionid…)
name ∈ forward list  → pass to client unchanged    (XSRF-TOKEN…)
otherwise            → drop silently               (adtrack…)
```

## 7. Admin API — `admin.go`

A separate Caddy module (`admin.api.gosestor`) mounted on the admin endpoint,
so the destructive operation inherits Caddy's existing admin trust boundary
(loopback + Host/origin checks) instead of inventing a bearer-token scheme:

```
POST /gosestor/revoke/42  → RevokeOwner(42) on every registered manager → 204
```

The glue is a package-global registry `map[*Handler]*session.Manager` — needed
because admin modules have no handle on per-site state. Keyed by pointer so
Caddy's reload sequence (provision new → cleanup old) never has a gap: the new
handler registers before the old one unregisters, and `Cleanup` also closes the
Redis pool.

## 8. Security decisions at a glance

| Threat                     | Defense                                                                  | Where                              |
|----------------------------|--------------------------------------------------------------------------|------------------------------------|
| Session fixation           | hard-delete rotation on identity change                                  | `manager.go` `BindOwner`/`rotateKey` |
| Identity spoofing          | header **and trailer** stripped from request; header stripped from response | `session_store.go` ServeHTTP/processLocked |
| Cookie smuggling           | client copies of managed names dropped upstream; KEY_ID never forwarded  | `prepareUpstreamCookies`           |
| Secret leak on failure     | unconditional Set-Cookie + identity scrub, fail_closed 502               | `ensureProcessed`                  |
| Scrub bypass via streaming | `Flush`/`Hijack` process headers first; no `Unwrap`                      | interceptor                        |
| Key guessing               | 256-bit `crypto/rand` ids                                                | `manager.go` `newID`               |
| CSRF-ish cookie config     | `SameSite=None` + `insecure` rejected at validate                        | `Validate`                         |
| Silent config foot-guns    | `ParseBool` errors, negative durations rejected, `rotate_on_login` is `*bool` (JSON omission → **true**) | `session_store.go` |

## Key points

1. **Two cookies-worth of trust, one cookie on the wire** — the client only
   ever holds a disposable `KEY_ID`; everything sensitive lives keyed by a
   `SESSION_ID` it never sees.
2. **Request path decides, response path mutates** — the single rule that makes
   rotation, owner binding, and error scrubbing safe under upstream failures
   and concurrency.
3. **Everything fails closed** — filter (deny-by-default), store errors
   (502 + scrub), config parsing (loud errors), JSON defaults (`*bool` → rotate).
4. **Interfaces at every seam** — `Store`, `Clock`, contract tests, and an
   injectable RNG make the whole security model testable deterministically; the
   two nastiest invariants are additionally mutation-tested and proven live in
   the Docker demo (`demo/demo.sh`).
