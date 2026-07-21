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
(0) strip all backend control headers from requests/trailers ← anti-spoof
(1) read __gosestor cookie
(2) Resolve(KEY_ID):                                     internal/session/manager.go
      key → sid → session row; enforce timeouts;
      slide TTLs; DECIDE rotateDue (touch nothing!)
(3) prepareUpstreamCookies:
      drop __gosestor + client copies of store-managed
      names, inject cached values
(4) call next handler (reverse_proxy → backend)

RESPONSE PATH (all normal HTTP responses are staged by the interceptor)
──────────────────────────────────────────────────────────
  buffer status/body while next handler runs
  downstream error → discard body + controls + cookies; mutate nothing
  downstream success:
    remove managed trailer declarations and late values
    capture + remove ALL Set-Cookie                 ┐
    parse + strip revoke header before lock;         │
        truthy → delete complete session and return  │ under per-session
    (5) parse owner/rotation/labels controls; strip   │ lock when
    (6) parse + filter Set-Cookie: fwd/store/drop;   │ synchronize_sessions
    (6b) atomically commit cookies + owner + labels  │
        + timestamps + optional key rotation         │
    (7) emit new/expired __gosestor as required      ┘
  commit staged status/body only after success
```

### The interceptor

Caddy hands us the `ResponseWriter` before the backend writes. The
`interceptor` stages normal HTTP status/body output until `next.ServeHTTP`
returns. This is intentional: a backend can write headers, flush bytes, and
still return an error. Delaying the wire commit ensures that such an error
applies no session mutation and leaks neither staged body nor backend metadata.
Managed trailer declarations and values populated after `WriteHeader` are
removed after the backend returns and before the response is committed.

`Flush` records the implicit status but does not bypass staging. A hijacked
connection cannot be rolled back, so the interceptor strips all managed
metadata and permits no response-driven session mutation, then commits the
scrubbed `101`/upgrade handshake before delegating the raw connection. There is
deliberately **no `Unwrap()`**: Go's
`http.ResponseController` must not reach the raw writer before the scrub.

The fail-safe in `ensureProcessed` is unconditional: on *any* response-path
error, **all** `Set-Cookie` and managed control headers/trailers are deleted
before anything reaches the wire. `fail_closed` additionally turns the response
into a 502; `fail_open` lets ordinary cache failures through without managed
state. A requested revocation is stricter: deletion or lock failure always
returns 502 in either mode, so logout can never look successful while the
session survives. Secrets never leak in any mode.

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

// Response path, step 6b: EXECUTE after downstream success
GetSession → re-check still due
ApplySessionControls(cookies, owner, labels, old → new, now)
// One Memory critical section / Redis script atomically validates the old key,
// applies cookie writes/deletes, changes the key mapping + reverse set, applies
// controls and timestamps, and aligns cascade TTLs.
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

**Login and label rotation** use that same atomic response transition. A stale
concurrent response that already lost the key race therefore cannot change
backend cookies, identity, labels, timestamps, reverse indexes, or cascade TTLs.
Cookie writes/deletes share the same old-key CAS and atomic transition, so a
stale response cannot attach backend authentication state to the winner's
session. Revocation still wins because the
transition requires both the session hash and the request's old key mapping to
exist. Hard deletion leaves no grace window: a graced key still maps to the
now-authenticated session, and a fixated pre-auth key could otherwise be
renewed indefinitely. A fresh pending key suppresses a second swap, so
login + interval boundary in one response means exactly one swap.

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

**Current-session logout** (`Live.Revoke`) is backend-driven through
`revoke_header` (default `X-Session-Revoke`). The handler parses and strips the
signal before trying the per-session lock, so even lock contention is recognized
as a failed logout rather than an ordinary fail-open cache error. A true value
wins over identity, labels, rotation, and every backend `Set-Cookie`: the complete
session cascade is deleted and the client proxy cookie is expired. A request
without a live session never mints one; a presented stale proxy cookie is still
expired. Invalid/false/disabled signals are stripped and otherwise ignored.

Revocation is also the store's stale-write boundary. Field-scoped session
mutations, `PutKey`, and `PutCookie` require the session hash to still exist,
atomically with their mutation (mutex in Memory, Lua in Redis). Separating
access touches, rotation, and labels also prevents stale reads from reverting a
concurrent owner or privilege transition. Thus a concurrent response resolved
before logout cannot recreate the session or leave orphan keys/cookies after the
delete. Redis performs the complete `DeleteSession` cascade atomically as well.

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

- `DeleteSession` atomically removes every key, cookie/hash, reverse set, session
  row, and owner-index membership.
- Field-scoped session mutations, `PutKey`, `ReplaceKey`, and `PutCookie`
  reject missing sessions, preventing stale concurrent responses from recreating
  revoked state or orphaning data. Temporal fields advance monotonically, and
  successful activity refreshes the session, current key, reverse-key set, and
  cookie/SHA hashes to one bounded TTL. Lua uses Redis `TIME` at execution to cap
  every refresh against both the persisted inactivity deadline and absolute final
  deadline; delayed or stale responses cannot regress timestamps or extend TTLs.
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
| Control-header spoofing    | managed headers stripped immediately; EOF-aware body wrapper strips late trailers | `session_store.go` ServeHTTP       |
| Current-session logout     | atomic cascade; expiry cookie; stale mutations require live session; failures 502 | `Live.Revoke`, store Lua             |
| Cookie smuggling           | client copies of managed names dropped upstream; KEY_ID never forwarded  | `prepareUpstreamCookies`           |
| Secret leak on failure     | cookies and controls scrubbed on mutation and downstream-error paths     | `ensureProcessed`/`discardBackendMetadata` |
| Scrub bypass via streaming | normal responses stage until success; hijacks discard managed metadata/state | interceptor                        |
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
