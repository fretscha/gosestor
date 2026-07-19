# Backend-Requested Rotation Header — Design

Date: 2026-07-19. Status: approved. Implements the "Backend-requested
rotation header" item from [the backlog](../backlog.md).

## Problem

`rotate_on_login` rotates the KEY_ID only on an OWNER_ID *transition*. A
privilege change under the same owner — MFA step-up, sudo-mode, role change,
password change — never rotates, while OWASP session guidance calls for
renewing the session ID on any privilege-level change. gosestor cannot detect
these events (the identity header carries the same owner ID before and after),
so the backend signals rotation explicitly via a response header. This also
covers triggers gosestor could never infer ("this account looks suspicious").

## Config surface

New handler field `RotateHeader string` (`rotate_header` in Caddyfile and
JSON):

- Empty / omitted → default `X-Session-Rotate`, feature **enabled** —
  consistent with the fail-safe defaults of `rotate_on_login` (nil → true)
  and `identity_header` (active as `X-Auth-User`).
- `rotate_header <name>` → enabled with a custom header name.
- `rotate_header off` → disabled: the header value is never acted on, but the
  default header name `X-Session-Rotate` is still stripped from responses
  (defense in depth — backend internals never reach the client, same posture
  as the unconditional identity-header strip).

## Value semantics

The header value is parsed with `strconv.ParseBool`:

- parses true (`1`, `t`, `true`, …) → rotation requested;
- parses false (`0`, `f`, `false`, …) → no-op;
- unparseable → no rotation, warning log (explicit failure over guessing).

The header is stripped from the response in **all** cases — enabled, disabled,
invalid value, and on the response-path error scrub in `ensureProcessed()`
alongside `Set-Cookie` and the identity header.

## Manager change (`internal/session/manager.go`)

New method `Live.ForceRotate(ctx) error`:

1. If `l.rewrite` is already set (Begin minted a fresh key, or BindOwner
   already rotated this response), skip — a second swap would churn keys for
   nothing. Same guard `MaybeRotate` uses.
2. Re-read the session; set `LastRotation = now`; persist the session
   **before** the key swap (same crash-ordering rationale as `MaybeRotate`:
   the old key must never be deleted unless its replacement is guaranteed a
   spot in this response). Setting `LastRotation` also resets the interval
   clock, so an interval rotation never immediately follows a requested one.
3. Call the existing `rotateKey()` — mint new KEY_ID, persist, **hard-delete**
   the old key. Every plausible backend trigger is security-motivated; a
   surviving old key would keep resolving to the now-elevated session.

## Handler wiring (`session_store.go`, `processLocked`)

- Step 5b (new, right after the identity-header block): read + unconditionally
  strip the rotation header; if it parsed true and the feature is enabled,
  set a `rotateRequested` flag.
- Step 6b: `if rotateRequested && ic.live != nil { ForceRotate } else { MaybeRotate }`
  — late in the response path, after cookie storage, under the session lock.
- No live session → the request is a no-op; we never mint a session just to
  rotate it (mirrors the identity-header guard).

## Tests (written first, TDD)

Manager level (`internal/session/manager_test.go`):

- `ForceRotate` issues a new KEY_ID, the old key stops resolving
  (hard-deleted), the session's cookies survive under the new key.
- `ForceRotate` after `BindOwner` in the same handle is a no-op (rewrite
  already pending).
- `ForceRotate` resets the interval-rotation clock (`LastRotation`).

Handler level (`session_store_test.go` / `caddytest/integration_test.go`):

- Backend responds with `X-Session-Rotate: 1` → client receives a fresh proxy
  cookie; the previous proxy cookie no longer resolves.
- The rotation header never reaches the client: enabled, disabled
  (`rotate_header off`), and store-error scrub paths.
- `rotate_header off` → header value `1` does not rotate.
- Invalid value (`X-Session-Rotate: banana`) → no rotation, header stripped.
- No session on the request → header triggers nothing (no session minted).

## Docs

README config table, code-walkthrough rotation section, backlog item moved to
shipped.
