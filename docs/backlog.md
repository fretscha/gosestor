# Backlog

Living list of planned and deferred work. Ordered by priority within each
section. The original v1 follow-ups (admin revoke endpoint,
`rotate_interval` wiring, and `rotate_on_login false`) shipped on 2026-07-06
(`f4335ab`). The CI pipeline shipped on 2026-07-19 (`.github/workflows/ci.yml`,
per [the design spec](designs/2026-07-19-ci-pipeline-design.md)).

## Next up

### Backend-requested rotation header

A response header (working name `X-Session-Rotate`, stripped like the
identity header) that lets the backend request a KEY_ID rotation on any
response.

**Why:** closes the step-up re-auth gap — `rotate_on_login` only fires on an
OWNER_ID *transition*, so a privilege change under the same owner (MFA
step-up, sudo-mode, role change, password change) never rotates. OWASP
session guidance calls for renewing the session ID on *any* privilege-level
change. gosestor cannot detect these events itself (the identity header
carries the same owner ID before and after), so the backend signals instead —
which also covers triggers gosestor could never infer ("this account looks
suspicious").

**Sketch:**

- `processLocked()` reads + unconditionally strips the header (same pattern
  as the identity header at `session_store.go:488`).
- A truthy value marks the handle for rotation; the existing two-phase
  response-path machinery (`MaybeRotate()` / `rotateKey()`) does the rest.
- **Hard-delete the old key** (like `rotate_on_login`), not grace-perioded
  (like interval rotation): every plausible backend trigger is
  security-motivated, and a graced key would keep resolving to the
  now-elevated session.
- Config knob to enable/disable + header name override; default TBD at
  implementation time.
- TDD: manager-level rotation test, handler-level strip + rotate integration
  test, regression test that the header never reaches the client.

Estimated: ~half a day with tests.

## Deferred until there is a real workload to measure against

### Resolve pipelining

Batch the per-request Redis round-trips in `Resolve()`. Premature without
production latency numbers.

### Low-priority hardening pass

Remaining low-severity review findings. Revisit once the plugin runs behind
real traffic.
