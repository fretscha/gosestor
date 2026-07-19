# Backlog

Living list of planned and deferred work. Ordered by priority within each
section. The original v1 follow-ups (admin revoke endpoint,
`rotate_interval` wiring, and `rotate_on_login false`) shipped on 2026-07-06
(`f4335ab`). The CI pipeline shipped on 2026-07-19 (`.github/workflows/ci.yml`,
per [the design spec](designs/2026-07-19-ci-pipeline-design.md)).
The backend-requested rotation header (`rotate_header`, default
`X-Session-Rotate`) also shipped on 2026-07-19, per
[its design spec](designs/2026-07-19-rotate-header-design.md).
Path-based authorization with labels (`authz` block + `labels_header`)
shipped the same day per
[its design spec](designs/2026-07-19-authz-labels-design.md).
The demo authz walkthrough (steps 8–11) shipped on 2026-07-19 per
[its design spec](designs/2026-07-19-demo-authz-design.md).

## Next up

(empty — see deferred items below)

## Deferred until there is a real workload to measure against

### Resolve pipelining

Batch the per-request Redis round-trips in `Resolve()`. Premature without
production latency numbers.

### Low-priority hardening pass

Remaining low-severity review findings. Revisit once the plugin runs behind
real traffic.
