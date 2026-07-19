# CI Pipeline — Design

Date: 2026-07-19. Status: approved. Implements the "CI pipeline" item from
[the backlog](../backlog.md).

## Goal

Every push and pull request on GitHub runs the full verification the project
already relies on locally: formatting, vet, the race-enabled test suite, and
proof that the plugin still compiles into a working Caddy binary.

## Decisions

- **Host:** GitHub, new public repo `github.com/fretscha/gosestor`
  (created as part of this work; the repo previously had no remote).
- **Module path:** renamed from `gosestor` to `github.com/fretscha/gosestor`
  so external users can `xcaddy build --with github.com/fretscha/gosestor`.
  Done as its own commit before the workflow lands. Mechanical: `go.mod`,
  internal import lines, `demo/Dockerfile` `--with` argument, doc mentions.
- **Smoke job shape:** native xcaddy on the runner (approach A), not
  `docker build` of `demo/Dockerfile`. Rationale: `setup-go` caching keeps it
  fast (~1–2 min warm) and it verifies what matters — the plugin compiles into
  a real Caddy binary and registers both modules. The Dockerfile is exercised
  by the local demo workflow; a Docker-build job can be added later if the
  demo bitrots.

## Workflow

One file, `.github/workflows/ci.yml`, triggered on push to `main` and on all
pull requests. Two parallel jobs on `ubuntu-latest`, Go version taken from
`go.mod` via `setup-go`'s `go-version-file`:

- **test:** `gofmt -l .` (fail on any output) → `go vet ./...` →
  `go test -race -count=1 ./...`
- **smoke:** `go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest` →
  `xcaddy build --with github.com/fretscha/gosestor=.` →
  `./caddy list-modules` must contain both `http.handlers.session_store` and
  `admin.api.gosestor`.

## Out of scope

Docker image build job, release automation, coverage reporting. Revisit when
the backlog's "real workload" items activate.
