# Build a Caddy binary that embeds the local gosestor plugin, then ship it on a
# slim runtime. Build context is the repository root (see docker-compose.yml) so
# the module source at /src/gosestor is the working tree, not a tagged release.
#
# We use a golang image whose Go version matches gosestor's go.mod directive
# rather than caddy's own builder image, which may lag behind.
FROM golang:1.26-bookworm AS builder
ENV CGO_ENABLED=0
RUN go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
COPY . /src/gosestor
RUN xcaddy build --with gosestor=/src/gosestor --output /out/caddy

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /out/caddy /usr/bin/caddy
COPY demo/Caddyfile /etc/caddy/Caddyfile
EXPOSE 80
ENTRYPOINT ["/usr/bin/caddy"]
CMD ["run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]
