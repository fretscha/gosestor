FROM golang:1.26-bookworm AS builder
ENV CGO_ENABLED=0
WORKDIR /src
COPY go.mod ./
COPY main.go ./
RUN go build -o /out/backend .

FROM debian:bookworm-slim
COPY --from=builder /out/backend /usr/bin/backend
EXPOSE 8080
ENTRYPOINT ["/usr/bin/backend"]
