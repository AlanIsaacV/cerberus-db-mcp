# syntax=docker/dockerfile:1

# Builder: compiles the static binaries the Raspberry Pi runs. BuildKit fills
# TARGETOS and TARGETARCH from the requested platform, so this same recipe can
# produce the Pi's arm64 binaries without relying on the builder's own CPU.
FROM --platform=$BUILDPLATFORM golang:1.26 AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG TARGETOS
ARG TARGETARCH

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /out/cerberus-db-mcp ./cmd/cerberus-db-mcp

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /out/cerberus-redis-mcp ./cmd/cerberus-redis-mcp

FROM gcr.io/distroless/static-debian12:nonroot AS cerberus-cache-mcp

COPY --from=builder /out/cerberus-redis-mcp /usr/local/bin/cerberus-redis-mcp

USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/cerberus-redis-mcp"]

# Final: distroless deliberately supplies neither a shell nor package manager.
# The image therefore exposes only the static server binary and runs it as the
# image's unprivileged built-in user.
FROM gcr.io/distroless/static-debian12:nonroot AS cerberus-db-mcp

COPY --from=builder /out/cerberus-db-mcp /usr/local/bin/cerberus-db-mcp

USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/cerberus-db-mcp"]
