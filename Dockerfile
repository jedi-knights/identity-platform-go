# syntax=docker/dockerfile:1

# =============================================================================
# Builder stage
#
# The whole workspace is copied because go.work uses local `use` directives for
# every module listed in it — currently every module under services/ plus
# test/acceptance. Without all of them present, the workspace cannot resolve
# inter-module dependencies at build time.
#
# Layer order is intentional: workspace definition → services. A change to one
# service invalidates the service build layer but not the workspace layer.
# =============================================================================
FROM golang:1.26-alpine AS builder

WORKDIR /workspace

COPY go.work go.work.sum ./
COPY services/ services/
COPY test/acceptance/ test/acceptance/

ARG SERVICE_NAME
RUN go build -o /app/service ./services/${SERVICE_NAME}/cmd

# =============================================================================
# Runtime stage
#
# Minimal alpine image with only what is needed at runtime:
#   - ca-certificates: required for any outbound TLS calls
#   - tzdata: required if time zone lookups are ever needed
#   - wget: used by Docker health checks (already in busybox but explicit here)
# =============================================================================
FROM alpine:3.21 AS runtime

RUN apk add --no-cache ca-certificates tzdata wget

COPY --from=builder /app/service /app/service

ENTRYPOINT ["/app/service"]
