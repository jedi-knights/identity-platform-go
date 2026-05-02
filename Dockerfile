# syntax=docker/dockerfile:1

# =============================================================================
# Builder stage
#
# The entire workspace is copied because go.work uses local `use` directives
# for libs/ and services/. Without all modules present, the workspace cannot
# resolve inter-module dependencies at build time.
#
# Layer order is intentional: workspace definition → shared libs → services.
# A change to a lib invalidates service build layers; a change to one service
# does not invalidate the others or the libs layer.
# =============================================================================
FROM golang:1.26-alpine AS builder

WORKDIR /workspace

COPY go.work go.work.sum ./
COPY libs/ libs/
COPY services/ services/

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
