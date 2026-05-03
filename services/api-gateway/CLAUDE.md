# api-gateway — Claude Context

## What This Service Does

The single ingress point for all client traffic. It resolves every inbound HTTP request to an upstream service using longest-prefix route matching, then forwards the request through a reverse proxy. Cross-cutting concerns (auth, rate limiting, circuit breaking, caching, compression, retries, IP filtering, tracing) are implemented as opt-in Decorator middleware — disabled features cost nothing on the request path.

---

## Routes Are Declared in Config, Not in Code

Routes live in `gateway.yaml` (or `/etc/gateway/gateway.yaml`). The `static.Resolver` loads them at startup and holds them in memory for the process lifetime. **Changing routes requires a restart** — there is no hot-reload path for route changes.

`config.ToDomainRoutes()` is the single translation point from config structs to `domain.Route` values. Changes to route shape must be made in both the `RouteConfig` struct and `ToDomainRoutes`.

---

## Middleware Ordering Is Load-Bearing — Do Not Reorder

The proxy catch-all middleware chain in `routes.go` executes in this order:

```
JWT auth → IP filter → concurrency → rate limit → cache → proxy
```

This order is intentional:

- **Auth before rate limit**: an invalid or missing token is rejected immediately without consuming a rate-limit slot. Reversing this lets unauthenticated clients exhaust the token bucket.
- **Cache after rate limit**: a request that would be rate-limited never reaches the cache. Reversing this wastes a cache lookup on traffic that will be rejected anyway.
- **Compression outermost**: wraps the entire chain so even panic-recovery error responses are compressed.

---

## Transport Chain — Decorator Stack

The outbound transport is assembled inside-out in `container.go`:

```
proxy.Transport ← url-picker (round-robin or weighted) ← retry ← circuit breaker
```

Request flow is **outermost → innermost** (circuit breaker runs first). Key implications:

- The **URL picker** sets `route.Upstream.URL` on a copy of the route before passing it to `proxy.Transport`. Never read `route.Upstream.URL` before the picker has run.
- The **retry** wraps the URL picker, so each retry attempt may select a different upstream instance — a natural hedge against a single unhealthy endpoint.
- The **circuit breaker** is per-route-name and created lazily on first use (`sync.Map`). Open circuits return `503` without touching the URL picker or proxy at all.
- `proxy.Transport` caches one `*httputil.ReverseProxy` per upstream URL in a `sync.Map`. Construction (url.Parse, struct allocation) happens once per unique URL, not per request.

---

## Error Handling After Headers Are Written

`httputil.ReverseProxy` may begin writing the response (status + headers) before the upstream body is fully received. Once that happens, it is too late to write a different status code.

`handler.go:Proxy` uses a `statusRecorder` to track whether the response writer has been used:

```go
if err := h.transport.Forward(rw, r, route); err != nil {
    if rw.Written() {
        // headers already sent — can only record the metric, cannot rewrite the response
    } else {
        httputil.WriteError(w, apperrors.New(apperrors.ErrCodeInternal, "upstream error"))
    }
}
```

**Never remove the `rw.Written()` check.** Writing a second status code after headers are sent produces a malformed HTTP response.

The upstream error itself flows back through a `upstreamErrHolder` injected into the request context — because `ReverseProxy.ErrorHandler` is a shared closure and cannot safely close over a per-request local variable.

---

## The `Rewrite` Hook — Not `Director`

`proxy.Transport` uses `ReverseProxy.Rewrite` (introduced in Go 1.20), not the deprecated `Director` hook. The critical security difference: when `Rewrite` is used, the reverse proxy strips hop-by-hop headers (including `Connection` and any headers it names) from the outgoing request **before** `Rewrite` runs.

With `Director`, those headers were forwarded to upstreams unless `Director` explicitly removed them. This meant a client could smuggle a header via `Connection: X-Secret` and have `X-Secret` forwarded downstream. `Rewrite` closes that attack surface automatically.

**Do not migrate back to `Director`.**

---

## All Features Are Opt-In — Nil Means Zero Cost

Every optional middleware is wired as `nil` when disabled, and `NewRouter` / `buildProxyChain` skip nil entries entirely. There is no no-op wrapper allocation — the middleware simply does not exist in the chain.

This applies to: auth, IP filter, rate limiter, concurrency limiter, cache, compression, retry, circuit breaker, tracing.

When adding a new middleware, follow the same pattern: return `nil` from the builder when the feature is disabled, and guard with `if mw != nil` in `NewRouter`.

---

## Two-Phase Graceful Shutdown

`handler.SetReady(false)` triggers Phase 1: `/health` and `/ready` return `503` immediately. The load balancer sees this and stops routing new traffic. The gateway sleeps `drain_timeout_secs` (default: 5) to let the LB finish draining, then calls `server.Shutdown`.

`SetReady` is exposed on `Container` so `cmd/serve.go` can call it from the SIGTERM handler before the drain sleep. Do not call `server.Shutdown` before `SetReady(false)` — the LB would keep routing traffic to an instance that is no longer accepting connections.

---

## Adapters and Extension Points

### Adding a new rate limiting strategy

1. Implement `ports.RateLimiter` (or `ports.ConcurrencyLimiter`) in a new package under `adapters/outbound/`.
2. Add a `case` to `buildRateLimiter` in `container.go`.
3. Add the strategy name to `validRateLimitStrategies` in `config/config.go`.
4. Add validation in `validateRateLimitParams`.

### Adding a new auth type

1. Implement `ports.TokenVerifier` in a new package under `adapters/inbound/auth/`.
2. Add a branch to `buildAuthVerifier` in `container.go`.

### Adding a new transport decorator

1. Implement `ports.UpstreamTransport` in a new package under `adapters/outbound/`.
2. Wrap the existing transport in `buildTransportChain` in `container.go` — innermost to outermost.

---

## Key Invariants

- **Route names must be unique.** `validate()` enforces this at startup. Route names are used as metric labels and circuit breaker keys — duplicates would conflate metrics and share circuit state.
- **URL picker must run before `proxy.Transport`.** `proxy.Transport` reads `route.Upstream.URL` which is set by the picker. Bypassing the picker leaves `route.Upstream.URL` as the first configured URL, silently breaking load balancing.
- **`X-Auth-*` headers are stripped on public paths**, not just unauthenticated requests. This prevents clients from spoofing identity claims to upstreams on paths that bypass JWT validation.
- **Config file not found is not an error.** All settings have defaults. A missing `gateway.yaml` produces a valid (all-defaults) config, not a startup failure.
