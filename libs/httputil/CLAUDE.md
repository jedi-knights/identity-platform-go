# libs/httputil — Claude Context

## Purpose

HTTP response helpers and middleware. Provides `WriteJSON`, `WriteError`, and three middleware: `TraceIDMiddleware`, `LoggingMiddleware`, `RecoveryMiddleware`.

---

## Core Invariant: Buffer Before Headers

`WriteJSON` always encodes into a `bytes.Buffer` before writing any headers. This is intentional — if JSON encoding fails the client receives a `500` rather than a `200` with a truncated body. **Do not change this to stream directly into `http.ResponseWriter`.**

---

## HTTPStatus Contract

`HTTPStatus` **panics on nil** — nil means success and must never be passed here. Non-`AppError` errors and unrecognised codes return `500`. All six predeclared `ErrorCode` values from `libs/errors` must appear in `appErrorHTTPStatus` — if a new code is added to `libs/errors`, update this map immediately.

---

## TraceIDMiddleware

- Reads `X-Trace-ID` from inbound request headers.
- Validates against a UUID v4 pattern before using it. Invalid or missing values are replaced with a freshly generated UUID — this prevents log injection via crafted headers.
- Echoes the trace ID back in the response header.
- Stores the trace ID in context via `logging.WithTraceID`.

---

## responseWriter Wrapper

`responseWriter` wraps `http.ResponseWriter` to track whether headers have been committed (`wroteHeader`) and capture the status code. Used by `LoggingMiddleware` (to log the actual status) and `RecoveryMiddleware` (to avoid writing a double response after a panic). **Do not bypass it in new middleware that needs to read the status code.**

---

## Middleware Order Matters

Standard recommended order when composing:

```
TraceIDMiddleware → RecoveryMiddleware → LoggingMiddleware → (auth) → handler
```

`TraceIDMiddleware` must run first so all subsequent middleware and handlers have a trace ID in context. `RecoveryMiddleware` must wrap `LoggingMiddleware` so panics are caught before the logging middleware tries to record a status.
