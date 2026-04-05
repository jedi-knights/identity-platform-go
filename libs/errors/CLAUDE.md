# libs/errors — Claude Context

## Purpose

Typed application errors for the identity platform. The central type is `AppError`, which pairs an `ErrorCode` with a human-readable message and an optional wrapped cause.

---

## ErrorCode → HTTP Status Mapping

There are exactly six predeclared `ErrorCode` constants. **Do not add new codes without also updating `libs/httputil`'s `appErrorHTTPStatus` map** — the two must stay in sync.

| ErrorCode | HTTP Status |
|-----------|-------------|
| `ErrCodeNotFound` | 404 |
| `ErrCodeUnauthorized` | 401 |
| `ErrCodeForbidden` | 403 |
| `ErrCodeBadRequest` | 400 |
| `ErrCodeConflict` | 409 |
| `ErrCodeInternal` | 500 |

Use `ValidCode` at API boundaries when an `ErrorCode` arrives from an external source — reject with `ErrCodeBadRequest` when it is unrecognised.

---

## Typed-Nil Interface Hazard

`Wrap` normalises typed nils to untyped nil at the point of storage. This is intentional and must not be removed.

A typed nil (`(*T)(nil)` assigned to an `error` interface) is a non-nil interface value. Storing it as-is in `AppError.err` would cause `Unwrap` to return a non-nil value and `Error()` to produce a confusing three-part string ending in `"<nil AppError>"`.

**Rule**: any function in this package (or any downstream package) that accepts an `error` and stores it must guard against typed nils. A doc comment warning callers not to pass typed nils is not a substitute — the guard must be in the implementation.

---

## Error Chain Participation

`AppError` implements `Unwrap()`, making it compatible with `errors.As`, `errors.Is`, and `fmt.Errorf("%w", ...)`. Use the `Is*` predicates (`IsNotFound`, `IsUnauthorized`, etc.) as a convenience for the most common code checks — they call `errors.As` internally and inspect the first `AppError` in the chain.

---

## What Belongs Here vs Elsewhere

- **Error construction**: `New`, `Wrap`, predicates — here
- **HTTP status mapping**: `libs/httputil.HTTPStatus` — there
- **JSON serialisation of error responses**: `libs/httputil.WriteError` — there
- **Logging of errors**: call site responsibility
