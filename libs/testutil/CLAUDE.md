# libs/testutil — Claude Context

## Purpose

Shared test helpers used across all service test suites. Keeps test boilerplate out of individual packages without introducing a heavy test framework dependency.

---

## Provided Helpers

| Helper | What it does |
|--------|-------------|
| `NewTestLogger()` | Returns a no-op `Logger` that discards all output — inject this in unit tests to silence log noise without requiring a real logger setup |
| `RequireNoError(t, err)` | Calls `t.Fatal` if `err` is non-nil; handles the typed-nil interface hazard (mirrors the guard in `libs/errors.Wrap`) |
| `AssertEqual(t, expected, actual)` | Deep-equality check via `reflect.DeepEqual`; note it distinguishes nil slices from empty slices |

---

## Typed-Nil Hazard in RequireNoError

`RequireNoError` uses the same `isNilableKind` guard as `libs/errors.Wrap`. A typed nil (`(*T)(nil)` stored in an `error` interface) is a non-nil interface but has no real error value. Treating it as an error failure would produce confusing test output. The guard normalises this consistently.

---

## What Belongs Here

- Helpers used by **two or more** service test suites
- Helpers that are **stable** — not tied to a particular service's domain

**Do not add** service-specific test helpers here. Keep them in the service's own `_test.go` files or a local `testhelpers_test.go`. This library should remain small.
