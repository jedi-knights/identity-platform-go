# authorization-policy-service — Claude Context

## What This Service Does

RBAC (Role-Based Access Control) engine. Maps subjects (users or clients) to roles, and roles to permissions. Serves two consumers:

1. **auth-server** — calls `GET /subjects/{id}/permissions` at token issuance time to embed roles/permissions in the JWT
2. **example-resource-service** — calls `POST /evaluate` at request time to check whether a specific subject can perform a specific action on a resource

---

## Domain Model

```
Subject → [Role names] → Role → [Permission{Resource, Action}]
```

Permissions are formatted as `"resource:action"` strings throughout. This format is embedded in JWTs and used as cache keys — do not change it without updating `libs/jwtutil.Claims` and the cache key scheme.

---

## Permission Resolution

`PolicyService.GetSubjectPermissions` deduplicates permissions across roles. If a subject has two roles that both grant `"document:read"`, the permission appears once in the result. This deduplication uses a `seen` map keyed on `"resource:action"`.

**Unknown roles are silently skipped.** If a subject is assigned a role that has no corresponding `RoleRepository` entry, that role is ignored rather than erroring. This allows roles to be removed without breaking existing policy assignments.

---

## Caching (Optional)

When `POLICY_REDIS_URL` is set, `container.go` wraps `PolicyService` with a `CachingPolicyEvaluator`:

- **Cache key**: `authz:{subject_id}:{resource}:{action}`
- **TTL**: 60 seconds
- **Fail-open**: Redis errors fall through to the database — evaluation always succeeds or fails based on real data
- **No cache invalidation on role mutations**: a subject's effective permissions may lag up to 60 seconds after a role change. This is intentional for the reference implementation.

If you implement role mutation endpoints, document this lag prominently in the API response or add explicit `DEL authz:{subject_id}:*` calls in the mutation handler.

---

## Outbound Dependencies

None. This service has no outbound HTTP calls — it reads from its own repository only.

---

## PermissionSpecification

`Evaluate` uses a `PermissionSpecification` (Specification pattern) to check whether any of a subject's roles grant the requested resource/action pair. This keeps the evaluation logic composable and testable independently of the repository layer.
