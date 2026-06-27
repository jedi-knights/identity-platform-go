# ADR-0015: Agent Principal Type — `actor_type` and `agent_id` Claims

**Status**: Proposed
**Date**: 2026-06-26

## Context

The platform currently issues tokens that distinguish *client types* (public vs
confidential, per ADR-0009 and ADR-0013) and *subjects* (human user via
authorization_code, no subject via client_credentials). It does not distinguish
*principal kinds*. A token issued to a human-driven OIDC client and a token
issued to an autonomous AI agent (via DCR + client_credentials) look identical
at the wire and in logs.

That distinction matters for an agentic deployment:

- **Audit** — "an action was taken at time T by client_id X" is sufficient
  forensics for a service backend; it's not sufficient for an autonomous agent
  whose behavior is probabilistic and whose blast radius spans whatever tools
  it's authorized to call. Audit consumers need to filter and alert on agent
  traffic specifically.
- **Policy** — an authorization policy may want to permit `agent` principals
  to call read-only MCP tools without per-tool registration, while requiring
  explicit grants for `user` and `service` principals. Today there is no claim
  the policy engine can switch on.
- **Rate limiting and cost accounting** — agents call tools at machine speed.
  Treating them in the same bucket as human-driven clients understates the
  resource pressure they create.
- **Delegation chains (forthcoming ADR-0016)** — when agent A exchanges a
  token to act on behalf of user U, the resulting token's `act` chain needs
  to identify A as an agent, not as an opaque client.

The MCP servers (`jk-mcp-nwsl`, `jk-mcp-ecnl`) are the immediate consumer.
They cannot today reject "anything that is not an agent" because the token
carries no such hint.

## Decision

Add two additive claims to access tokens, ID tokens (where meaningful), and
introspection responses:

- **`actor_type`** — string, one of `"user"`, `"service"`, `"agent"`. Identifies
  the kind of principal the token represents, *separate from* the OAuth client
  type (public/confidential).
- **`agent_id`** — string, present only when `actor_type=="agent"`. Stable
  identifier for the agent. For agents that registered via DCR it equals the
  `client_id`; for agents minted through other paths it is whatever the
  registry uses to identify the agent over its lifetime.

### Claim placement

| Claim | Access token (`at+jwt`) | ID token (`JWT`) | Introspection response |
|---|---|---|---|
| `actor_type` | required when set on the client | required when set on the client | required when set on the client |
| `agent_id` | present iff `actor_type=="agent"` | present iff `actor_type=="agent"` | present iff `actor_type=="agent"` |

Tokens issued before this ADR (no `actor_type` set on the client) omit both
claims — the platform stays backwards compatible. Resource servers that don't
know about `actor_type` ignore it (standard JWT forward compatibility).

### Source of truth

The client record (in `client-registry-service`) gains an `actor_type` field:

```go
type Client struct {
    // ... existing fields ...
    ActorType ActorType // "user" | "service" | "agent"; default "service"
    AgentID   string    // populated when ActorType == "agent"; defaults to ClientID
}
```

DCR (ADR-0013) accepts an `actor_type` metadata field on the registration
request. When omitted, the registry defaults to `"service"` — the safe
backwards-compatible value.

Token minting reads the client record once at issuance and copies
`actor_type` / `agent_id` into the JWT. Introspection mirrors them in the
response body.

### `jwtutil` changes

`go-platform/jwtutil.Claims` gains two optional fields:

```go
type Claims struct {
    jwt.RegisteredClaims
    Scope     string   `json:"scope,omitempty"`
    ClientID  string   `json:"client_id,omitempty"`
    ActorType string   `json:"actor_type,omitempty"`
    AgentID   string   `json:"agent_id,omitempty"`
    // ...
}
```

Both are `omitempty`. `IDClaims` gains the same fields. No new sentinel errors.

## Consequences

### Positive

- Audit logs can filter on `actor_type=agent` without joining against the
  client registry.
- The forthcoming MCP authorization port (`jk-mcp-nwsl`, `jk-mcp-ecnl`) can
  enforce coarse rules like "agents may call `readOnlyHint=true` tools without
  extra grants" without needing per-client registration of every Claude
  installation.
- Token exchange (ADR-0016) can carry an `act` chain that preserves
  `actor_type` per hop, making delegation transparent in audit.

### Negative

- Two more fields to keep consistent across the client record, token issuance,
  and introspection. Compile-time checks (ADR-0005) catch the contract surface
  but not the wiring.
- The default `actor_type="service"` is a guess. Existing confidential clients
  were never explicitly classified; if some are actually agents in the new
  model, they will be miscategorized until the registry is migrated.

### Migration

A one-shot DB migration sets `actor_type="service"` on every existing client
record. After deployment, agent operators re-register via DCR with
`actor_type="agent"` or update existing records via RFC 7592.

## Alternatives considered

- **Embed actor type in the OAuth scope.** Convention: add an `agent` scope.
  Rejected — scopes are about permissions, not principal identity. Mixing the
  two breaks consent UIs and confuses RBAC.
- **Use the existing `ClientType` (public/confidential).** Rejected — those
  values describe credential posture (does the client have a secret?), not
  whether the principal is human, service, or agent. An agent may be a public
  client (no secret, PKCE) *or* a confidential client; the dimensions are
  orthogonal.
- **Map agents to subjects (`sub`).** Rejected — `sub` is the human user (or
  empty for client_credentials), per OIDC §2. Overloading it would break
  every OIDC client that expects `sub` to identify a person.

## References

- `architecture/docs/agentic-posture.md` (portfolio gap analysis)
- ADR-0009 — code-jti claim shape (the same "additive internal claim" pattern)
- ADR-0013 — Dynamic Client Registration (the path agents use to onboard)
- RFC 9068 — JWT Profile for OAuth 2.0 Access Tokens (validates that
  additional claims are permitted)
- RFC 7662 — Token Introspection (introspection response is open-ended)
