# ADR-0016: Token Exchange (RFC 8693) for Agent-to-Agent Delegation

**Status**: Proposed
**Date**: 2026-06-26

## Context

The platform supports three grants today: `client_credentials`,
`authorization_code` (with PKCE), and `refresh_token`. None of them express
*delegation* — the case where one principal mints a token to act on behalf of
another principal, with both identities preserved.

Delegation is foundational for agentic deployments. Concrete scenarios:

- **Agent calls agent (A2A).** Claude, acting as agent A, calls a planning
  agent B. B needs a token to call MCP tools that proves "I am B, but A
  asked me to do this." Without delegation, B either uses A's token
  (impersonation, audit becomes meaningless) or its own token without A's
  context (the policy engine can't reason about who authorized the chain).
- **Agent on behalf of human.** A user grants an agent the right to call a
  resource. The agent's outbound calls must identify the agent *and* the
  user; the resource server enforces the human's policy, the audit log
  attributes the action to the agent.
- **Service-to-agent fan-out.** A backend service spawns an agent to fulfill
  a task. The agent's token should record the spawning service in the chain.

OAuth 2.1 doesn't address this. RFC 8693 (Token Exchange) does, and it's the
only IETF-standard answer. Token Exchange defines:

- A new grant type: `urn:ietf:params:oauth:grant-type:token-exchange`
- Two input tokens: `subject_token` (whose identity the new token represents)
  and optionally `actor_token` (who is acting on their behalf)
- An output token that may carry an `act` claim, a recursive structure that
  records every actor in the delegation chain

ADR-0008 (RS256 + JWKS) unblocked this — token exchange requires the auth
server to validate JWTs minted by itself (or by a trusted federation peer);
asymmetric keys + JWKS are the prerequisite.

## Decision

Implement RFC 8693 token exchange as a new grant strategy. The strategy
plugs into the existing `GrantStrategyRegistry` (ADR-0003); the dispatch
shape is unchanged.

### Request shape (RFC 8693 §2.1)

`POST /oauth/token` with `Content-Type: application/x-www-form-urlencoded`:

| Parameter | Required | Notes |
|---|---|---|
| `grant_type` | required | Must be `urn:ietf:params:oauth:grant-type:token-exchange` |
| `subject_token` | required | The token whose identity the new token represents |
| `subject_token_type` | required | Initially only `urn:ietf:params:oauth:token-type:access_token` (we issue JWTs) |
| `actor_token` | optional | The token of the principal acting on behalf of the subject |
| `actor_token_type` | optional | Same value set as above |
| `audience` | optional | Target resource server |
| `scope` | optional | Requested scopes (must be a subset of the subject_token's scopes) |
| `requested_token_type` | optional | Default `urn:ietf:params:oauth:token-type:access_token` |

Client authentication uses the existing token-endpoint mechanisms (HTTP Basic,
form-body, PKCE — see ADR-0009).

### Validation

The exchange strategy validates, in order:

1. The calling client is registered and authenticated. Public clients (no
   secret) may exchange tokens only when the `subject_token` was issued to
   them.
2. `subject_token` is an unrevoked access token issued by this server (RS256
   verify via JWKS) or by a federation peer in `AUTH_TRUSTED_ISSUERS`.
3. `actor_token` (if present) is also unrevoked and issued by this server or a
   trusted issuer.
4. Requested `scope` is a subset of `subject_token.scope`.
5. The combined delegation chain depth is within `AUTH_MAX_DELEGATION_DEPTH`
   (default 3 — caps fan-out).

### Issued token

The output is an `at+jwt` access token following RFC 9068 with these
modifications:

- `sub` is copied from `subject_token.sub` (preserves the subject identity).
- `actor_type` and `agent_id` (ADR-0015) are copied from the *actor* if
  `actor_token` was provided; otherwise from the calling client.
- A new top-level `act` claim records the delegation chain (RFC 8693 §4.1):

  ```json
  {
    "sub": "user-123",
    "scope": "read:standings",
    "actor_type": "agent",
    "agent_id": "agent-planner",
    "act": {
      "sub": "agent-planner",
      "actor_type": "agent",
      "act": {
        "sub": "agent-claude",
        "actor_type": "agent"
      }
    }
  }
  ```

  Each `act` level is the actor at that hop. Chains nest; the outermost `act`
  is the most recent actor.

- `family_id` (ADR-0014) is preserved from the subject token. A token-exchange
  output stays inside the same refresh-token family for revocation cascading
  — revoking the family kills every exchanged token derived from it.
- TTL is capped at `min(subject_token_remaining, AUTH_EXCHANGE_MAX_TTL)`
  (default 5 minutes for the cap). Delegated tokens are short-lived by default.

### Refresh tokens

The response does **not** include a refresh token. RFC 8693 does not preclude
issuing one, but issuing refresh tokens on every delegation hop would make
the family graph unbounded. Callers re-exchange instead of refresh.

### Audit

Every successful exchange emits an audit event (per ADR-0018 schema):

```
event_type: token_exchanged
actor_type, actor_id: from the actor token (or calling client)
subject_id: from the subject token
attrs.chain_depth: depth of the resulting `act` chain
attrs.requested_scope, attrs.granted_scope, attrs.audience
```

Replay detection is inherited from ADR-0014 — exchanging a revoked
subject_token fails. A subject_token's `code_jti` and `family_id` propagate
into the issued token so a downstream replay revokes the entire chain.

## Consequences

### Positive

- A2A delegation is expressible without impersonation. Audit chains are
  complete and machine-readable.
- The `act` chain enables the policy engine to reason about *who authorized
  this action originally* — useful for compliance and human-in-the-loop
  patterns.
- Federation becomes tractable: trusted external issuers can mint
  subject_tokens; the exchange step gives them a local representation that
  fits our revocation model.

### Negative

- Token exchange is a high-leverage attack surface. A compromised trusted
  issuer becomes a token-minting oracle for our resource servers. The
  `AUTH_TRUSTED_ISSUERS` list must be operationally tight (allowlist, signed
  JWKS endpoints, audited rotation).
- Chain depth and TTL caps are policy decisions baked into config. Misconfig
  (e.g., depth=10, TTL=1h) creates long, slow audit chains that are hard to
  reason about. Defaults err on the short side.
- The `act` chain is internal-by-design: most clients won't introspect it.
  We're committing to its shape forever (changing it is a breaking change
  for any policy engine that consumed it).

### Migration

Greenfield grant type — no migration. Existing clients that don't use token
exchange are unaffected. Resource servers that don't know about `act` ignore
it.

## Alternatives considered

- **Custom impersonation header.** Reject — leaks trust to whatever sets the
  header; no audit chain; not interoperable.
- **Reuse `authorization_code` with a special scope.** Reject — couples
  delegation to user-present flows; can't express service-only delegation.
- **Defer to OIDC CIBA.** CIBA addresses backchannel *authentication*, not
  delegation. Wrong tool.

## References

- `architecture/docs/agentic-posture.md`
- RFC 8693 — OAuth 2.0 Token Exchange
- RFC 9068 — JWT Profile for OAuth 2.0 Access Tokens
- ADR-0003 — Strategy pattern for grant types (the plug-in point)
- ADR-0008 — RS256 + JWKS (prerequisite)
- ADR-0014 — Refresh token family + revocation cascade (the cascade model
  this ADR extends)
- ADR-0015 — Agent principal type (`actor_type` / `agent_id` claims carried
  through the chain)
