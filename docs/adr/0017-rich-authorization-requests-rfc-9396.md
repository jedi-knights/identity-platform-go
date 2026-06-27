# ADR-0017: Rich Authorization Requests (RFC 9396)

**Status**: Proposed
**Date**: 2026-06-26

## Context

OAuth scopes are coarse. `read:standings` means "this token can read standings"
— for which team, in which league, for how long, with what cost ceiling? The
scope doesn't say. To express any of that, today, the resource server has to
encode it out-of-band (per-resource ACLs, per-tool config, side-channel
metadata).

That's tolerable for human-driven clients with small permission sets. It
breaks down in two agentic patterns:

- **Per-call permissioning.** Claude calls `get_standings(team=1234)` once,
  for one team, for the next minute. The "right" grant for that call is "read
  team 1234 for 60 seconds, then stop." Today the token grants
  `read:standings` for the whole token lifetime over every team.
- **Human-in-the-loop consent.** A user authorizes an agent to make a single
  $50 purchase. The grant is not "purchase" — it's "purchase, SKU X, $50
  cap, before end-of-day." Existing scopes can't carry the constraints; the
  user must rely on the resource server to apply them post-hoc.

RFC 9396 (OAuth 2.0 Rich Authorization Requests, "RAR") addresses both by
adding an `authorization_details` parameter — a JSON array of typed objects
describing the requested access in structured form. Each object has a `type`
discriminator and arbitrary type-specific fields. The authorization server
echoes (and may narrow) the array in the response and embeds the granted
details as an `authorization_details` claim in the issued token. Resource
servers enforce the array directly instead of (or alongside) scopes.

## Decision

Accept `authorization_details` on the `/oauth/authorize` and `/oauth/token`
endpoints. Persist granted details on authorization codes and access tokens.
Publish the supported `authorization_details_types` in the
`/.well-known/oauth-authorization-server` metadata (ADR-0012).

### Request shape (RFC 9396 §2)

`authorization_details` is a JSON array, URL-encoded as a form value or
passed as JSON in the request body:

```json
[
  {
    "type": "mcp_tool",
    "tool": "get_standings",
    "actions": ["read"],
    "constraints": {
      "team_id": "1234"
    },
    "expires_in": 300
  }
]
```

Each object's `type` field selects a registered type handler. Unknown types
are rejected with `invalid_authorization_details` (RFC 9396 §5).

### Type registry

This ADR registers two initial types; more can be added without further ADRs
provided the type schema is documented:

#### `mcp_tool` — fine-grained MCP tool authorization

```json
{
  "type": "mcp_tool",
  "tool": "<tool name>",                  // required, e.g. "get_standings"
  "actions": ["read"|"invoke"],           // optional, defaults ["invoke"]
  "constraints": { ... arbitrary ... },   // optional, free-form constraint map
  "expires_in": 300                       // optional, seconds; capped at token TTL
}
```

The MCP authorization port (`jk-mcp-nwsl`, `jk-mcp-ecnl`) consumes this on
every dispatch.

#### `resource` — generic resource permission

```json
{
  "type": "resource",
  "locations": ["https://api.example.com/v1"],
  "actions": ["read", "write"],
  "datatypes": ["account", "transaction"]
}
```

Mirrors the example in RFC 9396 §2.2. Used by the example-resource-service
(ADR demo) and any future REST resource backed by the platform.

### Granted details on tokens

If `authorization_details` was on the request and approved (in full or after
narrowing by the consent UI / login-ui), the granted array is:

- Persisted on the authorization code (for the `authorization_code` grant)
  and consumed atomically with the code (per ADR-0009).
- Embedded as the `authorization_details` claim on the issued access token
  (RFC 9396 §7).
- Echoed in the token-introspection response under the same key
  (RFC 9396 §10.1).

Token exchange (ADR-0016) preserves `authorization_details` from the
subject_token onto the exchanged token, intersected with any narrower
`authorization_details` parameter on the exchange request. The combined
detail must be a subset of the original.

### Interaction with scopes

`scope` and `authorization_details` coexist. The platform treats them as
**both** authoritative: a token may carry scopes *and* details; resource
servers enforce both. RFC 9396 §1.3 supports this.

For RAR-aware resource servers (initially the MCP servers), the granular
details are the source of truth and scopes are a coarse pre-filter. For
RAR-unaware resource servers (existing API consumers), scopes remain the only
mechanism and details are ignored.

### Discovery (ADR-0012 metadata)

`/.well-known/oauth-authorization-server` gains:

```json
{
  "authorization_details_types_supported": ["mcp_tool", "resource"]
}
```

Clients discover which types this server understands and decide whether to
opt in.

## Consequences

### Positive

- Per-call permissioning becomes expressible without scope explosion. Agents
  can request narrow, short-lived grants per tool call instead of getting
  blanket access.
- Human-in-the-loop consent becomes precise. The login-ui can render
  authorization_details transparently ("authorize Claude to read team 1234
  for 5 minutes") instead of opaque scopes.
- Token exchange chains carry granular constraints without losing fidelity.

### Negative

- New surface area on every endpoint that touches tokens. Bugs in the
  type-handler registry could leak permissions across types.
- Resource servers must opt in. Until the MCP servers implement enforcement,
  granted `authorization_details` is policy theater.
- The set of types is a public contract. Adding a type is cheap; changing
  one is a breaking change.

### Migration

Greenfield parameter. Existing flows that don't send `authorization_details`
behave exactly as before. The token schema gains an optional claim; ignoring
it is forward-compatible.

## Alternatives considered

- **Custom claim per use case.** Reject — every new use case is a new claim
  and a new contract. RAR centralizes the schema.
- **Hierarchical scopes (`read:standings:team:1234`).** Reject — string
  parsing in resource servers; doesn't scale to two constraints; no IETF
  standard.
- **GNAP (the OAuth-successor effort).** GNAP is a richer model but pre-RFC.
  RAR ships today and bridges to GNAP without lock-in.

## References

- `architecture/docs/agentic-posture.md`
- RFC 9396 — OAuth 2.0 Rich Authorization Requests
- ADR-0009 — Authorization code with PKCE (the persist-on-code, consume-on-token
  pattern is reused)
- ADR-0012 — Authorization server metadata (where type support is advertised)
- ADR-0015 — Agent principal type (RAR + `actor_type=agent` is the agent
  authorization picture in full)
- ADR-0016 — Token exchange (carries `authorization_details` through the
  `act` chain)
