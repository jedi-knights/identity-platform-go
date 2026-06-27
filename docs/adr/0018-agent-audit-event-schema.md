# ADR-0018: Agent Audit Event Schema

**Status**: Proposed
**Date**: 2026-06-26

## Context

The platform's services log via `go-logging` — structured JSON, suitable for
container log aggregators. That's enough for operational visibility (request
counts, error rates, latency) but not enough for **agent audit**.

Agent audit has different demands:

- **Stable schema** over a long horizon. Compliance reviews ask "show me every
  action this agent took in Q3" and expect the answer to compose across
  service rewrites. Log lines that drift with implementation aren't audit.
- **Cross-service joinable.** A single agent action fans out across
  auth-server (token issued), MCP server (tool dispatched), upstream API
  (request emitted). The audit record at each hop needs common fields so a
  consumer can stitch the chain.
- **Decision-aware.** Audit records "allow" and "deny" with equal fidelity —
  a denied tool call is more interesting than an allowed one. Log levels
  don't capture this; events with a `decision` field do.
- **Distinct from observability.** Traces (OTel) record *what happened and
  when*. Audit records *who did it, what they intended, and whether they were
  allowed*. The two systems can share a trace ID but have different retention,
  different access controls, and different schemas.

Today, MCP tool calls land in Fly logs as request-line strings; auth-server
issuance lands in JSON logs without a `decision` field; the policy service
emits its decisions but without the `actor_type` / `agent_id` claims from
ADR-0015. There is no single record any consumer can ingest end-to-end.

ADRs 0015–0017 add the *data* (`actor_type`, `agent_id`, `act` chain,
`authorization_details`). This ADR adds the *contract* under which every
service emits that data uniformly.

## Decision

Define a single agent-audit event envelope, hosted in a new
`go-platform/audit` package. Every service in the portfolio that mints,
exchanges, validates, introspects, or acts on agent tokens emits events
conforming to this envelope.

### Envelope

```json
{
  "schema_version": "1.0",
  "event_id": "01J7M3X9...",
  "event_type": "tool_invoked",
  "timestamp": "2026-06-26T22:00:00.000Z",
  "service": "jk-mcp-nwsl",
  "trace_id": "abc123",
  "correlation_id": "req-9f3...",
  "actor_type": "agent",
  "actor_id": "agent-claude-omar-laptop",
  "subject_id": "user-omar",
  "client_id": "agent-claude-omar-laptop",
  "resource": "tool:get_standings",
  "action": "invoke",
  "decision": "allow",
  "reason": "policy:read-only-agent",
  "attrs": {
    "tool_args_hash": "sha256:...",
    "upstream": "espn",
    "duration_ms": 142,
    "act_chain_depth": 2
  }
}
```

| Field | Required | Notes |
|---|---|---|
| `schema_version` | yes | This ADR is 1.0. Bumps are signaled, never silent. |
| `event_id` | yes | ULID for ordering + uniqueness. |
| `event_type` | yes | One of the registered types below. |
| `timestamp` | yes | RFC 3339 with millisecond precision. |
| `service` | yes | Service name (e.g., `auth-server`, `jk-mcp-nwsl`). |
| `trace_id` | yes when present | OTel trace ID; links to traces. |
| `correlation_id` | optional | Caller-supplied request ID. |
| `actor_type` | yes | From the token (ADR-0015): `user`, `service`, `agent`. |
| `actor_id` | yes | `agent_id` when agent; `client_id` for service; `sub` for user. |
| `subject_id` | optional | `sub` when distinct from actor (delegation). |
| `client_id` | optional | OAuth client used. |
| `resource` | yes | URI-like resource identifier (e.g., `tool:get_standings`, `token:access`, `client:registration`). |
| `action` | yes | Short verb (`invoke`, `issue`, `exchange`, `introspect`, `register`, `revoke`). |
| `decision` | yes | `allow` or `deny`. |
| `reason` | optional | Stable identifier of the decision rule. Free-form `text` discouraged; prefer `policy:<name>` or `error:<code>`. |
| `attrs` | optional | Free-form, event-type-specific. |

### Event-type registry

Registered initial types. Adding a type is a non-breaking change; renaming or
removing one is a `schema_version` bump.

| `event_type` | Emitted by | Trigger |
|---|---|---|
| `agent_authenticated` | auth-server | Token issued to a client with `actor_type=agent` |
| `agent_registered` | client-registry-service | DCR registration with `actor_type=agent` |
| `token_issued` | auth-server | Any access token issuance (not just agents) |
| `token_exchanged` | auth-server | Successful RFC 8693 exchange |
| `token_introspected` | token-introspection-service | Any introspection call |
| `token_revoked` | auth-server | Explicit revoke or family-cascade revoke |
| `policy_evaluated` | authorization-policy-service | Any policy decision |
| `tool_invoked` | jk-mcp-* | Any MCP tool dispatch (allow or deny) |
| `delegation_denied` | auth-server | Token exchange refused (chain too deep, scope widened, etc.) |
| `consent_granted` | login-ui | User approved an `authorization_details` request |
| `consent_denied` | login-ui | User refused an authorization request |

### Transport

The package supports three sinks (composable via the wrapping pattern
already used in MCP adapters):

- **Stderr JSON sink** — default. One event per line, identical to existing
  structured logs but on a separate logger name (`audit`) so log routers can
  filter.
- **OTel log sink** — emits the event as an OpenTelemetry log record with the
  trace_id linkage in the span context.
- **File sink** — append-only file rotation for environments that want audit
  on disk separately from operational logs.

Sinks are chosen at composition time via the `go-platform/container` DI
package; the calling code is sink-agnostic.

### Identity-platform-go wiring

Each service that needs to emit events imports `go-platform/audit`, resolves
an `Emitter` from the container, and calls `Emit(ctx, Event{...})` at the
audit point. The HTTP middleware chain (ADR-0001 / `httputil`) gains an
optional `AuditMiddleware` that emits per-request `tool_invoked` /
`token_introspected` events when wired in.

MCP servers (Python) mirror the schema without depending on the Go package
— they emit identically shaped JSON via structlog with the field names above.
A single consumer ingests both.

## Consequences

### Positive

- One schema across Go and Python services. A consumer (or a SIEM) can join
  events end-to-end.
- `decision` is a first-class field. Denied actions stop being log-level
  decisions made per-service.
- The `attrs` escape hatch keeps the schema small while letting event types
  carry the context they need.

### Negative

- Event-schema evolution becomes a public-contract concern. Adding fields is
  fine; renaming is not.
- The list of event types must stay disciplined — every new type is a new
  thing consumers may need to handle. The registry above doubles as a gate.
- Audit emission on the hot path adds work. Sinks must be non-blocking;
  failure to emit must not fail the underlying operation. The package
  enforces this by buffering and dropping with a metric on overflow.

### Backwards compatibility

The existing `go-logging` operational logs continue unchanged. Audit is a
separate stream. Consumers that don't read audit are unaffected.

## Alternatives considered

- **Extend `go-logging`.** Reject — couples audit semantics to operational
  logging. Retention, access, and routing should be separable.
- **Use OTel logs only.** Reject — OTel logs are a fine *transport* but not
  a schema. The agent-audit schema is the contract; OTel is one sink.
- **CloudEvents envelope.** Reject for v1 — CloudEvents adds verbosity for
  little gain inside a controlled portfolio. Revisit if we federate events
  outside the portfolio.

## References

- `architecture/docs/agentic-posture.md`
- ADR-0015 — Agent principal type (the actor fields come from these claims)
- ADR-0016 — Token exchange (`token_exchanged` event)
- ADR-0017 — Rich Authorization Requests (`consent_granted` event)
- RFC 9068 — JWT Profile for OAuth 2.0 Access Tokens (claim source for actor
  fields)
- `go-platform` README — the planned `audit` package location
