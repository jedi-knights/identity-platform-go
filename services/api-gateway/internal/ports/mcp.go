package ports

import (
	"context"

	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/domain"
)

// MCPInvoker is the inbound application port for MCP tool invocations.
// HTTP handlers call this interface; the concrete MCPGatewayService implements it.
//
// Invoke authenticates the caller via rawJWT, resolves the routing decision using
// the registered decider, and returns both the decision and the resolved tool so
// the handler can proxy without a second registry lookup.
// The tool is non-nil only when Decision is Allow or Redirect.
type MCPInvoker interface {
	Invoke(ctx context.Context, req domain.MCPToolRequest, rawJWT string) (domain.MCPRoutingDecision, domain.MCPTool, error)
}

// MCPDecider is the outbound port for routing decision logic.
// Two implementations exist: a static Go implementation and an Anthropic Claude adapter.
// The container wires the Anthropic adapter when GATEWAY_MCP_ANTHROPIC_API_KEY is set;
// otherwise it falls back to the static implementation.
type MCPDecider interface {
	Decide(ctx context.Context, user domain.MCPUser, tool domain.MCPTool, state domain.MCPRateLimitState, req domain.MCPToolRequest) (domain.MCPRoutingDecision, error)
}

// MCPRateLimiter is the outbound port for per-user MCP rate-limit tracking.
// It exposes full state (used/remaining/reset time/per-group counters) so that
// the decider can include this information in its reasoning context.
//
// State must never mutate the underlying counters — it is a read-only snapshot.
// Consume atomically increments the consumed count; it returns ErrRateLimitExceeded
// when the consumption would take the bucket below zero, protecting against TOCTOU
// races between State and Consume.
type MCPRateLimiter interface {
	State(ctx context.Context, userID string, tier domain.UserTier) (domain.MCPRateLimitState, error)
	Consume(ctx context.Context, userID, rateGroup string) error
}
