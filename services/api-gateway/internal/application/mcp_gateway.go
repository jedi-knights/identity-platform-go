package application

import (
	"context"
	"errors"
	"fmt"

	"github.com/ocrosby/identity-platform-go/libs/jwtutil"
	"github.com/ocrosby/identity-platform-go/libs/logging"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/ports"
)

// MCPGatewayService orchestrates MCP tool invocations: authenticate the caller,
// fetch rate-limit state, ask the decider for a routing decision, and consume
// a rate-limit token on allow/redirect.
//
// MCPGatewayService implements ports.MCPInvoker.
type MCPGatewayService struct {
	decider     ports.MCPDecider
	rateLimiter ports.MCPRateLimiter
	tools       []domain.MCPTool
	clientTiers map[string]string // client_id → tier string
	signingKey  []byte
	logger      logging.Logger
}

// Compile-time check: MCPGatewayService must satisfy ports.MCPInvoker.
var _ ports.MCPInvoker = (*MCPGatewayService)(nil)

// NewMCPGatewayService creates an MCPGatewayService.
// logger may be nil; if so, no logging is performed.
func NewMCPGatewayService(
	decider ports.MCPDecider,
	rateLimiter ports.MCPRateLimiter,
	tools []domain.MCPTool,
	clientTiers map[string]string,
	signingKey []byte,
	logger logging.Logger,
) *MCPGatewayService {
	return &MCPGatewayService{
		decider:     decider,
		rateLimiter: rateLimiter,
		tools:       tools,
		clientTiers: clientTiers,
		signingKey:  signingKey,
		logger:      logger,
	}
}

// Invoke authenticates the caller, resolves the routing decision, and — on
// allow or redirect — returns the resolved tool so the handler can proxy.
//
// "Tool not found" and "deny" are valid routing outcomes returned as a
// DecisionDeny with no error; errors are reserved for infrastructure failures
// (invalid JWT, rate limiter unavailability).
func (s *MCPGatewayService) Invoke(ctx context.Context, req domain.MCPToolRequest, rawJWT string) (domain.MCPRoutingDecision, domain.MCPTool, error) {
	claims, err := jwtutil.Parse(rawJWT, s.signingKey)
	if err != nil {
		return domain.MCPRoutingDecision{}, domain.MCPTool{}, fmt.Errorf("%w: %w", ErrMCPUnauthorized, err)
	}

	user := s.buildUser(claims)

	requested, ok := s.findTool(req.ToolName)
	if !ok {
		return domain.MCPRoutingDecision{
			Decision:    domain.DecisionDeny,
			Reason:      "tool_not_found",
			UserMessage: fmt.Sprintf("tool %q is not available", req.ToolName),
		}, domain.MCPTool{}, nil
	}

	state, err := s.rateLimiter.State(ctx, user.ID, user.Tier)
	if err != nil {
		return domain.MCPRoutingDecision{}, domain.MCPTool{}, fmt.Errorf("fetching rate limit state: %w", err)
	}

	decision, err := s.decider.Decide(ctx, user, requested, state, req)
	if err != nil {
		return domain.MCPRoutingDecision{}, domain.MCPTool{}, fmt.Errorf("deciding route: %w", err)
	}

	s.logDecision(req.ToolName, user.ID, decision.Decision)

	if decision.Decision == domain.DecisionDeny {
		return decision, domain.MCPTool{}, nil
	}

	return s.dispatchDecision(ctx, user.ID, decision)
}

// dispatchDecision resolves the target tool from the decision and consumes a rate-limit
// token. On TOCTOU exhaustion it returns a synthetic deny decision instead of an error.
func (s *MCPGatewayService) dispatchDecision(ctx context.Context, userID string, decision domain.MCPRoutingDecision) (domain.MCPRoutingDecision, domain.MCPTool, error) {
	// The decider may have changed the tool name (redirect to a lower-tier alternative).
	resolved, ok := s.findTool(decision.ToolName)
	if !ok {
		return domain.MCPRoutingDecision{}, domain.MCPTool{}, fmt.Errorf("%w: %q", ErrMCPRedirectToolNotFound, decision.ToolName)
	}

	if err := s.rateLimiter.Consume(ctx, userID, resolved.RateGroup); err != nil {
		// Consume can fail under TOCTOU conditions when the budget is exhausted
		// between State and Consume. Surface this as a deny rather than an error.
		if errors.Is(err, ports.ErrRateLimitExceeded) {
			return domain.MCPRoutingDecision{
				Decision:    domain.DecisionDeny,
				Reason:      "rate_limit_exceeded",
				UserMessage: "rate limit exceeded; please retry after the window resets",
			}, domain.MCPTool{}, nil
		}
		return domain.MCPRoutingDecision{}, domain.MCPTool{}, fmt.Errorf("consuming rate limit token: %w", err)
	}

	return decision, resolved, nil
}

// logDecision emits a debug log for the routing decision when a logger is configured.
func (s *MCPGatewayService) logDecision(toolName, userID string, decision domain.MCPDecisionKind) {
	if s.logger != nil {
		s.logger.With("tool", toolName, "user", userID, "decision", decision).Debug("mcp routing decision")
	}
}

// buildUser constructs an MCPUser from JWT claims and the configured client→tier map.
func (s *MCPGatewayService) buildUser(claims *jwtutil.Claims) domain.MCPUser {
	tier := domain.TierFree
	if t, ok := s.clientTiers[claims.ClientID]; ok {
		tier = domain.UserTier(t)
	}
	return domain.MCPUser{
		ID:   claims.Subject,
		Tier: tier,
		JWTClaims: map[string]any{
			"client_id": claims.ClientID,
			"scope":     claims.Scope,
		},
	}
}

// findTool looks up a tool by name in the configured registry.
func (s *MCPGatewayService) findTool(name string) (domain.MCPTool, bool) {
	for _, t := range s.tools {
		if t.Name == name {
			return t, true
		}
	}
	return domain.MCPTool{}, false
}
