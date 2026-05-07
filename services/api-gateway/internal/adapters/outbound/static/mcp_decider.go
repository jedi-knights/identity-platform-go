package static

import (
	"context"
	"fmt"

	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/ports"
)

// MCPStaticDecider applies the MCP routing rules directly in Go without calling
// the Anthropic API. It is used when GATEWAY_MCP_ANTHROPIC_API_KEY is not set.
//
// Rules applied in order:
//  1. If the user's tier is below the tool's tier: redirect to an accessible
//     alternative in the same rate group if one exists; deny otherwise.
//  2. If the global rate limit is exhausted: deny.
//  3. If the tool's rate group is exhausted: deny.
//  4. If the user is free and below 10% of their budget: allow with an upgrade suggestion.
//  5. Otherwise: allow.
type MCPStaticDecider struct {
	tools []domain.MCPTool
}

// Compile-time check: MCPStaticDecider must satisfy ports.MCPDecider.
var _ ports.MCPDecider = (*MCPStaticDecider)(nil)

// NewMCPStaticDecider creates a decider backed by the given tool registry.
func NewMCPStaticDecider(tools []domain.MCPTool) *MCPStaticDecider {
	return &MCPStaticDecider{tools: tools}
}

// Decide evaluates the routing rules and returns a decision without any external calls.
func (d *MCPStaticDecider) Decide(_ context.Context, user domain.MCPUser, tool domain.MCPTool, state domain.MCPRateLimitState, _ domain.MCPToolRequest) (domain.MCPRoutingDecision, error) {
	if d, ok := d.checkTier(user, tool); !ok {
		return d, nil
	}
	if d, ok := d.checkRateLimits(tool, state); !ok {
		return d, nil
	}
	return d.buildAllow(user, tool, state), nil
}

// checkTier returns (deny/redirect, false) when the user's tier is below the tool's tier.
// Returns (zero, true) when the tier is sufficient.
func (d *MCPStaticDecider) checkTier(user domain.MCPUser, tool domain.MCPTool) (domain.MCPRoutingDecision, bool) {
	if domain.TierOrder(user.Tier) >= domain.TierOrder(tool.Tier) {
		return domain.MCPRoutingDecision{}, true
	}
	if alt, ok := d.findAlternative(tool, user.Tier); ok {
		return domain.MCPRoutingDecision{
			Decision:    domain.DecisionRedirect,
			ToolName:    alt.Name,
			Reason:      "redirected to lower-tier alternative",
			UserMessage: fmt.Sprintf("your plan does not include %q; redirecting to %q", tool.Name, alt.Name),
			Metadata:    domain.MCPRoutingMetadata{SuggestedAlternative: alt.Name},
		}, false
	}
	return domain.MCPRoutingDecision{
		Decision:    domain.DecisionDeny,
		Reason:      "insufficient_tier",
		UserMessage: fmt.Sprintf("tool %q requires %s tier or above", tool.Name, tool.Tier),
	}, false
}

// checkRateLimits returns (deny, false) when the global or group budget is exhausted.
// Returns (zero, true) when budget is available.
func (d *MCPStaticDecider) checkRateLimits(tool domain.MCPTool, state domain.MCPRateLimitState) (domain.MCPRoutingDecision, bool) {
	if state.Remaining <= 0 {
		return domain.MCPRoutingDecision{
			Decision:    domain.DecisionDeny,
			Reason:      "rate_limit_exceeded",
			UserMessage: fmt.Sprintf("rate limit exhausted; resets at %s", state.ResetAt.UTC().Format("15:04:05 UTC")),
		}, false
	}
	if tool.RateGroup != "" {
		if group, ok := state.RateGroups[tool.RateGroup]; ok && group.Remaining <= 0 {
			return domain.MCPRoutingDecision{
				Decision:    domain.DecisionDeny,
				Reason:      "rate_group_exceeded",
				UserMessage: fmt.Sprintf("rate limit for group %q exhausted; resets at %s", tool.RateGroup, state.ResetAt.UTC().Format("15:04:05 UTC")),
			}, false
		}
	}
	return domain.MCPRoutingDecision{}, true
}

// buildAllow constructs the allow decision, adding an upgrade suggestion for free users near their limit.
func (d *MCPStaticDecider) buildAllow(user domain.MCPUser, tool domain.MCPTool, state domain.MCPRateLimitState) domain.MCPRoutingDecision {
	if user.Tier == domain.TierFree && state.Limit > 0 && float64(state.Remaining)/float64(state.Limit) < 0.10 {
		return domain.MCPRoutingDecision{
			Decision:    domain.DecisionAllow,
			ToolName:    tool.Name,
			Reason:      "allowed; free user approaching limit",
			UserMessage: fmt.Sprintf("you have %d requests remaining; consider upgrading for more capacity", state.Remaining),
			Metadata:    domain.MCPRoutingMetadata{SuggestedAlternative: "upgrade"},
		}
	}
	return domain.MCPRoutingDecision{
		Decision: domain.DecisionAllow,
		ToolName: tool.Name,
		Reason:   "allowed",
	}
}

// findAlternative returns the first tool in the same rate group that the user
// can access (tier ≤ user tier). An empty rate group means no group-based
// alternatives exist.
func (d *MCPStaticDecider) findAlternative(requested domain.MCPTool, userTier domain.UserTier) (domain.MCPTool, bool) {
	if requested.RateGroup == "" {
		return domain.MCPTool{}, false
	}
	for _, t := range d.tools {
		if t.Name == requested.Name {
			continue
		}
		if t.RateGroup == requested.RateGroup && domain.TierOrder(t.Tier) <= domain.TierOrder(userTier) {
			return t, true
		}
	}
	return domain.MCPTool{}, false
}
