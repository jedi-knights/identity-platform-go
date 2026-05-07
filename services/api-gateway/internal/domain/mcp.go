package domain

import "time"

// UserTier represents the access level of a user or client.
type UserTier string

const (
	TierFree       UserTier = "free"
	TierSubscriber UserTier = "subscriber"
	TierPremium    UserTier = "premium"
	TierInternal   UserTier = "internal"
)

// tierRank maps tiers to an integer for ordered comparison.
var tierRank = map[UserTier]int{
	TierFree:       0,
	TierSubscriber: 1,
	TierPremium:    2,
	TierInternal:   3,
}

// TierOrder returns the ordinal rank of a tier so that callers can compare
// tiers without switching on string values. Higher values indicate more access.
// Unknown tiers return -1.
func TierOrder(t UserTier) int {
	rank, ok := tierRank[t]
	if !ok {
		return -1
	}
	return rank
}

// MCPTool describes a tool registered in the gateway's tool registry.
type MCPTool struct {
	Name        string
	Tier        UserTier
	RateGroup   string // empty means no rate-group limit applies
	Description string
	UpstreamURL string // destination URL when this tool is allowed or redirected to
}

// MCPUser carries the identity and tier of the caller.
type MCPUser struct {
	ID        string
	Tier      UserTier
	OrgID     string         // empty when the caller is not an org member
	JWTClaims map[string]any // full decoded claims, for edge-case reasoning
}

// MCPGroupState holds rate-limit counters for a single named rate group.
type MCPGroupState struct {
	Limit     int
	Used      int
	Remaining int
}

// MCPRateLimitState is the complete rate-limit picture for one user at one instant.
type MCPRateLimitState struct {
	UserID        string
	Tier          UserTier
	WindowSeconds int
	Limit         int
	Used          int
	Remaining     int
	ResetAt       time.Time
	RateGroups    map[string]MCPGroupState // keyed by rate group name; always initialised
}

// MCPToolRequest is the inbound MCP tool call.
type MCPToolRequest struct {
	ToolName  string
	Arguments map[string]any
	RequestID string
}

// MCPDecisionKind is the outcome of a routing decision.
type MCPDecisionKind string

const (
	// DecisionAllow permits the request and forwards it to the tool's upstream.
	DecisionAllow MCPDecisionKind = "allow"
	// DecisionDeny blocks the request and returns an error to the caller.
	DecisionDeny MCPDecisionKind = "deny"
	// DecisionRedirect forwards the request to an alternative tool's upstream.
	DecisionRedirect MCPDecisionKind = "redirect"
)

// MCPRoutingMetadata carries optional hints attached to a routing decision.
type MCPRoutingMetadata struct {
	CostEstimate         string // "low", "medium", "high", or empty
	SuggestedAlternative string // non-empty when the decider recommends an alternative
}

// MCPRoutingDecision is the result of a routing evaluation.
// UserMessage is populated on deny and should be shown to the end user.
// Reason is for gateway logs only and should never be exposed to callers.
type MCPRoutingDecision struct {
	Decision    MCPDecisionKind
	ToolName    string // confirmed tool name, or the redirect target
	Reason      string
	UserMessage string
	Metadata    MCPRoutingMetadata
}
