// Package anthropic provides an MCPDecider that calls the Anthropic Claude API
// to make MCP tool routing decisions.
package anthropic

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"

	"github.com/ocrosby/identity-platform-go/libs/logging"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/ports"
)

//go:embed system_prompt.txt
var systemPrompt string

// MCPDecider calls Claude to produce a routing decision for each MCP tool request.
// The Anthropic API key is provided at construction time and is never read at
// request time — callers are responsible for loading it from the environment.
type MCPDecider struct {
	client anthropic.Client
	model  string
	logger logging.Logger
}

// Compile-time check: MCPDecider must satisfy ports.MCPDecider.
var _ ports.MCPDecider = (*MCPDecider)(nil)

// NewMCPDecider creates an MCPDecider using apiKey and model.
// logger may be nil.
func NewMCPDecider(apiKey, model string, logger logging.Logger) *MCPDecider {
	return &MCPDecider{
		client: anthropic.NewClient(option.WithAPIKey(apiKey)),
		model:  model,
		logger: logger,
	}
}

// routeContext is the JSON payload sent to Claude as the user message.
type routeContext struct {
	Context requestContext `json:"context"`
	Task    string         `json:"task"`
}

type requestContext struct {
	User           userPayload      `json:"user"`
	ToolRegistry   []toolPayload    `json:"tool_registry"`
	RateLimitState rateLimitPayload `json:"rate_limit_state"`
	Request        requestPayload   `json:"request"`
}

type userPayload struct {
	ID        string         `json:"id"`
	Tier      string         `json:"tier"`
	OrgID     *string        `json:"org_id"`
	JWTClaims map[string]any `json:"jwt_claims"`
}

type toolPayload struct {
	Name        string  `json:"name"`
	Tier        string  `json:"tier"`
	RateGroup   *string `json:"rate_group"`
	Description string  `json:"description"`
}

type rateLimitPayload struct {
	UserID        string                  `json:"user_id"`
	Tier          string                  `json:"tier"`
	WindowSeconds int                     `json:"window_seconds"`
	Limit         int                     `json:"limit"`
	Used          int                     `json:"used"`
	Remaining     int                     `json:"remaining"`
	ResetAt       string                  `json:"reset_at"`
	RateGroups    map[string]groupPayload `json:"rate_groups"`
}

type groupPayload struct {
	Limit     int `json:"limit"`
	Used      int `json:"used"`
	Remaining int `json:"remaining"`
}

type requestPayload struct {
	ToolName  string         `json:"tool_name"`
	Arguments map[string]any `json:"arguments"`
	RequestID string         `json:"request_id"`
}

// claudeDecision is the expected structure of Claude's JSON response.
type claudeDecision struct {
	Task        string         `json:"task"`
	Decision    string         `json:"decision"`
	ToolName    string         `json:"tool_name"`
	Reason      string         `json:"reason"`
	UserMessage string         `json:"user_message"`
	Metadata    claudeMetadata `json:"metadata"`
}

type claudeMetadata struct {
	CostEstimate         *string `json:"cost_estimate"`
	SuggestedAlternative *string `json:"suggested_alternative"`
}

// Decide builds the JSON context payload, calls Claude, and maps the response
// to a domain.MCPRoutingDecision.
func (d *MCPDecider) Decide(ctx context.Context, user domain.MCPUser, tool domain.MCPTool, state domain.MCPRateLimitState, req domain.MCPToolRequest) (domain.MCPRoutingDecision, error) {
	payload, err := d.buildPayload(user, tool, state, req)
	if err != nil {
		return domain.MCPRoutingDecision{}, fmt.Errorf("building claude payload: %w", err)
	}

	msg, err := d.client.Messages.New(ctx, anthropic.MessageNewParams{
		Model:     anthropic.Model(d.model),
		MaxTokens: 512,
		System: []anthropic.TextBlockParam{
			{Text: systemPrompt},
		},
		Messages: []anthropic.MessageParam{
			anthropic.NewUserMessage(anthropic.NewTextBlock(string(payload))),
		},
	})
	if err != nil {
		return domain.MCPRoutingDecision{}, fmt.Errorf("calling claude: %w", err)
	}

	if len(msg.Content) == 0 {
		return domain.MCPRoutingDecision{}, fmt.Errorf("claude returned empty response")
	}

	text := msg.Content[0].Text
	var resp claudeDecision
	if err := json.Unmarshal([]byte(text), &resp); err != nil {
		if d.logger != nil {
			d.logger.Error("failed to parse claude response", "raw", text, "error", err)
		}
		return domain.MCPRoutingDecision{}, fmt.Errorf("parsing claude response: %w", err)
	}

	return domain.MCPRoutingDecision{
		Decision:    domain.MCPDecisionKind(resp.Decision),
		ToolName:    resp.ToolName,
		Reason:      resp.Reason,
		UserMessage: resp.UserMessage,
		Metadata: domain.MCPRoutingMetadata{
			CostEstimate:         derefString(resp.Metadata.CostEstimate),
			SuggestedAlternative: derefString(resp.Metadata.SuggestedAlternative),
		},
	}, nil
}

func (d *MCPDecider) buildPayload(user domain.MCPUser, tool domain.MCPTool, state domain.MCPRateLimitState, req domain.MCPToolRequest) ([]byte, error) {
	var orgID *string
	if user.OrgID != "" {
		orgID = &user.OrgID
	}

	tools := make([]toolPayload, 1)
	var rg *string
	if tool.RateGroup != "" {
		rg = &tool.RateGroup
	}
	tools[0] = toolPayload{
		Name:        tool.Name,
		Tier:        string(tool.Tier),
		RateGroup:   rg,
		Description: tool.Description,
	}

	groups := make(map[string]groupPayload, len(state.RateGroups))
	for name, g := range state.RateGroups {
		groups[name] = groupPayload{Limit: g.Limit, Used: g.Used, Remaining: g.Remaining}
	}

	ctx := routeContext{
		Task: "route",
		Context: requestContext{
			User: userPayload{
				ID:        user.ID,
				Tier:      string(user.Tier),
				OrgID:     orgID,
				JWTClaims: user.JWTClaims,
			},
			ToolRegistry: tools,
			RateLimitState: rateLimitPayload{
				UserID:        state.UserID,
				Tier:          string(state.Tier),
				WindowSeconds: state.WindowSeconds,
				Limit:         state.Limit,
				Used:          state.Used,
				Remaining:     state.Remaining,
				ResetAt:       state.ResetAt.UTC().Format("2006-01-02T15:04:05Z"),
				RateGroups:    groups,
			},
			Request: requestPayload{
				ToolName:  req.ToolName,
				Arguments: req.Arguments,
				RequestID: req.RequestID,
			},
		},
	}

	return json.Marshal(ctx)
}

func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
