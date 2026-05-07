package static

import (
	"context"
	"testing"
	"time"

	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/domain"
)

var (
	toolWeather  = domain.MCPTool{Name: "weather", Tier: domain.TierFree, RateGroup: "wx", UpstreamURL: "http://wx:8080"}
	toolForecast = domain.MCPTool{Name: "forecast", Tier: domain.TierSubscriber, RateGroup: "wx", UpstreamURL: "http://forecast:8080"}
	toolPremium  = domain.MCPTool{Name: "analytics", Tier: domain.TierPremium, RateGroup: "", UpstreamURL: "http://analytics:8080"}
)

func freeUser() domain.MCPUser { return domain.MCPUser{ID: "u1", Tier: domain.TierFree} }
func subUser() domain.MCPUser  { return domain.MCPUser{ID: "u2", Tier: domain.TierSubscriber} }

func fullState(remaining int) domain.MCPRateLimitState {
	return domain.MCPRateLimitState{
		UserID:        "u1",
		Tier:          domain.TierFree,
		WindowSeconds: 60,
		Limit:         100,
		Used:          100 - remaining,
		Remaining:     remaining,
		ResetAt:       time.Now().Add(30 * time.Second),
		RateGroups: map[string]domain.MCPGroupState{
			"wx": {Limit: 10, Used: 3, Remaining: 7},
		},
	}
}

func groupExhaustedState() domain.MCPRateLimitState {
	s := fullState(50)
	s.RateGroups["wx"] = domain.MCPGroupState{Limit: 10, Used: 10, Remaining: 0}
	return s
}

func TestMCPStaticDecider_Allow(t *testing.T) {
	d := NewMCPStaticDecider([]domain.MCPTool{toolWeather, toolForecast, toolPremium})
	decision, err := d.Decide(context.Background(), freeUser(), toolWeather, fullState(50), domain.MCPToolRequest{ToolName: "weather"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Decision != domain.DecisionAllow {
		t.Errorf("expected allow, got %q (reason: %s)", decision.Decision, decision.Reason)
	}
}

func TestMCPStaticDecider_InsufficientTier_Redirect(t *testing.T) {
	// free user requesting subscriber tool — lower-tier alternative (weather) exists in same rate group
	d := NewMCPStaticDecider([]domain.MCPTool{toolWeather, toolForecast})
	decision, err := d.Decide(context.Background(), freeUser(), toolForecast, fullState(50), domain.MCPToolRequest{ToolName: "forecast"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Decision != domain.DecisionRedirect {
		t.Errorf("expected redirect, got %q", decision.Decision)
	}
	if decision.ToolName != "weather" {
		t.Errorf("expected redirect to weather, got %q", decision.ToolName)
	}
}

func TestMCPStaticDecider_InsufficientTier_Deny_NoAlternative(t *testing.T) {
	// free user requesting premium tool with no rate group (no alternative possible)
	d := NewMCPStaticDecider([]domain.MCPTool{toolWeather, toolPremium})
	decision, err := d.Decide(context.Background(), freeUser(), toolPremium, fullState(50), domain.MCPToolRequest{ToolName: "analytics"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Decision != domain.DecisionDeny {
		t.Errorf("expected deny, got %q", decision.Decision)
	}
}

func TestMCPStaticDecider_RateLimitExhausted(t *testing.T) {
	d := NewMCPStaticDecider([]domain.MCPTool{toolWeather})
	decision, err := d.Decide(context.Background(), freeUser(), toolWeather, fullState(0), domain.MCPToolRequest{ToolName: "weather"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Decision != domain.DecisionDeny {
		t.Errorf("expected deny on exhausted global limit, got %q", decision.Decision)
	}
}

func TestMCPStaticDecider_GroupRateLimitExhausted(t *testing.T) {
	d := NewMCPStaticDecider([]domain.MCPTool{toolWeather})
	decision, err := d.Decide(context.Background(), freeUser(), toolWeather, groupExhaustedState(), domain.MCPToolRequest{ToolName: "weather"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Decision != domain.DecisionDeny {
		t.Errorf("expected deny on exhausted group limit, got %q", decision.Decision)
	}
}

func TestMCPStaticDecider_FreeUserLowBudget_AllowWithSuggestion(t *testing.T) {
	// 9 remaining out of 100 = 9% < 10% threshold
	state := fullState(9)
	d := NewMCPStaticDecider([]domain.MCPTool{toolWeather})
	decision, err := d.Decide(context.Background(), freeUser(), toolWeather, state, domain.MCPToolRequest{ToolName: "weather"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Decision != domain.DecisionAllow {
		t.Errorf("expected allow with upgrade suggestion, got %q", decision.Decision)
	}
	if decision.Metadata.SuggestedAlternative == "" && decision.UserMessage == "" {
		t.Error("expected upgrade suggestion when free user is below 10% budget")
	}
}

func TestMCPStaticDecider_SubscriberCanAccessFreeToolDirectly(t *testing.T) {
	d := NewMCPStaticDecider([]domain.MCPTool{toolWeather, toolForecast})
	state := fullState(50)
	state.Tier = domain.TierSubscriber
	decision, err := d.Decide(context.Background(), subUser(), toolWeather, state, domain.MCPToolRequest{ToolName: "weather"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Decision != domain.DecisionAllow {
		t.Errorf("expected allow for subscriber accessing free tool, got %q", decision.Decision)
	}
}
