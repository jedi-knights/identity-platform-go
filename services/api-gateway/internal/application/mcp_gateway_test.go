package application

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/ocrosby/identity-platform-go/libs/jwtutil"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/domain"
)

// --- manual mocks ---

type mockMCPDecider struct {
	decision domain.MCPRoutingDecision
	err      error
}

func (m *mockMCPDecider) Decide(_ context.Context, _ domain.MCPUser, _ domain.MCPTool, _ domain.MCPRateLimitState, _ domain.MCPToolRequest) (domain.MCPRoutingDecision, error) {
	return m.decision, m.err
}

type mockMCPRateLimiter struct {
	state      domain.MCPRateLimitState
	stateErr   error
	consumeErr error
	consumed   []string // records "userID/rateGroup" pairs
}

func (m *mockMCPRateLimiter) State(_ context.Context, _ string, _ domain.UserTier) (domain.MCPRateLimitState, error) {
	return m.state, m.stateErr
}

func (m *mockMCPRateLimiter) Consume(_ context.Context, userID, rateGroup string) error {
	m.consumed = append(m.consumed, userID+"/"+rateGroup)
	return m.consumeErr
}

type capturingDecider struct {
	fn       func(domain.MCPUser)
	decision domain.MCPRoutingDecision
	err      error
}

func (c *capturingDecider) Decide(_ context.Context, user domain.MCPUser, _ domain.MCPTool, _ domain.MCPRateLimitState, _ domain.MCPToolRequest) (domain.MCPRoutingDecision, error) {
	if c.fn != nil {
		c.fn(user)
	}
	return c.decision, c.err
}

// --- test setup ---

var (
	testSigningKey = []byte("test-secret-key-32-bytes-padding!")
	testJWT        string
)

func TestMain(m *testing.M) {
	claims := jwtutil.NewClaims(jwtutil.ClaimsConfig{
		Issuer:    "test",
		Subject:   "user-1",
		TokenID:   "tok-1",
		ClientID:  "client-abc",
		Scope:     "read",
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	})
	var err error
	testJWT, err = jwtutil.Sign(claims, testSigningKey)
	if err != nil {
		panic("failed to sign test JWT: " + err.Error())
	}
	os.Exit(m.Run())
}

func makeTools() []domain.MCPTool {
	return []domain.MCPTool{
		{Name: "weather", Tier: domain.TierFree, RateGroup: "wx", Description: "weather data", UpstreamURL: "http://wx:8080"},
		{Name: "forecast", Tier: domain.TierSubscriber, RateGroup: "wx", Description: "forecast data", UpstreamURL: "http://forecast:8080"},
	}
}

func makeState(remaining int) domain.MCPRateLimitState {
	return domain.MCPRateLimitState{
		UserID:        "user-1",
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

// --- tests ---

func TestMCPGatewayService_ToolNotFound(t *testing.T) {
	svc := NewMCPGatewayService(
		&mockMCPDecider{},
		&mockMCPRateLimiter{state: makeState(50)},
		makeTools(),
		map[string]string{"client-abc": "free"},
		testSigningKey,
		nil,
	)

	decision, tool, err := svc.Invoke(context.Background(), domain.MCPToolRequest{
		ToolName: "nonexistent",
	}, testJWT)

	if err != nil {
		t.Fatalf("expected no error for tool-not-found, got %v", err)
	}
	if decision.Decision != domain.DecisionDeny {
		t.Errorf("expected deny, got %q", decision.Decision)
	}
	if tool.Name != "" {
		t.Errorf("expected empty tool on deny, got %q", tool.Name)
	}
}

func TestMCPGatewayService_Allow(t *testing.T) {
	decider := &mockMCPDecider{
		decision: domain.MCPRoutingDecision{
			Decision: domain.DecisionAllow,
			ToolName: "weather",
		},
	}
	rl := &mockMCPRateLimiter{state: makeState(50)}

	svc := NewMCPGatewayService(
		decider, rl, makeTools(),
		map[string]string{"client-abc": "free"},
		testSigningKey, nil,
	)

	decision, tool, err := svc.Invoke(context.Background(), domain.MCPToolRequest{
		ToolName: "weather",
	}, testJWT)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Decision != domain.DecisionAllow {
		t.Errorf("expected allow, got %q", decision.Decision)
	}
	if tool.Name != "weather" {
		t.Errorf("expected weather tool, got %q", tool.Name)
	}
	if len(rl.consumed) != 1 || rl.consumed[0] != "user-1/wx" {
		t.Errorf("expected consume called once with user-1/wx, got %v", rl.consumed)
	}
}

func TestMCPGatewayService_Deny(t *testing.T) {
	decider := &mockMCPDecider{
		decision: domain.MCPRoutingDecision{
			Decision:    domain.DecisionDeny,
			UserMessage: "rate limit exceeded",
		},
	}
	rl := &mockMCPRateLimiter{state: makeState(0)}

	svc := NewMCPGatewayService(
		decider, rl, makeTools(),
		map[string]string{"client-abc": "free"},
		testSigningKey, nil,
	)

	decision, tool, err := svc.Invoke(context.Background(), domain.MCPToolRequest{
		ToolName: "weather",
	}, testJWT)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Decision != domain.DecisionDeny {
		t.Errorf("expected deny, got %q", decision.Decision)
	}
	if tool.Name != "" {
		t.Errorf("expected empty tool on deny, got %q", tool.Name)
	}
	if len(rl.consumed) != 0 {
		t.Errorf("Consume should not be called on deny")
	}
}

func TestMCPGatewayService_Redirect(t *testing.T) {
	decider := &mockMCPDecider{
		decision: domain.MCPRoutingDecision{
			Decision: domain.DecisionRedirect,
			ToolName: "weather", // redirect to lower-tier tool
		},
	}
	rl := &mockMCPRateLimiter{state: makeState(50)}

	svc := NewMCPGatewayService(
		decider, rl, makeTools(),
		map[string]string{"client-abc": "free"},
		testSigningKey, nil,
	)

	decision, tool, err := svc.Invoke(context.Background(), domain.MCPToolRequest{
		ToolName: "forecast", // originally requested forecast
	}, testJWT)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Decision != domain.DecisionRedirect {
		t.Errorf("expected redirect, got %q", decision.Decision)
	}
	if tool.Name != "weather" {
		t.Errorf("expected redirect to weather tool, got %q", tool.Name)
	}
}

func TestMCPGatewayService_InvalidJWT(t *testing.T) {
	svc := NewMCPGatewayService(
		&mockMCPDecider{},
		&mockMCPRateLimiter{state: makeState(50)},
		makeTools(),
		map[string]string{},
		testSigningKey,
		nil,
	)

	_, _, err := svc.Invoke(context.Background(), domain.MCPToolRequest{
		ToolName: "weather",
	}, "not.a.jwt")

	if err == nil {
		t.Fatal("expected error for invalid JWT")
	}
	if !errors.Is(err, ErrMCPUnauthorized) {
		t.Errorf("expected ErrMCPUnauthorized, got %v", err)
	}
}

func TestMCPGatewayService_DefaultTierFree(t *testing.T) {
	var capturedUser domain.MCPUser
	decider := &capturingDecider{
		fn:       func(user domain.MCPUser) { capturedUser = user },
		decision: domain.MCPRoutingDecision{Decision: domain.DecisionAllow, ToolName: "weather"},
	}
	rl := &mockMCPRateLimiter{state: makeState(50)}

	svc := NewMCPGatewayService(
		decider, rl, makeTools(),
		map[string]string{}, // no client_tiers → default to free
		testSigningKey, nil,
	)

	_, _, _ = svc.Invoke(context.Background(), domain.MCPToolRequest{ToolName: "weather"}, testJWT)

	if capturedUser.Tier != domain.TierFree {
		t.Errorf("expected free tier default, got %q", capturedUser.Tier)
	}
}
