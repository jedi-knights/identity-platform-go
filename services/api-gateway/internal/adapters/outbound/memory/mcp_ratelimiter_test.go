package memory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/ports"
)

func makeTestConfig() testMCPConfig {
	return testMCPConfig{
		windowSeconds: 60,
		tiers: map[domain.UserTier]tierSpec{
			domain.TierFree:       {limit: 10, groups: map[string]int{"wx": 5}},
			domain.TierSubscriber: {limit: 100, groups: map[string]int{"wx": 20}},
		},
	}
}

type tierSpec struct {
	limit  int
	groups map[string]int
}

type testMCPConfig struct {
	windowSeconds int
	tiers         map[domain.UserTier]tierSpec
}

func newTestMCPRateLimiter(cfg testMCPConfig) *MCPRateLimiter {
	specs := make(map[domain.UserTier]mcpTierSpec, len(cfg.tiers))
	for tier, ts := range cfg.tiers {
		specs[tier] = mcpTierSpec{
			windowSeconds: cfg.windowSeconds,
			limit:         ts.limit,
			groups:        ts.groups,
		}
	}
	return &MCPRateLimiter{
		entries: make(map[string]*mcpEntry),
		tiers:   specs,
	}
}

func TestMCPRateLimiter_NewUser_FullBudget(t *testing.T) {
	rl := newTestMCPRateLimiter(makeTestConfig())
	state, err := rl.State(context.Background(), "u1", domain.TierFree)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if state.Limit != 10 {
		t.Errorf("expected limit 10, got %d", state.Limit)
	}
	if state.Remaining != 10 {
		t.Errorf("expected remaining 10 (full budget), got %d", state.Remaining)
	}
	if state.Used != 0 {
		t.Errorf("expected used 0, got %d", state.Used)
	}
	if _, ok := state.RateGroups["wx"]; !ok {
		t.Error("expected wx group in state")
	}
}

func TestMCPRateLimiter_Consume_DecrementsCounters(t *testing.T) {
	rl := newTestMCPRateLimiter(makeTestConfig())
	ctx := context.Background()

	if err := rl.Consume(ctx, "u1", "wx"); err != nil {
		t.Fatalf("consume error: %v", err)
	}

	state, err := rl.State(ctx, "u1", domain.TierFree)
	if err != nil {
		t.Fatalf("state error: %v", err)
	}
	if state.Remaining != 9 {
		t.Errorf("expected remaining 9, got %d", state.Remaining)
	}
	if state.Used != 1 {
		t.Errorf("expected used 1, got %d", state.Used)
	}
	if state.RateGroups["wx"].Remaining != 4 {
		t.Errorf("expected wx remaining 4, got %d", state.RateGroups["wx"].Remaining)
	}
}

func TestMCPRateLimiter_Consume_RejectsExhausted(t *testing.T) {
	rl := newTestMCPRateLimiter(makeTestConfig())
	ctx := context.Background()

	for i := 0; i < 10; i++ {
		if err := rl.Consume(ctx, "u1", ""); err != nil {
			t.Fatalf("consume %d error: %v", i, err)
		}
	}

	err := rl.Consume(ctx, "u1", "")
	if err == nil {
		t.Fatal("expected error when over limit")
	}
	if !errors.Is(err, ports.ErrRateLimitExceeded) {
		t.Errorf("expected ErrRateLimitExceeded, got %v", err)
	}
}

func TestMCPRateLimiter_WindowReset(t *testing.T) {
	rl := newTestMCPRateLimiter(testMCPConfig{
		windowSeconds: 1, // 1-second window for testing
		tiers: map[domain.UserTier]tierSpec{
			domain.TierFree: {limit: 3},
		},
	})
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		_ = rl.Consume(ctx, "u1", "")
	}

	state, _ := rl.State(ctx, "u1", domain.TierFree)
	if state.Remaining != 0 {
		t.Fatalf("expected 0 remaining before window reset, got %d", state.Remaining)
	}

	time.Sleep(1100 * time.Millisecond)

	state, err := rl.State(ctx, "u1", domain.TierFree)
	if err != nil {
		t.Fatalf("state error: %v", err)
	}
	if state.Remaining != 3 {
		t.Errorf("expected full budget after window reset, got %d remaining", state.Remaining)
	}
}

func TestMCPRateLimiter_GroupConsumeWithoutGlobal(t *testing.T) {
	// consuming with an empty rate group should not decrement group counters
	rl := newTestMCPRateLimiter(makeTestConfig())
	ctx := context.Background()

	_ = rl.Consume(ctx, "u1", "")

	state, _ := rl.State(ctx, "u1", domain.TierFree)
	if state.RateGroups["wx"].Remaining != 5 {
		t.Errorf("expected wx group unchanged at 5, got %d", state.RateGroups["wx"].Remaining)
	}
}
