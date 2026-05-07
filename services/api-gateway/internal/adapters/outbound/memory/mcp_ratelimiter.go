package memory

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/config"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/ports"
)

// mcpTierSpec holds the rate-limit configuration for one user tier.
type mcpTierSpec struct {
	windowSeconds int
	limit         int
	groups        map[string]int // rate group name → per-window limit
}

// mcpEntry tracks per-user consumption within the current window.
type mcpEntry struct {
	windowStart  time.Time
	used         int
	maxLimit     int // stored so Consume can check without re-looking up the tier
	tier         domain.UserTier
	groupUsed    map[string]int
	windowLength time.Duration
}

func (e *mcpEntry) resetIfExpired(now time.Time) {
	if now.Sub(e.windowStart) >= e.windowLength {
		e.windowStart = now
		e.used = 0
		for k := range e.groupUsed {
			e.groupUsed[k] = 0
		}
	}
}

// MCPRateLimiter is the in-memory implementation of ports.MCPRateLimiter.
// Each user's consumption is tracked in a sliding window keyed by user ID.
// This adapter is the swap point for a Redis-backed implementation in production
// deployments — replace it when horizontal scaling is required.
type MCPRateLimiter struct {
	mu      sync.Mutex
	entries map[string]*mcpEntry
	tiers   map[domain.UserTier]mcpTierSpec
}

// Compile-time check: MCPRateLimiter must satisfy ports.MCPRateLimiter.
var _ ports.MCPRateLimiter = (*MCPRateLimiter)(nil)

// NewMCPRateLimiter builds an MCPRateLimiter from the gateway MCP config and
// starts a background eviction goroutine that exits when ctx is cancelled.
func NewMCPRateLimiter(ctx context.Context, cfg config.MCPConfig) *MCPRateLimiter {
	specs := buildTierSpecs(cfg)
	rl := &MCPRateLimiter{
		entries: make(map[string]*mcpEntry),
		tiers:   specs,
	}
	go rl.evictLoop(ctx)
	return rl
}

// State returns a read-only snapshot of the user's current rate-limit counters.
// It initialises the entry if this is the user's first request in the window.
// State never mutates consumed counters.
func (rl *MCPRateLimiter) State(_ context.Context, userID string, tier domain.UserTier) (domain.MCPRateLimitState, error) {
	spec := rl.specFor(tier)
	now := time.Now()

	rl.mu.Lock()
	e := rl.ensureEntry(userID, spec, tier, now)
	e.resetIfExpired(now)
	used := e.used
	groupUsed := copyGroupUsed(e.groupUsed)
	windowStart := e.windowStart
	rl.mu.Unlock()

	remaining := spec.limit - used
	if remaining < 0 {
		remaining = 0
	}

	groups := make(map[string]domain.MCPGroupState, len(spec.groups))
	for name, limit := range spec.groups {
		gu := groupUsed[name]
		gr := limit - gu
		if gr < 0 {
			gr = 0
		}
		groups[name] = domain.MCPGroupState{
			Limit:     limit,
			Used:      gu,
			Remaining: gr,
		}
	}

	return domain.MCPRateLimitState{
		UserID:        userID,
		Tier:          tier,
		WindowSeconds: spec.windowSeconds,
		Limit:         spec.limit,
		Used:          used,
		Remaining:     remaining,
		ResetAt:       windowStart.Add(time.Duration(spec.windowSeconds) * time.Second),
		RateGroups:    groups,
	}, nil
}

// Consume atomically increments the user's consumed count. It returns
// ports.ErrRateLimitExceeded when consumption would exceed the limit,
// protecting against TOCTOU races between State and Consume.
func (rl *MCPRateLimiter) Consume(_ context.Context, userID, rateGroup string) error {
	now := time.Now()
	rl.mu.Lock()
	defer rl.mu.Unlock()

	// The tier is stored on the entry when State is called. If no entry exists yet
	// (e.g. in tests or unusual call patterns), default to free to avoid over-granting.
	e, ok := rl.entries[userID]
	if !ok {
		spec := rl.specFor(domain.TierFree)
		e = rl.createEntry(userID, spec, domain.TierFree, now)
	}
	e.resetIfExpired(now)

	// Determine the limit from the tier spec this entry was created under.
	// We store the spec on the entry to avoid needing the tier here.
	limit := e.maxLimit
	if e.used >= limit {
		return fmt.Errorf("%w: user %q has used %d/%d requests", ports.ErrRateLimitExceeded, userID, e.used, limit)
	}

	e.used++

	if rateGroup != "" {
		e.groupUsed[rateGroup]++
	}

	return nil
}

// ensureEntry returns the existing entry for userID or creates a fresh one.
// Caller must hold mu.
func (rl *MCPRateLimiter) ensureEntry(userID string, spec mcpTierSpec, tier domain.UserTier, now time.Time) *mcpEntry {
	if e, ok := rl.entries[userID]; ok {
		return e
	}
	return rl.createEntry(userID, spec, tier, now)
}

// createEntry creates and stores a new entry. Caller must hold mu.
func (rl *MCPRateLimiter) createEntry(userID string, spec mcpTierSpec, tier domain.UserTier, now time.Time) *mcpEntry {
	groups := make(map[string]int, len(spec.groups))
	for name := range spec.groups {
		groups[name] = 0
	}
	e := &mcpEntry{
		windowStart:  now,
		tier:         tier,
		maxLimit:     spec.limit,
		groupUsed:    groups,
		windowLength: time.Duration(spec.windowSeconds) * time.Second,
	}
	rl.entries[userID] = e
	return e
}

// specFor returns the tier spec for the given tier, falling back to free
// if the tier is not configured.
func (rl *MCPRateLimiter) specFor(tier domain.UserTier) mcpTierSpec {
	if s, ok := rl.tiers[tier]; ok {
		return s
	}
	if s, ok := rl.tiers[domain.TierFree]; ok {
		return s
	}
	return mcpTierSpec{windowSeconds: 60, limit: 10}
}

func (rl *MCPRateLimiter) evictLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			rl.evictStale(now)
		}
	}
}

func (rl *MCPRateLimiter) evictStale(now time.Time) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	for id, e := range rl.entries {
		// Evict entries whose window expired more than 2× the window ago.
		if now.Sub(e.windowStart) > 2*e.windowLength {
			delete(rl.entries, id)
		}
	}
}

func buildTierSpecs(cfg config.MCPConfig) map[domain.UserTier]mcpTierSpec {
	specs := make(map[domain.UserTier]mcpTierSpec, len(cfg.RateLimits))
	for tier, rc := range cfg.RateLimits {
		groups := make(map[string]int, len(rc.Groups))
		for name, gc := range rc.Groups {
			groups[name] = gc.Limit
		}
		specs[domain.UserTier(tier)] = mcpTierSpec{
			windowSeconds: rc.WindowSeconds,
			limit:         rc.Limit,
			groups:        groups,
		}
	}
	return specs
}

func copyGroupUsed(src map[string]int) map[string]int {
	dst := make(map[string]int, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}
