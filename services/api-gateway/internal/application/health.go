package application

import (
	"context"
	"strings"
	"sync"

	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/ports"
)

// HealthAggregator concurrently checks health of all downstream services.
type HealthAggregator struct {
	checker ports.HealthChecker
	routes  []domain.Route
}

// NewHealthAggregator creates a new aggregator.
func NewHealthAggregator(checker ports.HealthChecker, routes []domain.Route) *HealthAggregator {
	return &HealthAggregator{
		checker: checker,
		routes:  routes,
	}
}

// AggregateHealth checks all unique backend URLs concurrently and returns a report.
func (a *HealthAggregator) AggregateHealth(ctx context.Context) ports.HealthReport {
	// Deduplicate backend URLs.
	type backend struct {
		prefix string
		url    string
	}
	seen := make(map[string]bool)
	var backends []backend
	for _, r := range a.routes {
		if !seen[r.Upstream.URL] {
			seen[r.Upstream.URL] = true
			backends = append(backends, backend{prefix: r.Match.PathPrefix, url: r.Upstream.URL})
		}
	}

	type result struct {
		prefix string
		url    string
		err    error
	}

	results := make([]result, len(backends))
	var wg sync.WaitGroup
	for i, b := range backends {
		wg.Add(1)
		go func(idx int, bk backend) {
			defer wg.Done()
			healthURL := strings.TrimRight(bk.url, "/") + "/health"
			err := a.checker.Check(ctx, healthURL)
			results[idx] = result{prefix: bk.prefix, url: bk.url, err: err}
		}(i, b)
	}
	wg.Wait()

	services := make(map[string]ports.ServiceHealth, len(results))
	healthyCount := 0
	for _, r := range results {
		status := "healthy"
		if r.err != nil {
			status = "unhealthy"
		} else {
			healthyCount++
		}
		services[r.prefix] = ports.ServiceHealth{
			Status: status,
			URL:    r.url,
		}
	}

	return ports.HealthReport{
		Status:   overallHealthStatus(healthyCount, len(results)),
		Services: services,
	}
}

// overallHealthStatus derives a simple three-state health string.
func overallHealthStatus(healthyCount, total int) string {
	if healthyCount == 0 {
		return "unhealthy"
	}
	if healthyCount < total {
		return "degraded"
	}
	return "healthy"
}
