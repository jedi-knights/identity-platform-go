package ports

import (
	"context"
)

// HealthAggregator checks all downstream services and returns aggregate status.
type HealthAggregator interface {
	AggregateHealth(ctx context.Context) HealthReport
}

// HealthReport contains the aggregate health status.
type HealthReport struct {
	Status   string                   `json:"status"`
	Services map[string]ServiceHealth `json:"services"`
}

// ServiceHealth represents a single downstream service's health.
type ServiceHealth struct {
	Status string `json:"status"`
	URL    string `json:"url"`
}

// HealthChecker checks the health of a single downstream service.
type HealthChecker interface {
	Check(ctx context.Context, url string) error
}

// RateLimiter determines whether a request from a given key should be allowed.
type RateLimiter interface {
	Allow(key string) bool
}
