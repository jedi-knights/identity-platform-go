package healthhttp

import (
	"context"
	"fmt"
	"net/http"

	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/ports"
)

var _ ports.HealthChecker = (*Checker)(nil)

// Checker performs HTTP health checks against downstream services.
type Checker struct {
	client *http.Client
}

// NewChecker creates a health checker with the given HTTP client.
func NewChecker(client *http.Client) *Checker {
	return &Checker{client: client}
}

// Check sends a GET request to the given URL and returns an error if the
// service is unhealthy (non-200 response or connection failure).
func (c *Checker) Check(ctx context.Context, url string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("creating health request: %w", err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("health check failed for %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health check returned %d for %s", resp.StatusCode, url)
	}
	return nil
}
