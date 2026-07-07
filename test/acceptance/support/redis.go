package support

import (
	"context"
	"fmt"

	"github.com/testcontainers/testcontainers-go/modules/redis"
)

// SharedRedis holds the one Redis container the whole suite run shares.
// Spinning a container per scenario would be slow for no real benefit —
// see RandomID's doc comment for why sharing it is safe under parallel
// scenarios.
type SharedRedis struct {
	URL       string
	container *redis.RedisContainer
}

// StartSharedRedis launches a single redis:7-alpine testcontainer for the
// whole suite run. Call Stop when the suite finishes (see main_test.go's
// BeforeSuite/AfterSuite wiring).
func StartSharedRedis(ctx context.Context) (*SharedRedis, error) {
	container, err := redis.Run(ctx, "redis:7-alpine")
	if err != nil {
		return nil, fmt.Errorf("starting redis container: %w", err)
	}
	url, err := container.ConnectionString(ctx)
	if err != nil {
		return nil, fmt.Errorf("reading redis connection string: %w", err)
	}
	return &SharedRedis{URL: url, container: container}, nil
}

// Stop terminates the shared Redis container.
func (r *SharedRedis) Stop(ctx context.Context) error {
	if r == nil || r.container == nil {
		return nil
	}
	return r.container.Terminate(ctx)
}
