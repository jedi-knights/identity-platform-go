// Package steps contains godog step definitions, one file per feature
// area, plus shared infrastructure: scenario.go (World lifecycle),
// topology.go (which service processes each feature needs), and
// common_steps.go (generic response assertions every feature reuses).
// See support.World's doc comment for the isolation guarantees every
// step definition here must uphold: never hardcode a fixture ID, never
// share a World across scenarios.
package steps

import (
	"context"
	"fmt"

	"github.com/cucumber/godog"

	"github.com/ocrosby/identity-platform-go/test/acceptance/support"
)

// InitializeScenario registers every step definition and the Before/After
// hooks that start and stop this scenario's service processes. Godog
// re-invokes this function fresh for every scenario/pickle — including
// under `-c N` concurrency, where each concurrent goroutine gets its own
// call — so the `world` variable closed over below is never shared
// across scenarios; that is what makes godog's parallel runner safe here,
// not anything in this file itself.
//
// redisURL returns the shared suite-wide Redis container's connection
// string, resolved lazily since the container starts in
// TestSuiteInitializer after ScenarioInitializer has already registered
// this callback.
func InitializeScenario(sctx *godog.ScenarioContext, redisURL func() string) {
	var world *support.World
	getWorld := func() *support.World { return world }

	sctx.Before(func(ctx context.Context, sc *godog.Scenario) (context.Context, error) {
		world = support.NewWorld()
		if err := startTopologyForTags(ctx, world, sc, redisURL); err != nil {
			return ctx, fmt.Errorf("starting service topology: %w", err)
		}
		return ctx, nil
	})

	sctx.After(func(ctx context.Context, _ *godog.Scenario, _ error) (context.Context, error) {
		if world != nil {
			world.Close()
		}
		return ctx, nil
	})

	registerCommonSteps(sctx, getWorld)
	registerClientCredentialsSteps(sctx, getWorld)
	registerRefreshTokenSteps(sctx, getWorld)
	registerRevocationSteps(sctx, getWorld)
	registerIntrospectionSteps(sctx, getWorld)
	registerBearerTokenSteps(sctx, getWorld)
}
