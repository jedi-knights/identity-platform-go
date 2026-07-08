//go:build acceptance

// This suite is excluded from `task test:unit`/`task test:integration`
// (and from a bare `go test ./...` in this module) by design — it builds
// real service binaries and starts a Docker container, which the fast
// unit/integration loops must not do. Run it via `task test:acceptance`
// or `go test -tags acceptance ./...`.
package acceptance_test

import (
	"context"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/cucumber/godog"

	"github.com/ocrosby/identity-platform-go/test/acceptance/steps"
	"github.com/ocrosby/identity-platform-go/test/acceptance/support"
	_ "github.com/ocrosby/identity-platform-go/test/acceptance/support/allure"
)

// sharedRedis is the one Redis container the whole suite run shares — see
// support.StartSharedRedis's doc comment for why one shared container is
// safe under parallel scenarios. Package-level here is fine because,
// unlike World, it holds no per-scenario mutable state.
var sharedRedis *support.SharedRedis

func TestFeatures(t *testing.T) {
	suite := godog.TestSuite{
		Name: "acceptance",
		TestSuiteInitializer: func(sctx *godog.TestSuiteContext) {
			sctx.BeforeSuite(func() {
				ctx := context.Background()
				r, err := support.StartSharedRedis(ctx)
				if err != nil {
					t.Fatalf("starting shared redis container: %v", err)
				}
				sharedRedis = r
			})
			sctx.AfterSuite(func() {
				if sharedRedis != nil {
					_ = sharedRedis.Stop(context.Background())
				}
			})
		},
		ScenarioInitializer: func(sctx *godog.ScenarioContext) {
			steps.InitializeScenario(sctx, func() string { return sharedRedis.URL })
		},
		Options: &godog.Options{
			Format: format(),
			Paths:  paths(),
			// Strict: false is godog's default and silently treats an
			// undefined/pending step as a pass (confirmed: an undefined
			// step exits 0). That defeats the point of an acceptance
			// suite meant to prove RFC/ADR coverage — a typo'd step
			// pattern would report green forever. Strict makes any
			// undefined, pending, or ambiguous step fail the run.
			Strict:      true,
			TestingT:    t,
			Concurrency: concurrency(),
		},
	}

	if suite.Run() != 0 {
		os.Exit(1)
	}
}

// format reads ACCEPTANCE_FORMAT (defaulting to "pretty", godog's
// human-readable console output) so `task test:acceptance:report` can
// request "allure" — see support/allure's package doc comment — without
// changing the default developer loop's output.
func format() string {
	if v := os.Getenv("ACCEPTANCE_FORMAT"); v != "" {
		return v
	}
	return "pretty"
}

// paths reads ACCEPTANCE_PATHS (comma-separated, defaulting to the whole
// features directory) so a single feature file can be run during
// development, e.g. ACCEPTANCE_PATHS=features/token_revocation.feature —
// this suite has no domain tags to filter by (see any feature file's
// header comment: scenarios tag their own @topology, not a shared
// feature-level tag), so path filtering is the mechanism that actually
// works here.
func paths() []string {
	v := os.Getenv("ACCEPTANCE_PATHS")
	if v == "" {
		return []string{"features"}
	}
	return strings.Split(v, ",")
}

// concurrency reads ACCEPTANCE_CONCURRENCY (defaulting to 1) so `task
// test:acceptance` can run scenarios in parallel — every scenario builds
// its own fresh World (see support.World's doc comment), so this is safe
// at any value.
func concurrency() int {
	v := os.Getenv("ACCEPTANCE_CONCURRENCY")
	if v == "" {
		return 1
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 {
		return 1
	}
	return n
}
