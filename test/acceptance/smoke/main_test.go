//go:build smoke

// This suite validates what the subprocess-based acceptance suite (see
// ../main_test.go) structurally cannot: the real Dockerfile, the real
// docker-compose.yml env wiring, and real container-to-container
// networking. It drives fixed HTTP ports against an already-running
// `docker compose` stack — it does not build binaries, does not start
// containers itself, and does not spawn a World per scenario the way the
// main suite does. Run it via `task test:smoke`, which brings the stack
// up, runs this suite, and tears the stack down — never `go test` in
// isolation, since nothing here starts its own dependencies.
package smoke

import (
	"os"
	"testing"

	"github.com/cucumber/godog"
)

func TestSmoke(t *testing.T) {
	suite := godog.TestSuite{
		Name:                 "smoke",
		ScenarioInitializer:  InitializeScenario,
		TestSuiteInitializer: InitializeTestSuite,
		Options: &godog.Options{
			Format:   "pretty",
			Paths:    []string{"features"},
			Tags:     "@smoke",
			TestingT: t,
			// Serial by design (per the Phase 4 plan) — every scenario
			// shares the same long-lived compose stack rather than each
			// getting a fresh World, so there is no isolation guarantee
			// that would make concurrent scenarios safe.
			Concurrency: 1,
		},
	}

	if suite.Run() != 0 {
		os.Exit(1)
	}
}
