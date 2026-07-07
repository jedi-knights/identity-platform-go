package steps

import (
	"context"
	"fmt"
	"os"
	"strconv"

	"github.com/cucumber/godog"

	"github.com/ocrosby/identity-platform-go/test/acceptance/support"
)

// startTopologyForTags creates this scenario's temp dir and starts
// exactly the service processes its feature file's `@topology:*` tag
// declares — not the full platform — so scenarios stay fast. Add a new
// case here (and tag the corresponding feature file) as new feature
// files need a different service combination.
func startTopologyForTags(ctx context.Context, world *support.World, sc *godog.Scenario, redisURL func() string) error {
	tempDir, err := os.MkdirTemp("", "acceptance-scenario-")
	if err != nil {
		return fmt.Errorf("creating scenario temp dir: %w", err)
	}
	world.TempDir = tempDir

	for _, tag := range sc.Tags {
		switch tag.Name {
		case "@topology:auth-client-registry":
			if err := startAuthAndClientRegistry(ctx, world); err != nil {
				return err
			}
		}
	}
	return nil
}

// startAuthAndClientRegistry builds and starts auth-server and
// client-registry-service for one scenario, wiring auth-server's
// AUTH_CLIENT_REGISTRY_URL at client-registry-service's freshly-allocated
// port.
//
// client-registry-service intentionally uses its in-memory adapter here
// (CLIENT_DATABASE_URL unset) rather than the SQLite adapter from
// services/client-registry-service/internal/adapters/outbound/sqlite —
// that adapter's container.go DSN-scheme dispatch is not on `main` yet at
// the time this feature file was written (it ships in a separate PR).
// In-memory is a fully supported, zero-external-dependency adapter in its
// own right, so this is not a workaround so much as the correct default;
// once the SQLite-dispatch PR lands, a later feature can set
// CLIENT_DATABASE_URL=file:... to exercise that path specifically.
func startAuthAndClientRegistry(ctx context.Context, world *support.World) error {
	clientRegistry, err := startClientRegistryService(ctx)
	if err != nil {
		return err
	}
	world.Services["client-registry-service"] = clientRegistry

	authServer, err := startAuthServer(ctx, clientRegistry.BaseURL)
	if err != nil {
		return err
	}
	world.Services["auth-server"] = authServer
	return nil
}

func startClientRegistryService(ctx context.Context) (*support.RunningService, error) {
	port, err := support.FreePort()
	if err != nil {
		return nil, err
	}
	bin, err := support.BuildBinary("client-registry-service")
	if err != nil {
		return nil, err
	}
	return support.StartService(ctx, "client-registry-service", bin, port, []string{
		"CLIENT_SERVER_PORT=" + strconv.Itoa(port),
	})
}

func startAuthServer(ctx context.Context, clientRegistryURL string) (*support.RunningService, error) {
	port, err := support.FreePort()
	if err != nil {
		return nil, err
	}
	bin, err := support.BuildBinary("auth-server")
	if err != nil {
		return nil, err
	}
	return support.StartService(ctx, "auth-server", bin, port, []string{
		"AUTH_SERVER_PORT=" + strconv.Itoa(port),
		"AUTH_CLIENT_REGISTRY_URL=" + clientRegistryURL,
	})
}
