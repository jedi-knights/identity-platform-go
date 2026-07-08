package steps

import (
	"context"
	"io"
	"net/http"
	"strings"

	"github.com/cucumber/godog"

	"github.com/ocrosby/identity-platform-go/test/acceptance/support"
)

func registerBearerTokenSteps(sctx *godog.ScenarioContext, world func() *support.World) {
	sctx.Step(`^the client calls "([^"]*)" on example-resource-service with the access_token$`,
		func(ctx context.Context, methodAndPath string) error {
			w := world()
			return callResourceService(ctx, w, methodAndPath, "Bearer "+w.Vars["access_token"])
		})

	sctx.Step(`^the client calls "([^"]*)" on example-resource-service without an Authorization header$`,
		func(ctx context.Context, methodAndPath string) error {
			return callResourceService(ctx, world(), methodAndPath, "")
		})

	sctx.Step(`^the client calls "([^"]*)" on example-resource-service with a malformed Authorization header$`,
		func(ctx context.Context, methodAndPath string) error {
			return callResourceService(ctx, world(), methodAndPath, "Token some-opaque-value")
		})
}

// callResourceService issues methodAndPath (e.g. "GET /resources") against
// example-resource-service, setting the Authorization header verbatim
// when non-empty, and stores the response for later "Then" assertions.
func callResourceService(ctx context.Context, world *support.World, methodAndPath, authHeader string) error {
	parts := strings.SplitN(methodAndPath, " ", 2)
	method, path := parts[0], parts[1]

	req, err := http.NewRequestWithContext(ctx, method, world.Services["example-resource-service"].BaseURL+path, nil)
	if err != nil {
		return err
	}
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}

	resp, err := world.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	world.LastResponse = resp
	world.LastBody = body
	return nil
}
