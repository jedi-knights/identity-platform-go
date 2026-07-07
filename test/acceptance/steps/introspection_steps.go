package steps

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/cucumber/godog"

	"github.com/ocrosby/identity-platform-go/test/acceptance/support"
)

func registerIntrospectionSteps(sctx *godog.ScenarioContext, world func() *support.World) {
	sctx.Step(`^a resource server introspects the access_token via token-introspection-service$`, func(ctx context.Context) error {
		w := world()
		return stepIntrospectViaService(ctx, w, w.Vars["access_token"])
	})

	sctx.Step(`^a resource server introspects "([^"]*)" via token-introspection-service$`, func(ctx context.Context, token string) error {
		return stepIntrospectViaService(ctx, world(), token)
	})

	sctx.Step(`^a resource server introspects the access_token via token-introspection-service without a valid secret$`, func(ctx context.Context) error {
		w := world()
		return stepIntrospectViaServiceWithSecret(ctx, w, w.Vars["access_token"], "wrong-secret")
	})
}

// stepIntrospectViaService posts to token-introspection-service's own
// POST /introspect, authenticated with the pre-shared secret
// startAuthClientRegistryIntrospection configured it with.
func stepIntrospectViaService(ctx context.Context, world *support.World, token string) error {
	return stepIntrospectViaServiceWithSecret(ctx, world, token, introspectionSecret)
}

func stepIntrospectViaServiceWithSecret(ctx context.Context, world *support.World, token, secret string) error {
	form := url.Values{"token": {token}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		world.Services["token-introspection-service"].BaseURL+"/introspect", strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+secret)

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
