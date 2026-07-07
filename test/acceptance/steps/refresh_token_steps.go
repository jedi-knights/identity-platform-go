package steps

import (
	"context"
	"net/url"

	"github.com/cucumber/godog"

	"github.com/ocrosby/identity-platform-go/test/acceptance/support"
)

func registerRefreshTokenSteps(sctx *godog.ScenarioContext, world func() *support.World) {
	sctx.Step(`^the client obtains a token using the client_credentials grant with scope "([^"]*)"$`,
		func(ctx context.Context, scope string) error {
			w := world()
			if err := stepRequestClientCredentialsToken(ctx, w, w.Vars["client_secret"], scope); err != nil {
				return err
			}
			return captureField(w, "refresh_token", "refresh_token")
		})

	sctx.Step(`^the client requests a token using the refresh_token grant$`, func(ctx context.Context) error {
		return stepRequestRefreshToken(ctx, world(), world().Vars["refresh_token"])
	})

	sctx.Step(`^the client requests a token using the refresh_token grant with refresh_token "([^"]*)"$`,
		func(ctx context.Context, refreshToken string) error {
			return stepRequestRefreshToken(ctx, world(), refreshToken)
		})

	sctx.Step(`^the client requests a token using the refresh_token grant with the previous refresh_token again$`,
		func(ctx context.Context) error {
			return stepRequestRefreshToken(ctx, world(), world().Vars["used_refresh_token"])
		})

	sctx.Step(`^the current refresh_token is set aside for a later replay attempt$`, func() error {
		w := world()
		w.Vars["used_refresh_token"] = w.Vars["refresh_token"]
		return nil
	})
}

// stepRequestRefreshToken posts a refresh_token grant request to
// auth-server's /oauth/token using the same client credentials the
// scenario's client was registered with.
func stepRequestRefreshToken(ctx context.Context, world *support.World, refreshToken string) error {
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {world.Vars["client_id"]},
		"client_secret": {world.Vars["client_secret"]},
		"refresh_token": {refreshToken},
	}
	return postToken(ctx, world, form)
}
