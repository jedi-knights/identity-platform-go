package steps

import (
	"context"
	"net/url"

	"github.com/cucumber/godog"

	"github.com/ocrosby/identity-platform-go/test/acceptance/support"
)

func registerRevocationSteps(sctx *godog.ScenarioContext, world func() *support.World) {
	sctx.Step(`^the client revokes the access_token$`, func(ctx context.Context) error {
		w := world()
		return stepRevoke(ctx, w, w.Vars["client_id"], w.Vars["client_secret"], w.Vars["access_token"], "")
	})

	sctx.Step(`^the client revokes the access_token with token_type_hint "([^"]*)"$`, func(ctx context.Context, hint string) error {
		w := world()
		return stepRevoke(ctx, w, w.Vars["client_id"], w.Vars["client_secret"], w.Vars["access_token"], hint)
	})

	sctx.Step(`^the client attempts to revoke a token without authenticating$`, func(ctx context.Context) error {
		return stepRevoke(ctx, world(), "", "", "some-token", "")
	})

	sctx.Step(`^the client introspects the access_token$`, func(ctx context.Context) error {
		w := world()
		return stepIntrospect(ctx, w, w.Vars["client_id"], w.Vars["client_secret"], w.Vars["access_token"])
	})
}

// stepRevoke posts to auth-server's /oauth/revoke. clientID/clientSecret
// empty means the request is sent with no client authentication at all,
// to exercise RFC 7009 §2's "callers must authenticate" requirement.
func stepRevoke(ctx context.Context, world *support.World, clientID, clientSecret, token, typeHint string) error {
	form := url.Values{"token": {token}}
	if typeHint != "" {
		form.Set("token_type_hint", typeHint)
	}
	if clientID != "" {
		form.Set("client_id", clientID)
		form.Set("client_secret", clientSecret)
	}
	return postForm(ctx, world, "/oauth/revoke", form)
}

// stepIntrospect posts to auth-server's own /oauth/introspect (RFC 7662)
// — reusing the client_id/client_secret authentication path, since
// AUTH_INTROSPECTION_SECRET is unset in this topology (see
// authenticateIntrospectionCaller's fallback to client-credential auth).
func stepIntrospect(ctx context.Context, world *support.World, clientID, clientSecret, token string) error {
	form := url.Values{
		"token":         {token},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
	}
	return postForm(ctx, world, "/oauth/introspect", form)
}
