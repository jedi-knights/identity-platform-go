package steps

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/cucumber/godog"

	"github.com/ocrosby/identity-platform-go/test/acceptance/support"
)

func registerRichAuthorizationRequestsSteps(sctx *godog.ScenarioContext, world func() *support.World) {
	sctx.Step(`^the client requests a token using the client_credentials grant with scope "([^"]*)" and authorization_details:$`,
		func(ctx context.Context, scope string, details *godog.DocString) error {
			w := world()
			form := url.Values{
				"grant_type":            {"client_credentials"},
				"client_id":             {w.Vars["client_id"]},
				"client_secret":         {w.Vars["client_secret"]},
				"scope":                 {scope},
				"authorization_details": {details.Content},
			}
			return postToken(ctx, w, form)
		})

	sctx.Step(`^the client starts an authorization_code flow with redirect_uri "([^"]*)", scope "([^"]*)", and authorization_details:$`,
		func(ctx context.Context, redirectURI, scope string, details *godog.DocString) error {
			return stepStartAuthorizeWithRAR(ctx, world(), redirectURI, scope, details.Content)
		})

	sctx.Step(`^the response redirects with error "([^"]*)"$`, func(errCode string) error {
		return stepAssertRedirectError(world(), errCode)
	})

	sctx.Step(`^the response's authorization_details contains a "([^"]*)" entry with "([^"]*)" equal to "([^"]*)"$`,
		func(wantType, field, want string) error {
			return stepAssertAuthorizationDetailsEntry(world(), wantType, field, want)
		})

	sctx.Step(`^the client exchanges the "([^"]*)" for a new access_token with authorization_details:$`,
		func(ctx context.Context, subjectVar string, details *godog.DocString) error {
			w := world()
			form := url.Values{
				"grant_type":            {"urn:ietf:params:oauth:grant-type:token-exchange"},
				"client_id":             {w.Vars["client_id"]},
				"client_secret":         {w.Vars["client_secret"]},
				"subject_token":         {w.Vars[subjectVar]},
				"subject_token_type":    {"urn:ietf:params:oauth:token-type:access_token"},
				"authorization_details": {details.Content},
			}
			return postToken(ctx, w, form)
		})
}

// stepStartAuthorizeWithRAR is stepStartAuthorize (authorization_code_steps.go)
// with an authorization_details query param added — kept as its own function
// rather than adding an optional parameter to the shared helper, since only
// this feature needs it and every other authorization_code_pkce.feature
// caller should stay untouched.
func stepStartAuthorizeWithRAR(ctx context.Context, world *support.World, redirectURI, scope, detailsJSON string) error {
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {world.Vars["client_id"]},
		"redirect_uri":          {redirectURI},
		"scope":                 {scope},
		"state":                 {support.RandomID("state")},
		"code_challenge":        {world.Vars["code_challenge"]},
		"code_challenge_method": {"S256"},
		"authorization_details": {detailsJSON},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		world.Services["auth-server"].BaseURL+"/oauth/authorize?"+q.Encode(), nil)
	if err != nil {
		return err
	}

	noRedirectClient := &http.Client{
		Timeout: world.HTTPClient.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := noRedirectClient.Do(req)
	if err != nil {
		return fmt.Errorf("calling auth-server: %w", err)
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

// stepAssertRedirectError checks the Location header's error query
// parameter without following the redirect — RFC 6749 §4.1.2.1's
// authorize-time error routing sends the client back to its own
// redirect_uri with ?error=... rather than rendering a 4xx body.
func stepAssertRedirectError(world *support.World, want string) error {
	location := world.LastResponse.Header.Get("Location")
	if location == "" {
		return fmt.Errorf("no Location header on last response (status %d) — body: %s", world.LastResponse.StatusCode, world.LastBody)
	}
	parsed, err := url.Parse(location)
	if err != nil {
		return fmt.Errorf("parsing Location header %q: %w", location, err)
	}
	got := parsed.Query().Get("error")
	if got != want {
		return fmt.Errorf("redirect error: want %q, got %q — Location: %s", want, got, location)
	}
	return nil
}

// stepAssertAuthorizationDetailsEntry decodes the last response body's
// authorization_details array (present on token, introspection, and
// authorize-redirect-adjacent responses) and checks that at least one
// entry has the given type and the given field equal to want. Field
// values are compared via fmt.Sprint so both string and array/number
// JSON values can be matched without a type switch at the call site.
func stepAssertAuthorizationDetailsEntry(world *support.World, wantType, field, want string) error {
	var decoded struct {
		AuthorizationDetails []map[string]any `json:"authorization_details"`
	}
	if err := json.Unmarshal(world.LastBody, &decoded); err != nil {
		return fmt.Errorf("decoding response body: %w — body: %s", err, world.LastBody)
	}
	for _, entry := range decoded.AuthorizationDetails {
		if entry["type"] != wantType {
			continue
		}
		if got := fmt.Sprint(entry[field]); got == want {
			return nil
		}
	}
	return fmt.Errorf("no authorization_details entry with type %q and %s=%q found in: %s",
		wantType, field, want, world.LastBody)
}
