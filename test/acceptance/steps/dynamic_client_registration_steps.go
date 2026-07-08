package steps

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/cucumber/godog"

	"github.com/ocrosby/identity-platform-go/test/acceptance/support"
)

// dcrArrayFields lists the RFC 7591 §2 registration-request fields whose
// wire type is a JSON array. Every other field in the table is sent as a
// plain string. Comma-separated table cell values split into the array.
var dcrArrayFields = map[string]bool{
	"redirect_uris":  true,
	"grant_types":    true,
	"response_types": true,
	"contacts":       true,
}

func registerDynamicClientRegistrationSteps(sctx *godog.ScenarioContext, world func() *support.World) {
	sctx.Step(`^the client submits a dynamic client registration request:$`, func(ctx context.Context, table *godog.Table) error {
		return stepRegisterDCR(ctx, world(), table)
	})

	sctx.Step(`^the client reads its own registration with its registration_access_token$`, func(ctx context.Context) error {
		w := world()
		return stepGetRegistration(ctx, w, w.Vars["client_id"], w.Vars["registration_access_token"])
	})

	sctx.Step(`^the client reads its own registration without a token$`, func(ctx context.Context) error {
		w := world()
		return stepGetRegistration(ctx, w, w.Vars["client_id"], "")
	})

	sctx.Step(`^the client reads its own registration with an incorrect token$`, func(ctx context.Context) error {
		w := world()
		return stepGetRegistration(ctx, w, w.Vars["client_id"], "not-the-real-token")
	})

	sctx.Step(`^the client updates its own registration with its registration_access_token:$`, func(ctx context.Context, table *godog.Table) error {
		w := world()
		return stepPutRegistration(ctx, w, w.Vars["client_id"], w.Vars["registration_access_token"], table)
	})

	sctx.Step(`^the client deletes its own registration with its registration_access_token$`, func(ctx context.Context) error {
		w := world()
		return stepDeleteRegistration(ctx, w, w.Vars["client_id"], w.Vars["registration_access_token"])
	})
}

// dcrRequestBody builds an RFC 7591 §2 registration-request JSON body from
// a Given step's data table — each row is a (field, value) pair, with
// array-typed fields (see dcrArrayFields) split on comma.
func dcrRequestBody(table *godog.Table) map[string]any {
	body := map[string]any{}
	for _, row := range table.Rows {
		field, value := row.Cells[0].Value, row.Cells[1].Value
		if dcrArrayFields[field] {
			body[field] = strings.Split(value, ",")
			continue
		}
		body[field] = value
	}
	return body
}

// stepRegisterDCR posts to client-registry-service's RFC 7591 POST
// /register and, on success, captures client_id/registration_access_token
// so later steps can exercise the RFC 7592 management endpoints against
// the client this scenario just created.
func stepRegisterDCR(ctx context.Context, world *support.World, table *godog.Table) error {
	payload, err := json.Marshal(dcrRequestBody(table))
	if err != nil {
		return fmt.Errorf("marshalling registration request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		world.Services["client-registry-service"].BaseURL+"/register", strings.NewReader(string(payload)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := world.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("calling client-registry-service: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	world.LastResponse = resp
	world.LastBody = body

	if resp.StatusCode != http.StatusCreated {
		return nil // let the scenario's own "Then" steps assert on the error
	}

	var decoded struct {
		ClientID                string `json:"client_id"`
		RegistrationAccessToken string `json:"registration_access_token"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		return fmt.Errorf("decoding registration response: %w — body: %s", err, body)
	}
	world.Vars["client_id"] = decoded.ClientID
	world.Vars["registration_access_token"] = decoded.RegistrationAccessToken
	return nil
}

// stepGetRegistration calls the RFC 7592 GET /register/{client_id}
// management endpoint. An empty token sends no Authorization header.
func stepGetRegistration(ctx context.Context, world *support.World, clientID, token string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		world.Services["client-registry-service"].BaseURL+"/register/"+clientID, nil)
	if err != nil {
		return err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return doDCRRequest(world, req)
}

// stepPutRegistration calls the RFC 7592 PUT /register/{client_id}
// management endpoint with a full-replacement metadata document built
// from the step's data table.
func stepPutRegistration(ctx context.Context, world *support.World, clientID, token string, table *godog.Table) error {
	payload, err := json.Marshal(dcrRequestBody(table))
	if err != nil {
		return fmt.Errorf("marshalling update request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPut,
		world.Services["client-registry-service"].BaseURL+"/register/"+clientID, strings.NewReader(string(payload)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return doDCRRequest(world, req)
}

// stepDeleteRegistration calls the RFC 7592 DELETE /register/{client_id}
// management endpoint.
func stepDeleteRegistration(ctx context.Context, world *support.World, clientID, token string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete,
		world.Services["client-registry-service"].BaseURL+"/register/"+clientID, nil)
	if err != nil {
		return err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return doDCRRequest(world, req)
}

func doDCRRequest(world *support.World, req *http.Request) error {
	resp, err := world.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("calling client-registry-service: %w", err)
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
