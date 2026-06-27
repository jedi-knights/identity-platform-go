package http_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jedi-knights/go-logging/pkg/logging"

	inboundhttp "github.com/ocrosby/identity-platform-go/services/client-registry-service/internal/adapters/inbound/http"
	"github.com/ocrosby/identity-platform-go/services/client-registry-service/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/client-registry-service/internal/ports"
)

type fakeRegistrar struct {
	resp *domain.RegistrationResponse
	err  error

	gotReq domain.RegistrationRequest
}

func (f *fakeRegistrar) Register(_ context.Context, req domain.RegistrationRequest) (*domain.RegistrationResponse, error) {
	f.gotReq = req
	return f.resp, f.err
}

var _ ports.ClientRegistrar = (*fakeRegistrar)(nil)

func quietLog() logging.Logger {
	return logging.New(logging.Config{Level: "error", Format: "text", Environment: "test"})
}

func newRegHandler(t *testing.T, reg *fakeRegistrar) *inboundhttp.RegistrationHandler {
	t.Helper()
	return inboundhttp.NewRegistrationHandler(reg, quietLog())
}

func TestRegistrationHandler_Register_ReturnsCreatedWithBody(t *testing.T) {
	reg := &fakeRegistrar{resp: &domain.RegistrationResponse{
		ClientID:                "abc123",
		ClientIDIssuedAt:        1750000000,
		RegistrationAccessToken: "tok",
		RegistrationClientURI:   "https://clients.example.com/register/abc123",
		ClientName:              "Test",
		RedirectURIs:            []string{"https://example.com/cb"},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: domain.TokenEndpointAuthMethodNone,
	}}
	h := newRegHandler(t, reg)
	body, _ := json.Marshal(domain.RegistrationRequest{
		ClientName:   "Test",
		RedirectURIs: []string{"https://example.com/cb"},
	})
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body))

	h.Register(w, r)

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusCreated)
	}
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "json") {
		t.Errorf("Content-Type = %q", ct)
	}
	if cc := w.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
	if pr := w.Header().Get("Pragma"); pr != "no-cache" {
		t.Errorf("Pragma = %q, want no-cache", pr)
	}

	var got domain.RegistrationResponse
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if got.ClientID != "abc123" {
		t.Errorf("client_id = %q", got.ClientID)
	}
}

func TestRegistrationHandler_Register_ForwardsRequest(t *testing.T) {
	reg := &fakeRegistrar{resp: &domain.RegistrationResponse{ClientID: "abc"}}
	h := newRegHandler(t, reg)
	body, _ := json.Marshal(domain.RegistrationRequest{
		ClientName:              "MCP",
		TokenEndpointAuthMethod: domain.TokenEndpointAuthMethodBasic,
		RedirectURIs:            []string{"https://example.com/cb"},
	})
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body))

	h.Register(w, r)

	if reg.gotReq.ClientName != "MCP" {
		t.Errorf("ClientName = %q", reg.gotReq.ClientName)
	}
	if reg.gotReq.TokenEndpointAuthMethod != domain.TokenEndpointAuthMethodBasic {
		t.Errorf("TokenEndpointAuthMethod = %q", reg.gotReq.TokenEndpointAuthMethod)
	}
}

func TestRegistrationHandler_Register_MapsValidationErrorTo400(t *testing.T) {
	reg := &fakeRegistrar{err: &domain.RegistrationError{
		Code:        domain.RegistrationErrorInvalidRedirectURI,
		Description: "must use https",
	}}
	h := newRegHandler(t, reg)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(`{}`))

	h.Register(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
	var body domain.RegistrationError
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.Code != domain.RegistrationErrorInvalidRedirectURI {
		t.Errorf("error = %q", body.Code)
	}
	if body.Description != "must use https" {
		t.Errorf("error_description = %q", body.Description)
	}
}

func TestRegistrationHandler_Register_MapsServerErrorTo500(t *testing.T) {
	reg := &fakeRegistrar{err: errors.New("database fell over")}
	h := newRegHandler(t, reg)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(`{}`))

	h.Register(w, r)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", w.Code)
	}
	var body domain.RegistrationError
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.Code != domain.RegistrationErrorServerError {
		t.Errorf("error = %q", body.Code)
	}
}

func TestRegistrationHandler_Register_RejectsInvalidJSON(t *testing.T) {
	reg := &fakeRegistrar{}
	h := newRegHandler(t, reg)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(`not json`))

	h.Register(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestRegistrationHandler_Register_RejectsOversizeBody(t *testing.T) {
	reg := &fakeRegistrar{}
	h := newRegHandler(t, reg)
	bigBody := strings.Repeat("x", (1<<20)+100)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/register", io.NopCloser(strings.NewReader(bigBody)))

	h.Register(w, r)

	if w.Code != http.StatusRequestEntityTooLarge && w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 413 or 400 (depends on parser behaviour)", w.Code)
	}
}

func TestNewRegistrationHandler_NilRegistrarPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected NewRegistrationHandler(nil, ...) to panic")
		}
	}()
	_ = inboundhttp.NewRegistrationHandler(nil, quietLog())
}

func TestNewRouter_RegisterRoute_RegisteredWhenHandlerNonNil(t *testing.T) {
	reg := &fakeRegistrar{resp: &domain.RegistrationResponse{ClientID: "abc"}}
	regHandler := newRegHandler(t, reg)
	h := newHandler(t, &fakeCreator{}, &fakeReader{}, &fakeValidator{}, &fakeDeleter{})
	router := inboundhttp.NewRouter(h, regHandler, quietLog())
	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)

	resp, err := http.Post(srv.URL+"/register", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("POST /register: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("status = %d, want 201", resp.StatusCode)
	}
}

func TestNewRouter_RegisterRoute_404WhenHandlerNil(t *testing.T) {
	h := newHandler(t, &fakeCreator{}, &fakeReader{}, &fakeValidator{}, &fakeDeleter{})
	router := inboundhttp.NewRouter(h, nil, quietLog())
	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)

	resp, err := http.Post(srv.URL+"/register", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("POST /register: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404 when DCR disabled", resp.StatusCode)
	}
}
