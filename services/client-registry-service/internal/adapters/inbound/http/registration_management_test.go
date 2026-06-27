package http_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	inboundhttp "github.com/ocrosby/identity-platform-go/services/client-registry-service/internal/adapters/inbound/http"
	"github.com/ocrosby/identity-platform-go/services/client-registry-service/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/client-registry-service/internal/ports"
)

type fakeManager struct {
	readResp   *domain.RegistrationResponse
	readErr    error
	updateResp *domain.RegistrationResponse
	updateErr  error
	deleteErr  error

	gotClientID string
	gotToken    string
	gotUpdate   domain.RegistrationRequest
}

func (f *fakeManager) ReadRegistration(_ context.Context, clientID, token string) (*domain.RegistrationResponse, error) {
	f.gotClientID = clientID
	f.gotToken = token
	return f.readResp, f.readErr
}

func (f *fakeManager) UpdateRegistration(_ context.Context, clientID, token string, req domain.RegistrationRequest) (*domain.RegistrationResponse, error) {
	f.gotClientID = clientID
	f.gotToken = token
	f.gotUpdate = req
	return f.updateResp, f.updateErr
}

func (f *fakeManager) DeleteRegistration(_ context.Context, clientID, token string) error {
	f.gotClientID = clientID
	f.gotToken = token
	return f.deleteErr
}

var _ ports.ClientRegistrationManager = (*fakeManager)(nil)

func newMgmtHandler(t *testing.T, mgr *fakeManager) *inboundhttp.RegistrationManagementHandler {
	t.Helper()
	return inboundhttp.NewRegistrationManagementHandler(mgr, quietLog())
}

func newMgmtRouter(t *testing.T, mgr *fakeManager) *httptest.Server {
	t.Helper()
	h := newHandler(t, &fakeCreator{}, &fakeReader{}, &fakeValidator{}, &fakeDeleter{})
	router := inboundhttp.NewRouter(h, nil, newMgmtHandler(t, mgr), quietLog())
	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)
	return srv
}

func TestManagement_Get_ReturnsMetadata(t *testing.T) {
	mgr := &fakeManager{readResp: &domain.RegistrationResponse{ClientID: "abc"}}
	srv := newMgmtRouter(t, mgr)

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/register/abc", nil)
	req.Header.Set("Authorization", "Bearer tok-1")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if mgr.gotClientID != "abc" {
		t.Errorf("client_id forwarded = %q", mgr.gotClientID)
	}
	if mgr.gotToken != "tok-1" {
		t.Errorf("token forwarded = %q", mgr.gotToken)
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q", cc)
	}
}

func TestManagement_Get_404OnNotFound(t *testing.T) {
	mgr := &fakeManager{readErr: domain.ErrRegistrationNotFound}
	srv := newMgmtRouter(t, mgr)

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/register/abc", nil)
	req.Header.Set("Authorization", "Bearer tok")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d", resp.StatusCode)
	}
}

func TestManagement_Get_401OnMissingToken(t *testing.T) {
	mgr := &fakeManager{readErr: &domain.RegistrationError{
		Code: domain.RegistrationErrorInvalidToken,
	}}
	srv := newMgmtRouter(t, mgr)

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/register/abc", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d", resp.StatusCode)
	}
}

func TestManagement_Get_500OnUntypedError(t *testing.T) {
	mgr := &fakeManager{readErr: errors.New("boom")}
	srv := newMgmtRouter(t, mgr)

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/register/abc", nil)
	req.Header.Set("Authorization", "Bearer tok")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d", resp.StatusCode)
	}
	var body domain.RegistrationError
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.Code != domain.RegistrationErrorServerError {
		t.Errorf("error = %q", body.Code)
	}
}

func TestManagement_Put_ReturnsUpdatedMetadata(t *testing.T) {
	mgr := &fakeManager{updateResp: &domain.RegistrationResponse{ClientID: "abc", ClientName: "Updated"}}
	srv := newMgmtRouter(t, mgr)

	body, _ := json.Marshal(domain.RegistrationRequest{
		ClientName:   "Updated",
		RedirectURIs: []string{"https://example.com/cb"},
	})
	req, _ := http.NewRequest(http.MethodPut, srv.URL+"/register/abc", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer tok")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PUT: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if mgr.gotUpdate.ClientName != "Updated" {
		t.Errorf("ClientName forwarded = %q", mgr.gotUpdate.ClientName)
	}
}

func TestManagement_Put_400OnValidationError(t *testing.T) {
	mgr := &fakeManager{updateErr: &domain.RegistrationError{
		Code:        domain.RegistrationErrorInvalidRedirectURI,
		Description: "bad scheme",
	}}
	srv := newMgmtRouter(t, mgr)

	req, _ := http.NewRequest(http.MethodPut, srv.URL+"/register/abc", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer tok")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PUT: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d", resp.StatusCode)
	}
}

func TestManagement_Put_400OnInvalidJSON(t *testing.T) {
	mgr := &fakeManager{}
	srv := newMgmtRouter(t, mgr)

	req, _ := http.NewRequest(http.MethodPut, srv.URL+"/register/abc", strings.NewReader(`not json`))
	req.Header.Set("Authorization", "Bearer tok")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PUT: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d", resp.StatusCode)
	}
}

func TestManagement_Delete_204OnSuccess(t *testing.T) {
	mgr := &fakeManager{}
	srv := newMgmtRouter(t, mgr)

	req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/register/abc", nil)
	req.Header.Set("Authorization", "Bearer tok")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("DELETE: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("status = %d", resp.StatusCode)
	}
	if mgr.gotClientID != "abc" || mgr.gotToken != "tok" {
		t.Errorf("forwarded = %q / %q", mgr.gotClientID, mgr.gotToken)
	}
}

func TestManagement_Delete_404OnNotFound(t *testing.T) {
	mgr := &fakeManager{deleteErr: domain.ErrRegistrationNotFound}
	srv := newMgmtRouter(t, mgr)

	req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/register/abc", nil)
	req.Header.Set("Authorization", "Bearer tok")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("DELETE: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d", resp.StatusCode)
	}
}

func TestNewRouter_ManagementRoutes_404WhenHandlerNil(t *testing.T) {
	h := newHandler(t, &fakeCreator{}, &fakeReader{}, &fakeValidator{}, &fakeDeleter{})
	router := inboundhttp.NewRouter(h, nil, nil, quietLog())
	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)

	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		req, _ := http.NewRequest(method, srv.URL+"/register/abc", nil)
		req.Header.Set("Authorization", "Bearer tok")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s: %v", method, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s status = %d", method, resp.StatusCode)
		}
	}
}

func TestNewRegistrationManagementHandler_NilManagerPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected NewRegistrationManagementHandler(nil, ...) to panic")
		}
	}()
	_ = inboundhttp.NewRegistrationManagementHandler(nil, quietLog())
}
