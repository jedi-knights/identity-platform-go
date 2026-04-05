package http_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	apperrors "github.com/ocrosby/identity-platform-go/libs/errors"
	"github.com/ocrosby/identity-platform-go/libs/logging"
	inboundhttp "github.com/ocrosby/identity-platform-go/services/client-registry-service/internal/adapters/inbound/http"
	"github.com/ocrosby/identity-platform-go/services/client-registry-service/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/client-registry-service/internal/ports"
)

// --- fakes ---

type fakeCreator struct {
	resp *domain.CreateClientResponse
	err  error
}

func (f *fakeCreator) CreateClient(_ context.Context, _ domain.CreateClientRequest) (*domain.CreateClientResponse, error) {
	return f.resp, f.err
}

type fakeReader struct {
	getResp  *domain.GetClientResponse
	getErr   error
	listResp []*domain.GetClientResponse
	listErr  error
}

func (f *fakeReader) GetClient(_ context.Context, _ string) (*domain.GetClientResponse, error) {
	return f.getResp, f.getErr
}

func (f *fakeReader) ListClients(_ context.Context) ([]*domain.GetClientResponse, error) {
	return f.listResp, f.listErr
}

type fakeValidator struct {
	resp *domain.ValidateClientResponse
	err  error
}

func (f *fakeValidator) ValidateClient(_ context.Context, _ domain.ValidateClientRequest) (*domain.ValidateClientResponse, error) {
	return f.resp, f.err
}

type fakeDeleter struct {
	err error
}

func (f *fakeDeleter) DeleteClient(_ context.Context, _ string) error {
	return f.err
}

// Compile-time checks: fakes must satisfy the port interfaces they stand in for.
var (
	_ ports.ClientCreator   = (*fakeCreator)(nil)
	_ ports.ClientReader    = (*fakeReader)(nil)
	_ ports.ClientValidator = (*fakeValidator)(nil)
	_ ports.ClientDeleter   = (*fakeDeleter)(nil)
)

// plainError is a non-AppError error used to exercise the generic 500 path.
type plainError struct{ msg string }

func (e *plainError) Error() string { return e.msg }

func newHandler(t *testing.T, creator *fakeCreator, reader *fakeReader, validator *fakeValidator, deleter *fakeDeleter) *inboundhttp.Handler {
	t.Helper()
	logger := logging.NewLogger(logging.Config{Level: "error", Format: "text", Environment: "test"})
	return inboundhttp.NewHandler(creator, reader, validator, deleter, logger)
}

// --- CreateClient ---

func TestCreateClient_Returns201WithLocation(t *testing.T) {
	h := newHandler(t,
		&fakeCreator{resp: &domain.CreateClientResponse{ClientID: "abc", Name: "App"}},
		&fakeReader{}, &fakeValidator{}, &fakeDeleter{},
	)
	body, _ := json.Marshal(domain.CreateClientRequest{Name: "App", GrantTypes: []string{"client_credentials"}})
	req := httptest.NewRequest(http.MethodPost, "/clients", bytes.NewReader(body))
	w := httptest.NewRecorder()

	h.CreateClient(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("got status %d, want 201", w.Code)
	}
	if want := "/clients/abc"; w.Header().Get("Location") != want {
		t.Errorf("Location = %q, want %q", w.Header().Get("Location"), want)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	var resp domain.CreateClientResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if resp.ClientID != "abc" {
		t.Errorf("body client_id = %q, want %q", resp.ClientID, "abc")
	}
}

func TestCreateClient_InvalidJSON_Returns400(t *testing.T) {
	h := newHandler(t, &fakeCreator{}, &fakeReader{}, &fakeValidator{}, &fakeDeleter{})
	req := httptest.NewRequest(http.MethodPost, "/clients", bytes.NewReader([]byte("bad")))
	w := httptest.NewRecorder()

	h.CreateClient(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("got status %d, want 400", w.Code)
	}
}

// TestCreateClient_BodyTooLarge_Returns413 verifies that a body exceeding the
// 1 MB limit is rejected with 413, not 400. The body must be a valid JSON
// string so the decoder reads past the 1 MB boundary before MaxBytesReader
// triggers; a body of non-JSON bytes would fail with a SyntaxError first.
func TestCreateClient_BodyTooLarge_Returns413(t *testing.T) {
	h := newHandler(t, &fakeCreator{}, &fakeReader{}, &fakeValidator{}, &fakeDeleter{})
	// Wrap a 2 MB string value so the decoder crosses the 1 MB MaxBytesReader limit.
	prefix := []byte(`{"name":"`)
	suffix := []byte(`"}`)
	value := bytes.Repeat([]byte("a"), 2<<20)
	body := append(append(prefix, value...), suffix...)
	req := httptest.NewRequest(http.MethodPost, "/clients", bytes.NewReader(body))
	w := httptest.NewRecorder()

	h.CreateClient(w, req)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("got status %d, want 413", w.Code)
	}
}

func TestCreateClient_ValidationError_Returns400(t *testing.T) {
	h := newHandler(t,
		&fakeCreator{err: apperrors.New(apperrors.ErrCodeBadRequest, "name is required")},
		&fakeReader{}, &fakeValidator{}, &fakeDeleter{},
	)
	body, _ := json.Marshal(domain.CreateClientRequest{})
	req := httptest.NewRequest(http.MethodPost, "/clients", bytes.NewReader(body))
	w := httptest.NewRecorder()

	h.CreateClient(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("got status %d, want 400", w.Code)
	}
}

func TestCreateClient_InternalError_Returns500(t *testing.T) {
	h := newHandler(t,
		&fakeCreator{err: &plainError{"unexpected db failure"}},
		&fakeReader{}, &fakeValidator{}, &fakeDeleter{},
	)
	body, _ := json.Marshal(domain.CreateClientRequest{Name: "App", GrantTypes: []string{"cc"}})
	req := httptest.NewRequest(http.MethodPost, "/clients", bytes.NewReader(body))
	w := httptest.NewRecorder()

	h.CreateClient(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("got status %d, want 500", w.Code)
	}
}

// --- ListClients ---

func TestListClients_Success_Returns200(t *testing.T) {
	h := newHandler(t,
		&fakeCreator{},
		&fakeReader{listResp: []*domain.GetClientResponse{
			{ClientID: "c1", Name: "App"},
		}},
		&fakeValidator{}, &fakeDeleter{},
	)
	req := httptest.NewRequest(http.MethodGet, "/clients", nil)
	w := httptest.NewRecorder()

	h.ListClients(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("got status %d, want 200", w.Code)
	}
}

// TestListClients_EmptyCollection_ReturnsEmptyArray verifies that an empty
// repository returns [] (not null) so JSON clients don't need nil-checks.
func TestListClients_EmptyCollection_ReturnsEmptyArray(t *testing.T) {
	h := newHandler(t,
		&fakeCreator{},
		&fakeReader{listResp: nil}, // nil slice from service
		&fakeValidator{}, &fakeDeleter{},
	)
	req := httptest.NewRequest(http.MethodGet, "/clients", nil)
	w := httptest.NewRecorder()

	h.ListClients(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("got status %d, want 200", w.Code)
	}
	var body []any
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body == nil {
		t.Error("expected [] not null for empty collection")
	}
}

func TestListClients_ServiceError_Returns500(t *testing.T) {
	h := newHandler(t,
		&fakeCreator{},
		&fakeReader{listErr: fmt.Errorf("db exploded")},
		&fakeValidator{}, &fakeDeleter{},
	)
	req := httptest.NewRequest(http.MethodGet, "/clients", nil)
	w := httptest.NewRecorder()

	h.ListClients(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("got status %d, want 500", w.Code)
	}
}

// --- GetClient ---

func TestGetClient_NotFound_Returns404(t *testing.T) {
	h := newHandler(t,
		&fakeCreator{},
		&fakeReader{getErr: apperrors.New(apperrors.ErrCodeNotFound, "client not found")},
		&fakeValidator{}, &fakeDeleter{},
	)
	req := httptest.NewRequest(http.MethodGet, "/clients/missing", nil)
	req.SetPathValue("id", "missing")
	w := httptest.NewRecorder()

	h.GetClient(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("got status %d, want 404", w.Code)
	}
}

func TestGetClient_Success_Returns200(t *testing.T) {
	h := newHandler(t,
		&fakeCreator{},
		&fakeReader{getResp: &domain.GetClientResponse{ClientID: "c1", Name: "App", Active: true}},
		&fakeValidator{}, &fakeDeleter{},
	)
	req := httptest.NewRequest(http.MethodGet, "/clients/c1", nil)
	req.SetPathValue("id", "c1")
	w := httptest.NewRecorder()

	h.GetClient(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("got status %d, want 200", w.Code)
	}
	var resp domain.GetClientResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if resp.ClientID != "c1" {
		t.Errorf("got client_id %q, want %q", resp.ClientID, "c1")
	}
}

func TestGetClient_MissingID_Returns400(t *testing.T) {
	h := newHandler(t, &fakeCreator{}, &fakeReader{}, &fakeValidator{}, &fakeDeleter{})
	req := httptest.NewRequest(http.MethodGet, "/clients/", nil)
	w := httptest.NewRecorder()

	h.GetClient(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("got status %d, want 400", w.Code)
	}
}

func TestGetClient_InternalError_Returns500(t *testing.T) {
	h := newHandler(t,
		&fakeCreator{},
		&fakeReader{getErr: &plainError{"unexpected"}},
		&fakeValidator{}, &fakeDeleter{},
	)
	req := httptest.NewRequest(http.MethodGet, "/clients/c1", nil)
	req.SetPathValue("id", "c1")
	w := httptest.NewRecorder()

	h.GetClient(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("got status %d, want 500", w.Code)
	}
}

// --- DeleteClient ---

// TestDeleteClient_NotFound_Returns204 verifies that DELETE is idempotent:
// deleting an already-absent resource returns 204, not 404.
func TestDeleteClient_NotFound_Returns204(t *testing.T) {
	h := newHandler(t,
		&fakeCreator{}, &fakeReader{}, &fakeValidator{},
		&fakeDeleter{err: apperrors.New(apperrors.ErrCodeNotFound, "client not found")},
	)
	req := httptest.NewRequest(http.MethodDelete, "/clients/missing", nil)
	req.SetPathValue("id", "missing")
	w := httptest.NewRecorder()

	h.DeleteClient(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("got status %d, want 204 (DELETE must be idempotent)", w.Code)
	}
}

func TestDeleteClient_Success_Returns204(t *testing.T) {
	h := newHandler(t, &fakeCreator{}, &fakeReader{}, &fakeValidator{}, &fakeDeleter{})
	req := httptest.NewRequest(http.MethodDelete, "/clients/c1", nil)
	req.SetPathValue("id", "c1")
	w := httptest.NewRecorder()

	h.DeleteClient(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("got status %d, want 204", w.Code)
	}
	if w.Body.Len() != 0 {
		t.Errorf("204 response must have empty body, got %q", w.Body.String())
	}
}

func TestDeleteClient_MissingID_Returns400(t *testing.T) {
	h := newHandler(t, &fakeCreator{}, &fakeReader{}, &fakeValidator{}, &fakeDeleter{})
	req := httptest.NewRequest(http.MethodDelete, "/clients/", nil)
	w := httptest.NewRecorder()

	h.DeleteClient(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("got status %d, want 400", w.Code)
	}
}

func TestDeleteClient_InternalError_Returns500(t *testing.T) {
	h := newHandler(t,
		&fakeCreator{}, &fakeReader{}, &fakeValidator{},
		&fakeDeleter{err: &plainError{"unexpected"}},
	)
	req := httptest.NewRequest(http.MethodDelete, "/clients/c1", nil)
	req.SetPathValue("id", "c1")
	w := httptest.NewRecorder()

	h.DeleteClient(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("got status %d, want 500", w.Code)
	}
}

// --- ValidateClient ---

func TestValidateClient_EmptyClientID_Returns400(t *testing.T) {
	h := newHandler(t, &fakeCreator{}, &fakeReader{}, &fakeValidator{}, &fakeDeleter{})
	body, _ := json.Marshal(domain.ValidateClientRequest{ClientID: "", ClientSecret: "s"})
	req := httptest.NewRequest(http.MethodPost, "/clients/validate", bytes.NewReader(body))
	w := httptest.NewRecorder()

	h.ValidateClient(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("got status %d, want 400", w.Code)
	}
}

func TestValidateClient_InvalidJSON_Returns400(t *testing.T) {
	h := newHandler(t, &fakeCreator{}, &fakeReader{}, &fakeValidator{}, &fakeDeleter{})
	req := httptest.NewRequest(http.MethodPost, "/clients/validate", bytes.NewReader([]byte("bad")))
	w := httptest.NewRecorder()

	h.ValidateClient(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("got status %d, want 400", w.Code)
	}
}

// TestValidateClient_BodyTooLarge_Returns413 verifies that a body exceeding
// the 1 MB limit is rejected with 413, not 400. See TestCreateClient_BodyTooLarge_Returns413
// for why the body must contain a valid JSON string rather than raw bytes.
func TestValidateClient_BodyTooLarge_Returns413(t *testing.T) {
	h := newHandler(t, &fakeCreator{}, &fakeReader{}, &fakeValidator{}, &fakeDeleter{})
	prefix := []byte(`{"client_id":"`)
	suffix := []byte(`"}`)
	value := bytes.Repeat([]byte("a"), 2<<20)
	body := append(append(prefix, value...), suffix...)
	req := httptest.NewRequest(http.MethodPost, "/clients/validate", bytes.NewReader(body))
	w := httptest.NewRecorder()

	h.ValidateClient(w, req)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("got status %d, want 413", w.Code)
	}
}

func TestValidateClient_Valid_Returns200(t *testing.T) {
	h := newHandler(t,
		&fakeCreator{}, &fakeReader{},
		&fakeValidator{resp: &domain.ValidateClientResponse{Valid: true}},
		&fakeDeleter{},
	)
	body, _ := json.Marshal(domain.ValidateClientRequest{ClientID: "c1", ClientSecret: "s"})
	req := httptest.NewRequest(http.MethodPost, "/clients/validate", bytes.NewReader(body))
	w := httptest.NewRecorder()

	h.ValidateClient(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("got status %d, want 200", w.Code)
	}
	var resp domain.ValidateClientResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if !resp.Valid {
		t.Error("expected valid=true in response body")
	}
}

// TestValidateClient_InvalidCredentials_Returns401 verifies that the handler
// returns 401 (not 200 with valid=false) when credentials are rejected.
// Hiding auth failures in a 200 body violates REST conventions.
func TestValidateClient_InvalidCredentials_Returns401(t *testing.T) {
	h := newHandler(t,
		&fakeCreator{}, &fakeReader{},
		&fakeValidator{resp: &domain.ValidateClientResponse{Valid: false}},
		&fakeDeleter{},
	)
	body, _ := json.Marshal(domain.ValidateClientRequest{ClientID: "c1", ClientSecret: "wrong"})
	req := httptest.NewRequest(http.MethodPost, "/clients/validate", bytes.NewReader(body))
	w := httptest.NewRecorder()

	h.ValidateClient(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("got status %d, want 401", w.Code)
	}
	if wwwAuth := w.Header().Get("WWW-Authenticate"); wwwAuth == "" {
		t.Error("expected WWW-Authenticate header on 401 response")
	}
}

// TestValidateClient_EmptySecret_Returns400 verifies that the handler rejects
// requests with a missing client_secret at the HTTP layer.
func TestValidateClient_EmptySecret_Returns400(t *testing.T) {
	h := newHandler(t, &fakeCreator{}, &fakeReader{}, &fakeValidator{}, &fakeDeleter{})
	body, _ := json.Marshal(domain.ValidateClientRequest{ClientID: "c1", ClientSecret: ""})
	req := httptest.NewRequest(http.MethodPost, "/clients/validate", bytes.NewReader(body))
	w := httptest.NewRecorder()

	h.ValidateClient(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("got status %d, want 400", w.Code)
	}
}

// TestValidateClient_AppError propagates the structured status code (not 500).
func TestValidateClient_AppError_Returns400(t *testing.T) {
	h := newHandler(t,
		&fakeCreator{}, &fakeReader{},
		&fakeValidator{err: apperrors.New(apperrors.ErrCodeBadRequest, "malformed credentials")},
		&fakeDeleter{},
	)
	body, _ := json.Marshal(domain.ValidateClientRequest{ClientID: "c1", ClientSecret: "s"})
	req := httptest.NewRequest(http.MethodPost, "/clients/validate", bytes.NewReader(body))
	w := httptest.NewRecorder()

	h.ValidateClient(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("got status %d, want 400", w.Code)
	}
}

func TestValidateClient_InternalError_Returns500(t *testing.T) {
	h := newHandler(t,
		&fakeCreator{}, &fakeReader{},
		&fakeValidator{err: &plainError{"unexpected"}},
		&fakeDeleter{},
	)
	body, _ := json.Marshal(domain.ValidateClientRequest{ClientID: "c1", ClientSecret: "s"})
	req := httptest.NewRequest(http.MethodPost, "/clients/validate", bytes.NewReader(body))
	w := httptest.NewRecorder()

	h.ValidateClient(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("got status %d, want 500", w.Code)
	}
}

// --- Health ---

func TestHealth_Returns200(t *testing.T) {
	h := newHandler(t, &fakeCreator{}, &fakeReader{}, &fakeValidator{}, &fakeDeleter{})
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()

	h.Health(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("got status %d, want 200", w.Code)
	}
	var body map[string]string
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["status"] != "ok" {
		t.Errorf("health body status = %q, want %q", body["status"], "ok")
	}
}
