package http_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	apperrors "github.com/ocrosby/identity-platform-go/libs/errors"
	"github.com/ocrosby/identity-platform-go/libs/logging"
	inboundhttp "github.com/ocrosby/identity-platform-go/services/authorization-policy-service/internal/adapters/inbound/http"
	"github.com/ocrosby/identity-platform-go/services/authorization-policy-service/internal/domain"
)

// fakeEvaluator stubs ports.PolicyEvaluator.
type fakeEvaluator struct {
	resp *domain.EvaluationResponse
	err  error
}

func (f *fakeEvaluator) Evaluate(_ context.Context, _ domain.EvaluationRequest) (*domain.EvaluationResponse, error) {
	return f.resp, f.err
}

// fakePermReader stubs ports.SubjectPermissionsReader.
type fakePermReader struct {
	result *domain.SubjectPermissions
	err    error
}

func (f *fakePermReader) GetSubjectPermissions(_ context.Context, _ string) (*domain.SubjectPermissions, error) {
	return f.result, f.err
}

func newTestHandler(eval *fakeEvaluator, reader *fakePermReader) *inboundhttp.Handler {
	logger := logging.NewLogger(logging.Config{Level: "error", Format: "text", Environment: "test"})
	return inboundhttp.NewHandler(eval, reader, logger)
}

// ---- Evaluate ----

func TestEvaluate_MissingFields_Returns400(t *testing.T) {
	h := newTestHandler(
		&fakeEvaluator{resp: &domain.EvaluationResponse{Allowed: true}},
		&fakePermReader{},
	)
	// SubjectID present but Resource and Action are empty
	body, _ := json.Marshal(domain.EvaluationRequest{SubjectID: "user-1"})
	req := httptest.NewRequest(http.MethodPost, "/evaluate", bytes.NewReader(body))
	w := httptest.NewRecorder()

	h.Evaluate(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("got status %d, want 400", w.Code)
	}
}

func TestEvaluate_InvalidJSON_Returns400(t *testing.T) {
	h := newTestHandler(&fakeEvaluator{}, &fakePermReader{})
	req := httptest.NewRequest(http.MethodPost, "/evaluate", bytes.NewReader([]byte("not json")))
	w := httptest.NewRecorder()

	h.Evaluate(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("got status %d, want 400", w.Code)
	}
}

func TestEvaluate_Allowed_Returns200(t *testing.T) {
	h := newTestHandler(
		&fakeEvaluator{resp: &domain.EvaluationResponse{Allowed: true}},
		&fakePermReader{},
	)
	body, _ := json.Marshal(domain.EvaluationRequest{SubjectID: "u", Resource: "articles", Action: "read"})
	req := httptest.NewRequest(http.MethodPost, "/evaluate", bytes.NewReader(body))
	w := httptest.NewRecorder()

	h.Evaluate(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("got status %d, want 200", w.Code)
	}
	var resp domain.EvaluationResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if !resp.Allowed {
		t.Errorf("Allowed = false, want true")
	}
}

func TestEvaluate_EvaluatorError_Returns500(t *testing.T) {
	h := newTestHandler(
		&fakeEvaluator{err: apperrors.New(apperrors.ErrCodeInternal, "db down")},
		&fakePermReader{},
	)
	body, _ := json.Marshal(domain.EvaluationRequest{SubjectID: "u", Resource: "r", Action: "a"})
	req := httptest.NewRequest(http.MethodPost, "/evaluate", bytes.NewReader(body))
	w := httptest.NewRecorder()

	h.Evaluate(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("got status %d, want 500", w.Code)
	}
}

// ---- GetSubjectPermissions ----

func TestGetSubjectPermissions_MissingSubjectID_Returns400(t *testing.T) {
	h := newTestHandler(&fakeEvaluator{}, &fakePermReader{})
	// r.PathValue("subjectID") returns "" when the route doesn't inject the value
	req := httptest.NewRequest(http.MethodGet, "/subjects//permissions", nil)
	w := httptest.NewRecorder()

	h.GetSubjectPermissions(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("got status %d, want 400", w.Code)
	}
}

func TestGetSubjectPermissions_Success_Returns200(t *testing.T) {
	want := &domain.SubjectPermissions{
		SubjectID:   "user-1",
		Roles:       []string{"admin"},
		Permissions: []string{"articles:read"},
	}
	h := newTestHandler(&fakeEvaluator{}, &fakePermReader{result: want})
	req := httptest.NewRequest(http.MethodGet, "/subjects/user-1/permissions", nil)
	// inject the path value as the real ServeMux would
	req.SetPathValue("subjectID", "user-1")
	w := httptest.NewRecorder()

	h.GetSubjectPermissions(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("got status %d, want 200", w.Code)
	}
	var got domain.SubjectPermissions
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if got.SubjectID != want.SubjectID {
		t.Errorf("SubjectID = %q, want %q", got.SubjectID, want.SubjectID)
	}
}

func TestGetSubjectPermissions_ReaderError_Returns500(t *testing.T) {
	h := newTestHandler(
		&fakeEvaluator{},
		&fakePermReader{err: apperrors.New(apperrors.ErrCodeInternal, "db down")},
	)
	req := httptest.NewRequest(http.MethodGet, "/subjects/user-1/permissions", nil)
	req.SetPathValue("subjectID", "user-1")
	w := httptest.NewRecorder()

	h.GetSubjectPermissions(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("got status %d, want 500", w.Code)
	}
}

// ---- Health ----

func TestHealth_Returns200(t *testing.T) {
	h := newTestHandler(&fakeEvaluator{}, &fakePermReader{})
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()

	h.Health(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("got status %d, want 200", w.Code)
	}
}
