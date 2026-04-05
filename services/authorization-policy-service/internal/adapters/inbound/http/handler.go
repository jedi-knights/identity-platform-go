package http

import (
	"encoding/json"
	"errors"
	"net/http"

	apperrors "github.com/ocrosby/identity-platform-go/libs/errors"
	"github.com/ocrosby/identity-platform-go/libs/httputil"
	"github.com/ocrosby/identity-platform-go/libs/logging"
	"github.com/ocrosby/identity-platform-go/services/authorization-policy-service/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/authorization-policy-service/internal/ports"
)

// Handler holds HTTP handler dependencies.
type Handler struct {
	evaluator ports.PolicyEvaluator
	logger    logging.Logger
}

func NewHandler(evaluator ports.PolicyEvaluator, logger logging.Logger) *Handler {
	return &Handler{evaluator: evaluator, logger: logger}
}

// Evaluate handles POST /evaluate.
//
// @Summary      Evaluate authorization policy
// @Description  Evaluates RBAC policies for a subject against a resource and action
// @Tags         policy
// @Accept       json
// @Produce      json
// @Param        request  body      domain.EvaluationRequest   true  "Evaluation request"
// @Success      200      {object}  domain.EvaluationResponse
// @Failure      400      {object}  httputil.ErrorResponse
// @Router       /evaluate [post]
func (h *Handler) Evaluate(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MB
	req, ok := h.decodeEvaluationRequest(w, r)
	if !ok {
		return
	}

	resp, err := h.evaluator.Evaluate(r.Context(), req)
	if err != nil {
		var ae *apperrors.AppError
		if !errors.As(err, &ae) || ae.Code == apperrors.ErrCodeInternal {
			h.logger.Error("policy evaluation failed", "error", err.Error())
		}
		httputil.WriteError(w, err)
		return
	}

	httputil.WriteJSON(w, http.StatusOK, resp)
}

// decodeEvaluationRequest parses and validates the request body.
// Returns (req, true) on success; writes an error response and returns (_, false) on failure.
func (h *Handler) decodeEvaluationRequest(w http.ResponseWriter, r *http.Request) (domain.EvaluationRequest, bool) {
	var req domain.EvaluationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, apperrors.New(apperrors.ErrCodeBadRequest, "invalid request body"))
		return req, false
	}
	if req.SubjectID == "" || req.Resource == "" || req.Action == "" {
		httputil.WriteError(w, apperrors.New(apperrors.ErrCodeBadRequest, "subject_id, resource, and action are required"))
		return req, false
	}
	return req, true
}

// Health handles GET /health.
//
// @Summary      Health check
// @Description  Returns service health status
// @Tags         health
// @Produce      json
// @Success      200  {object}  map[string]string
// @Router       /health [get]
func (h *Handler) Health(w http.ResponseWriter, _ *http.Request) {
	httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
