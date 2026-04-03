package http

import (
	"encoding/json"
	"net/http"

	apperrors "github.com/ocrosby/identity-platform-go/libs/errors"
	"github.com/ocrosby/identity-platform-go/libs/httputil"
	"github.com/ocrosby/identity-platform-go/libs/logging"
	"github.com/ocrosby/identity-platform-go/services/authorization-policy-service/internal/application"
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
// @Param        request  body      application.EvaluationRequest   true  "Evaluation request"
// @Success      200      {object}  application.EvaluationResponse
// @Failure      400      {object}  httputil.ErrorResponse
// @Router       /evaluate [post]
func (h *Handler) Evaluate(w http.ResponseWriter, r *http.Request) {
	var req application.EvaluationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, apperrors.New(apperrors.ErrCodeBadRequest, "invalid request body"))
		return
	}

	resp, err := h.evaluator.Evaluate(r.Context(), req)
	if err != nil {
		h.logger.Error("policy evaluation failed", "error", err.Error())
		httputil.WriteError(w, apperrors.New(apperrors.ErrCodeBadRequest, err.Error()))
		return
	}

	httputil.WriteJSON(w, http.StatusOK, resp)
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
