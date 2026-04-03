package http

import (
	"encoding/json"
	"net/http"

	apperrors "github.com/ocrosby/identity-platform-go/libs/errors"
	"github.com/ocrosby/identity-platform-go/libs/httputil"
	"github.com/ocrosby/identity-platform-go/libs/logging"
	"github.com/ocrosby/identity-platform-go/services/example-resource-service/internal/application"
	"github.com/ocrosby/identity-platform-go/services/example-resource-service/internal/ports"
)

// Handler holds HTTP handler dependencies.
type Handler struct {
	lister  ports.ResourceLister
	getter  ports.ResourceGetter
	creator ports.ResourceCreator
	logger  logging.Logger
}

func NewHandler(
	lister ports.ResourceLister,
	getter ports.ResourceGetter,
	creator ports.ResourceCreator,
	logger logging.Logger,
) *Handler {
	return &Handler{
		lister:  lister,
		getter:  getter,
		creator: creator,
		logger:  logger,
	}
}

// ListResources handles GET /resources.
func (h *Handler) ListResources(w http.ResponseWriter, r *http.Request) {
	resources, err := h.lister.ListResources(r.Context())
	if err != nil {
		h.logger.Error("list resources failed", "error", err.Error())
		httputil.WriteError(w, apperrors.New(apperrors.ErrCodeInternal, err.Error()))
		return
	}
	httputil.WriteJSON(w, http.StatusOK, resources)
}

// GetResource handles GET /resources/{id}.
func (h *Handler) GetResource(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		httputil.WriteError(w, apperrors.New(apperrors.ErrCodeBadRequest, "resource id is required"))
		return
	}

	resource, err := h.getter.GetResource(r.Context(), id)
	if err != nil {
		h.logger.Error("get resource failed", "error", err.Error())
		httputil.WriteError(w, err)
		return
	}

	httputil.WriteJSON(w, http.StatusOK, resource)
}

// CreateResource handles POST /resources.
func (h *Handler) CreateResource(w http.ResponseWriter, r *http.Request) {
	var req application.CreateResourceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, apperrors.New(apperrors.ErrCodeBadRequest, "invalid request body"))
		return
	}

	resource, err := h.creator.CreateResource(r.Context(), req)
	if err != nil {
		h.logger.Error("create resource failed", "error", err.Error())
		httputil.WriteError(w, err)
		return
	}

	httputil.WriteJSON(w, http.StatusCreated, resource)
}

// Health handles GET /health.
func (h *Handler) Health(w http.ResponseWriter, _ *http.Request) {
	httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
