package http

import (
	"encoding/json"
	"net/http"

	apperrors "github.com/ocrosby/identity-platform-go/libs/errors"
	"github.com/ocrosby/identity-platform-go/libs/httputil"
	"github.com/ocrosby/identity-platform-go/libs/logging"
	"github.com/ocrosby/identity-platform-go/services/example-resource-service/internal/application"

	// imported for swagger doc generation
	_ "github.com/ocrosby/identity-platform-go/services/example-resource-service/internal/domain"
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
//
// @Summary      List resources
// @Description  Returns all resources. Requires 'read' scope.
// @Tags         resources
// @Produce      json
// @Security     BearerAuth
// @Success      200  {array}   domain.Resource
// @Failure      401  {object}  httputil.ErrorResponse
// @Failure      403  {object}  httputil.ErrorResponse
// @Failure      500  {object}  httputil.ErrorResponse
// @Router       /resources [get]
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
//
// @Summary      Get resource by ID
// @Description  Returns a specific resource by ID. Requires 'read' scope.
// @Tags         resources
// @Produce      json
// @Security     BearerAuth
// @Param        id   path      string  true  "Resource ID"
// @Success      200  {object}  domain.Resource
// @Failure      400  {object}  httputil.ErrorResponse
// @Failure      401  {object}  httputil.ErrorResponse
// @Failure      404  {object}  httputil.ErrorResponse
// @Router       /resources/{id} [get]
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
//
// @Summary      Create resource
// @Description  Creates a new resource. Requires 'write' scope.
// @Tags         resources
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        request  body      application.CreateResourceRequest  true  "Resource data"
// @Success      201      {object}  domain.Resource
// @Failure      400      {object}  httputil.ErrorResponse
// @Failure      401      {object}  httputil.ErrorResponse
// @Router       /resources [post]
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
