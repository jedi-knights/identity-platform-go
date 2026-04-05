package http

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"

	apperrors "github.com/ocrosby/identity-platform-go/libs/errors"
	"github.com/ocrosby/identity-platform-go/libs/httputil"
	"github.com/ocrosby/identity-platform-go/libs/logging"
	"github.com/ocrosby/identity-platform-go/services/example-resource-service/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/example-resource-service/internal/ports"
)

// Handler holds HTTP handler dependencies.
type Handler struct {
	lister        ports.ResourceLister
	getter        ports.ResourceGetter
	creator       ports.ResourceCreator
	logger        logging.Logger
	policyChecker ports.PolicyChecker
}

// NewHandler creates a Handler with the given dependencies.
// policyChecker may be nil; when nil, policy evaluation is skipped and scope alone gates access.
func NewHandler(
	lister ports.ResourceLister,
	getter ports.ResourceGetter,
	creator ports.ResourceCreator,
	logger logging.Logger,
	policyChecker ports.PolicyChecker,
) *Handler {
	return &Handler{
		lister:        lister,
		getter:        getter,
		creator:       creator,
		logger:        logger,
		policyChecker: policyChecker,
	}
}

// hasPermission checks the JWT permissions claim in context for the required permission.
// Returns (granted, present): present=false means the claim was absent from the token
// (pre-RBAC token), signalling the caller should fall back to the remote policy service.
func hasPermission(ctx context.Context, required string) (granted, present bool) {
	perms, ok := ctx.Value(contextKeyPermissions).([]string)
	if !ok || perms == nil {
		return false, false
	}
	for _, p := range perms {
		if p == required {
			return true, true
		}
	}
	return false, true
}

// checkAccess enforces the two-layer authorization contract:
//  1. JWT permissions claim present → check locally, no outbound call.
//  2. JWT permissions absent → fall back to remote PolicyChecker when configured.
//  3. Neither present → allow (scope-only pre-RBAC mode).
//
// Returns true when access is permitted. When access is denied or an error occurs,
// it writes the appropriate error response and returns false.
func (h *Handler) checkAccess(w http.ResponseWriter, r *http.Request, subjectID, permission, resource, action string) bool {
	if granted, present := hasPermission(r.Context(), permission); present {
		if !granted {
			httputil.WriteError(w, apperrors.New(apperrors.ErrCodeForbidden, "insufficient permissions"))
			return false
		}
		return true
	}
	if h.policyChecker == nil {
		return true
	}
	ok, err := h.policyChecker.Evaluate(r.Context(), subjectID, resource, action)
	if err != nil {
		h.logger.Error("policy evaluation failed", "error", err)
		httputil.WriteError(w, apperrors.New(apperrors.ErrCodeInternal, "authorization check unavailable"))
		return false
	}
	if !ok {
		httputil.WriteError(w, apperrors.New(apperrors.ErrCodeForbidden, "policy does not permit this action"))
		return false
	}
	return true
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
	subjectID, _ := r.Context().Value(contextKeySubject).(string)
	if !h.checkAccess(w, r, subjectID, "resources:read", "resources", "read") {
		return
	}

	resources, err := h.lister.ListResources(r.Context())
	if err != nil {
		h.logger.Error("list resources failed", "error", err.Error())
		httputil.WriteError(w, apperrors.New(apperrors.ErrCodeInternal, "failed to list resources"))
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

	subjectID, _ := r.Context().Value(contextKeySubject).(string)
	if !h.checkAccess(w, r, subjectID, "resources:read", "resources", "read") {
		return
	}

	resource, err := h.getter.GetResource(r.Context(), id)
	if err != nil {
		var ae *apperrors.AppError
		if errors.As(err, &ae) {
			httputil.WriteError(w, ae)
			return
		}
		h.logger.Error("get resource failed", "error", err.Error())
		httputil.WriteError(w, apperrors.New(apperrors.ErrCodeInternal, "failed to get resource"))
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
// @Param        request  body      domain.CreateResourceRequest  true  "Resource data"
// @Success      201      {object}  domain.Resource
// @Failure      400      {object}  httputil.ErrorResponse
// @Failure      401      {object}  httputil.ErrorResponse
// @Failure      413      {object}  httputil.ErrorResponse
// @Router       /resources [post]
func (h *Handler) CreateResource(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MB
	var req domain.CreateResourceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		httputil.WriteError(w, apperrors.New(apperrors.ErrCodeBadRequest, "invalid request body"))
		return
	}

	subjectID, _ := r.Context().Value(contextKeySubject).(string)
	if !h.checkAccess(w, r, subjectID, "resources:write", "resources", "write") {
		return
	}

	resource, err := h.creator.CreateResource(r.Context(), req)
	if err != nil {
		var ae *apperrors.AppError
		if errors.As(err, &ae) {
			httputil.WriteError(w, ae)
			return
		}
		h.logger.Error("create resource failed", "error", err.Error())
		httputil.WriteError(w, apperrors.New(apperrors.ErrCodeInternal, "failed to create resource"))
		return
	}

	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	w.Header().Set("Location", scheme+"://"+r.Host+"/resources/"+url.PathEscape(resource.ID))
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
