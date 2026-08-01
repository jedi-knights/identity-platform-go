package http

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/jedi-knights/go-platform/apperrors"
	"github.com/jedi-knights/go-platform/httputil"
)

// requesterHeader carries the caller's user_id. Temporary bridge until
// auth-server's JWT integration lands (E7-S3c) — at that point the
// middleware will populate it from a validated access-token claim
// rather than trusting a client-supplied header.
const requesterHeader = "X-Requester-User-ID"

// activeAccountResponse is the GET response body. AccountID is a
// pointer so the "never set" case serializes as JSON null rather than
// as an empty string — downstream clients (login-ui) rely on the
// distinction to know whether to prompt the user to choose.
type activeAccountResponse struct {
	AccountID *string `json:"account_id"`
}

// setActiveAccountRequest is the PUT body. AccountID is required and
// non-empty; clearing the selection is not supported today (a future
// DELETE endpoint would take that path).
type setActiveAccountRequest struct {
	AccountID string `json:"account_id"`
}

// GetActiveAccount handles GET /users/{id}/active-account.
//
// @Summary      Get the user's active account
// @Description  Returns the currently selected account for the user. account_id is null when the user has never chosen.
// @Tags         users
// @Produce      json
// @Param        id                     path  string  true  "User ID"
// @Param        X-Requester-User-ID    header  string  true  "Requester user ID (must equal path id)"
// @Success      200  {object}  activeAccountResponse
// @Failure      400  {object}  httputil.ErrorResponse
// @Failure      403  {object}  httputil.ErrorResponse
// @Router       /users/{id}/active-account [get]
func (h *Handler) GetActiveAccount(w http.ResponseWriter, r *http.Request) {
	userID, err := h.authorizeSelf(r)
	if err != nil {
		httputil.WriteError(w, err)
		return
	}
	accountID, err := h.preferences.GetActiveAccount(r.Context(), userID)
	if err != nil {
		h.logger.Error("get active account failed", "error", err.Error())
		httputil.WriteError(w, err)
		return
	}
	resp := activeAccountResponse{}
	if accountID != "" {
		id := accountID
		resp.AccountID = &id
	}
	httputil.WriteJSON(w, http.StatusOK, resp)
}

// SetActiveAccount handles PUT /users/{id}/active-account.
//
// @Summary      Set the user's active account
// @Description  Upserts the currently selected account for the user.
// @Tags         users
// @Accept       json
// @Param        id                     path    string                    true  "User ID"
// @Param        X-Requester-User-ID    header  string                    true  "Requester user ID (must equal path id)"
// @Param        request                body    setActiveAccountRequest   true  "Active account selection"
// @Success      204
// @Failure      400  {object}  httputil.ErrorResponse
// @Failure      403  {object}  httputil.ErrorResponse
// @Router       /users/{id}/active-account [put]
func (h *Handler) SetActiveAccount(w http.ResponseWriter, r *http.Request) {
	userID, err := h.authorizeSelf(r)
	if err != nil {
		httputil.WriteError(w, err)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var body setActiveAccountRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httputil.WriteError(w, apperrors.New(apperrors.ErrCodeBadRequest, "invalid request body"))
		return
	}
	if err := h.preferences.SetActiveAccount(r.Context(), userID, body.AccountID); err != nil {
		var ae *apperrors.AppError
		if !errors.As(err, &ae) || ae.Code() == apperrors.ErrCodeInternal {
			h.logger.Error("set active account failed", "error", err.Error())
		}
		httputil.WriteError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// authorizeSelf resolves the {id} path parameter and requires the
// X-Requester-User-ID header to match it. Returns the userID on success
// or an apperror (400 missing header / bad path, 403 mismatch) that
// callers write directly to the response.
func (h *Handler) authorizeSelf(r *http.Request) (string, error) {
	userID := r.PathValue("id")
	if userID == "" {
		return "", apperrors.New(apperrors.ErrCodeBadRequest, "user id is required")
	}
	requester := r.Header.Get(requesterHeader)
	if requester == "" {
		return "", apperrors.New(apperrors.ErrCodeBadRequest, requesterHeader+" header is required")
	}
	if requester != userID {
		return "", apperrors.New(apperrors.ErrCodeForbidden, "requester may only manage own preferences")
	}
	return userID, nil
}
