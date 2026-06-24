package http

import (
	"net/http"
	"strings"

	"github.com/jedi-knights/go-logging/pkg/logging"
	"github.com/jedi-knights/go-platform/apperrors"
	"github.com/jedi-knights/go-platform/httputil"

	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/application"
	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/ports"
)

// UserInfoHandler serves OIDC /userinfo (OIDC Core §5.3). It validates the
// bearer access token, enforces the openid scope, and projects the user's
// claims onto the scope set the token carries — exactly the same projection
// rule the ID-token issuer uses (ADR-0010).
//
// Two endpoints share this handler:
//
//	GET  /userinfo
//	POST /userinfo
//
// Both accept the access token in the standard RFC 6750 Authorization
// header; POST is allowed per OIDC §5.3.1 for clients that prefer it.
type UserInfoHandler struct {
	validator     application.TokenValidator
	claimsFetcher ports.UserClaimsFetcher
	logger        logging.Logger
}

// NewUserInfoHandler wires the handler to the access-token validator and the
// user-claims fetcher. The validator may be either HS256 or RS256 — same
// interface either way. claimsFetcher may be nil — when unset, the handler
// returns 503 (the service has nothing to project).
func NewUserInfoHandler(validator application.TokenValidator, claimsFetcher ports.UserClaimsFetcher, logger logging.Logger) *UserInfoHandler {
	return &UserInfoHandler{validator: validator, claimsFetcher: claimsFetcher, logger: logger}
}

// Get handles GET|POST /userinfo.
//
// @Summary      OIDC UserInfo
// @Description  Returns the OIDC claims permitted by the access token's scopes.
// @Tags         oidc
// @Produce      json
// @Success      200  {object}  map[string]any
// @Failure      401  {object}  httputil.ErrorResponse
// @Failure      403  {object}  httputil.ErrorResponse
// @Router       /userinfo [get]
func (h *UserInfoHandler) Get(w http.ResponseWriter, r *http.Request) {
	raw, ok := extractAccessToken(w, r)
	if !ok {
		return
	}
	token, err := h.validator.Validate(r.Context(), raw)
	if err != nil {
		writeUserInfoUnauthorized(w, "invalid_token", "invalid or expired token")
		return
	}
	if !domain.HasScope(token.Scopes, domain.ScopeOpenID) {
		writeUserInfoForbidden(w)
		return
	}
	if h.claimsFetcher == nil {
		httputil.WriteError(w, apperrors.New(apperrors.ErrCodeUnavailable, "userinfo backend not configured"))
		return
	}
	claims, err := h.claimsFetcher.GetUserClaims(r.Context(), token.Subject)
	if err != nil {
		if apperrors.IsNotFound(err) {
			writeUserInfoUnauthorized(w, "invalid_token", "subject not found")
			return
		}
		h.logger.Error("userinfo: claims fetch failed", "error", err)
		httputil.WriteError(w, apperrors.New(apperrors.ErrCodeInternal, "userinfo lookup failed"))
		return
	}
	httputil.WriteJSON(w, http.StatusOK, projectUserInfo(token.Scopes, claims))
}

// extractAccessToken pulls the Bearer token off the Authorization header,
// writing the 401 + WWW-Authenticate challenge if it is missing or
// malformed. Mirrors the pattern used in example-resource-service's bearer
// middleware so the wire shape stays consistent.
func extractAccessToken(w http.ResponseWriter, r *http.Request) (string, bool) {
	auth := r.Header.Get("Authorization")
	if auth == "" || !strings.HasPrefix(auth, "Bearer ") {
		writeUserInfoChallenge(w)
		return "", false
	}
	raw := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
	if raw == "" {
		writeUserInfoChallenge(w)
		return "", false
	}
	return raw, true
}

// writeUserInfoChallenge writes the RFC 6750 §3 401 challenge for an absent
// or malformed bearer token.
func writeUserInfoChallenge(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="auth-server"`)
	httputil.WriteError(w, apperrors.New(apperrors.ErrCodeUnauthorized, "missing or malformed bearer token"))
}

// writeUserInfoUnauthorized writes a 401 with the OIDC §5.3.3 error code
// embedded in the WWW-Authenticate header. The message body still uses the
// platform's standard error envelope so logging stays uniform.
func writeUserInfoUnauthorized(w http.ResponseWriter, errorCode, description string) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="auth-server", error="`+errorCode+`"`)
	httputil.WriteError(w, apperrors.New(apperrors.ErrCodeUnauthorized, description))
}

// writeUserInfoForbidden writes the OIDC §5.3.3 403 insufficient_scope
// response — the access token is valid but its scope set does not include
// "openid" (or any other scope the handler is trying to serve).
func writeUserInfoForbidden(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="auth-server", error="insufficient_scope", scope="openid"`)
	httputil.WriteError(w, apperrors.New(apperrors.ErrCodeForbidden, "access token does not include the 'openid' scope"))
}

// projectUserInfo builds the response body honoring scope-based filtering.
// sub is always present — every OIDC compliant response must carry it
// (OIDC §5.3.2). email / email_verified arrive via the "email" scope; name
// and updated_at via "profile".
func projectUserInfo(scopes []string, claims *ports.UserClaims) map[string]any {
	out := map[string]any{
		"sub": claims.Subject,
	}
	if domain.HasScope(scopes, domain.ScopeEmail) {
		if claims.Email != "" {
			out["email"] = claims.Email
		}
		out["email_verified"] = claims.EmailVerified
	}
	if domain.HasScope(scopes, domain.ScopeProfile) {
		if claims.Name != "" {
			out["name"] = claims.Name
		}
		if claims.UpdatedAt > 0 {
			out["updated_at"] = claims.UpdatedAt
		}
	}
	return out
}

