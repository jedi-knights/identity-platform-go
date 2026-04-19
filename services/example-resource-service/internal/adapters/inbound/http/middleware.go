package http

import (
	"context"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"

	apperrors "github.com/ocrosby/identity-platform-go/libs/errors"
	"github.com/ocrosby/identity-platform-go/libs/httputil"
	"github.com/ocrosby/identity-platform-go/libs/logging"
	"github.com/ocrosby/identity-platform-go/services/example-resource-service/internal/ports"
)

type contextKey int

const (
	contextKeySubject contextKey = iota
	contextKeyScopes
	contextKeyClientID
	contextKeyPermissions // JWT permissions claim; nil when absent (pre-RBAC tokens)
)

type jwtClaims struct {
	jwt.RegisteredClaims
	ClientID    string   `json:"client_id"`
	Scope       string   `json:"scope"`       // RFC 9068 §2.2.3.1: space-delimited string
	Permissions []string `json:"permissions"` // RBAC permissions; absent in pre-RBAC tokens
}

// IntrospectionAuthMiddleware validates the Bearer token by calling token-introspection-service.
// Revoked tokens are correctly rejected because the introspection service checks the auth-server's
// token store on every request.
func IntrospectionAuthMiddleware(introspector ports.TokenIntrospector, logger logging.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw, ok := extractBearer(w, r)
			if !ok {
				return
			}

			result, err := introspector.Introspect(r.Context(), raw)
			if err != nil {
				logger.Error("introspection service error", "error", err)
				w.Header().Set("WWW-Authenticate", `Bearer realm="example-resource-service", error="server_error"`)
				httputil.WriteError(w, apperrors.New(apperrors.ErrCodeInternal, "token validation unavailable"))
				return
			}
			if !result.Active {
				w.Header().Set("WWW-Authenticate", `Bearer realm="example-resource-service", error="invalid_token"`)
				httputil.WriteError(w, apperrors.New(apperrors.ErrCodeUnauthorized, "invalid or revoked token"))
				return
			}

			ctx := r.Context()
			ctx = context.WithValue(ctx, contextKeySubject, result.Subject)
			ctx = context.WithValue(ctx, contextKeyScopes, strings.Fields(result.Scope))
			ctx = context.WithValue(ctx, contextKeyClientID, result.ClientID)
			ctx = context.WithValue(ctx, contextKeyPermissions, result.Permissions)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// JWTAuthMiddleware validates the JWT Bearer token locally.
// Used as a fallback when RESOURCE_INTROSPECTION_URL is not configured.
//
// NOTE: Local validation cannot detect revoked tokens. Tokens revoked via
// auth-server's /oauth/revoke remain valid here until they expire. For
// revocation to work, configure RESOURCE_INTROSPECTION_URL to point at
// token-introspection-service and use IntrospectionAuthMiddleware instead.
func JWTAuthMiddleware(signingKey []byte, logger logging.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw, ok := extractBearer(w, r)
			if !ok {
				return
			}

			token, err := jwt.ParseWithClaims(raw, &jwtClaims{}, func(t *jwt.Token) (interface{}, error) {
				if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, apperrors.New(apperrors.ErrCodeUnauthorized, "invalid signing method")
				}
				return signingKey, nil
			})

			if err != nil || !token.Valid {
				logger.Warn("invalid token", "error", err)
				w.Header().Set("WWW-Authenticate", `Bearer realm="example-resource-service", error="invalid_token"`)
				httputil.WriteError(w, apperrors.New(apperrors.ErrCodeUnauthorized, "invalid token"))
				return
			}

			claims, ok := token.Claims.(*jwtClaims)
			if !ok {
				w.Header().Set("WWW-Authenticate", `Bearer realm="example-resource-service", error="invalid_token"`)
				httputil.WriteError(w, apperrors.New(apperrors.ErrCodeUnauthorized, "invalid token claims"))
				return
			}

			ctx := r.Context()
			ctx = context.WithValue(ctx, contextKeySubject, claims.Subject)
			ctx = context.WithValue(ctx, contextKeyScopes, strings.Fields(claims.Scope))
			ctx = context.WithValue(ctx, contextKeyClientID, claims.ClientID)
			ctx = context.WithValue(ctx, contextKeyPermissions, claims.Permissions)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireScopeMiddleware enforces that the token has the required scope (Chain of Responsibility).
// Returns 401 (not 403) when scopes are absent from context — this indicates the auth middleware
// did not run or the token was missing, which is an authentication failure, not an authorization one.
func RequireScopeMiddleware(requiredScope string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			scopes, ok := r.Context().Value(contextKeyScopes).([]string)
			if !ok {
				w.Header().Set("WWW-Authenticate", `Bearer realm="example-resource-service"`)
				httputil.WriteError(w, apperrors.New(apperrors.ErrCodeUnauthorized, "missing authentication context"))
				return
			}

			for _, s := range scopes {
				if s == requiredScope {
					next.ServeHTTP(w, r)
					return
				}
			}

			httputil.WriteError(w, apperrors.New(apperrors.ErrCodeForbidden, "insufficient scope"))
		})
	}
}

// extractBearer extracts the Bearer token from the Authorization header.
// Writes a 401 and returns false if the header is missing or malformed.
func extractBearer(w http.ResponseWriter, r *http.Request) (string, bool) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		w.Header().Set("WWW-Authenticate", `Bearer realm="example-resource-service"`)
		httputil.WriteError(w, apperrors.New(apperrors.ErrCodeUnauthorized, "missing or invalid authorization header"))
		return "", false
	}
	raw := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
	if raw == "" {
		w.Header().Set("WWW-Authenticate", `Bearer realm="example-resource-service"`)
		httputil.WriteError(w, apperrors.New(apperrors.ErrCodeUnauthorized, "missing or invalid authorization header"))
		return "", false
	}
	return raw, true
}
