package http

import (
	"context"
	"errors"
	"net/http"
	"strings"

	apperrors "github.com/ocrosby/identity-platform-go/libs/errors"
	"github.com/ocrosby/identity-platform-go/libs/httputil"
	"github.com/ocrosby/identity-platform-go/libs/jwtutil"
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

			// Propagate token claims to downstream handlers via context.
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

			claims, err := jwtutil.Parse(raw, signingKey)
			if err != nil {
				if errors.Is(err, jwtutil.ErrTokenExpired) {
					logger.Info("expired token rejected", "error", err)
				} else {
					logger.Warn("invalid token rejected", "error", err)
				}
				w.Header().Set("WWW-Authenticate", `Bearer realm="example-resource-service", error="invalid_token"`)
				httputil.WriteError(w, apperrors.New(apperrors.ErrCodeUnauthorized, "invalid token"))
				return
			}

			// Propagate token claims to downstream handlers via context.
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
// Panics if requiredScope is empty — an empty scope matches nothing a real token carries and
// indicates a wiring mistake, not a runtime condition.
func RequireScopeMiddleware(requiredScope string) func(http.Handler) http.Handler {
	if requiredScope == "" {
		panic("RequireScopeMiddleware: requiredScope must not be empty")
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			scopes, ok := r.Context().Value(contextKeyScopes).([]string)
			if !ok {
				w.Header().Set("WWW-Authenticate", `Bearer realm="example-resource-service"`)
				httputil.WriteError(w, apperrors.New(apperrors.ErrCodeUnauthorized, "missing authentication context"))
				return
			}

			// Scope names are public identifiers (e.g. "read", "write"), not secrets.
			// Plain equality is correct here; subtle.ConstantTimeCompare is for secrets.
			for _, s := range scopes {
				if s == requiredScope {
					next.ServeHTTP(w, r)
					return
				}
			}

			// RFC 6750 §3.1: insufficient_scope responses must carry WWW-Authenticate
			// with error="insufficient_scope" so clients can request broader authorization.
			w.Header().Set("WWW-Authenticate", `Bearer realm="example-resource-service", error="insufficient_scope"`)
			httputil.WriteError(w, apperrors.New(apperrors.ErrCodeForbidden, "insufficient scope"))
		})
	}
}

// extractBearer extracts the Bearer token from the Authorization header.
// Writes a 401 and returns false if the header is missing or malformed.
//
// Extra whitespace between "Bearer" and the token value is normalised by
// TrimSpace, so "Bearer   tok" is treated the same as "Bearer tok". A header
// that is all whitespace after the prefix (e.g. "Bearer   ") is rejected.
func extractBearer(w http.ResponseWriter, r *http.Request) (string, bool) {
	authHeader := r.Header.Get("Authorization")
	// First check: missing header or wrong scheme (e.g. "Token xyz").
	// The scheme match is intentionally case-sensitive ("Bearer", not "bearer").
	// RFC 7235 permits case-insensitive schemes, but strict uppercase-B matching
	// is simpler and all major OAuth2 clients send the canonical form.
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		w.Header().Set("WWW-Authenticate", `Bearer realm="example-resource-service"`)
		httputil.WriteError(w, apperrors.New(apperrors.ErrCodeUnauthorized, "missing or invalid authorization header"))
		return "", false
	}
	// Second check: "Bearer " with only whitespace after it (e.g. "Bearer   ").
	raw := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
	if raw == "" {
		w.Header().Set("WWW-Authenticate", `Bearer realm="example-resource-service"`)
		httputil.WriteError(w, apperrors.New(apperrors.ErrCodeUnauthorized, "missing or invalid authorization header"))
		return "", false
	}
	return raw, true
}
