package http

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/jedi-knights/go-platform/apperrors"

	"github.com/jedi-knights/go-logging/pkg/logging"

	"github.com/jedi-knights/go-platform/jwtutil"

	"github.com/jedi-knights/go-platform/httputil"

	"github.com/ocrosby/identity-platform-go/services/example-resource-service/internal/ports"
)

type contextKey int

const (
	contextKeySubject contextKey = iota
	contextKeyScopes
	contextKeyClientID
	contextKeyPermissions // JWT permissions claim; nil when absent (pre-RBAC tokens)
	// contextKeyAcr holds the RFC 9470 authentication-context-class-
	// reference value (ADR-0024 in identity-platform-go's auth-server).
	// Populated only by IntrospectionAuthMiddleware from
	// ports.IntrospectionResult.Acr — JWTAuthMiddleware and
	// RS256AuthMiddleware never set it, since no local JWT claim carries
	// it (see the ADR's Context section). Absent from context, not just
	// empty-string, for any request those two middlewares authenticated.
	contextKeyAcr
)

// IntrospectionAuthMiddleware validates the Bearer token by calling token-introspection-service.
// Revoked tokens are correctly rejected because the introspection service checks the auth-server's
// token store on every request.
//
// When expectedAudience is non-empty, the aud claim from the introspection result must contain
// that value (RFC 9068 §2.2 audience binding at the resource server).
func IntrospectionAuthMiddleware(introspector ports.TokenIntrospector, logger logging.Logger, expectedAudience string) func(http.Handler) http.Handler {
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

			// RFC 9068 §2.2: verify the token was issued for this resource server.
			if expectedAudience != "" && !audienceContains(result.Audience, expectedAudience) {
				w.Header().Set("WWW-Authenticate", `Bearer realm="example-resource-service", error="invalid_token"`)
				httputil.WriteError(w, apperrors.New(apperrors.ErrCodeUnauthorized, "token audience does not include this resource server"))
				return
			}

			// Propagate token claims to downstream handlers via context.
			ctx := r.Context()
			ctx = context.WithValue(ctx, contextKeySubject, result.Subject)
			ctx = context.WithValue(ctx, contextKeyScopes, strings.Fields(result.Scope))
			ctx = context.WithValue(ctx, contextKeyClientID, result.ClientID)
			ctx = context.WithValue(ctx, contextKeyPermissions, result.Permissions)
			// RFC 9470 (ADR-0024): propagate unconditionally, even when empty —
			// RequireACRMiddleware distinguishes "absent from context" (auth
			// middleware didn't run) from "present but empty/mismatched" (this
			// introspector has no acr to offer, e.g. token-introspection-service
			// today) only by the comma-ok assertion, so the value itself can be "".
			ctx = context.WithValue(ctx, contextKeyAcr, result.Acr)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// JWTAuthMiddleware validates the JWT Bearer token locally.
// Used as a fallback when RESOURCE_INTROSPECTION_URL is not configured.
//
// When audience is non-empty, the token's aud claim must include that value
// per RFC 9068 §4 (audience validation). When empty, audience is not checked.
// When issuer is non-empty, the token's iss claim must match (RFC 8725 §3.8).
// When empty, issuer is not checked.
//
// NOTE: Local validation cannot detect revoked tokens. Tokens revoked via
// auth-server's /oauth/revoke remain valid here until they expire. For
// revocation to work, configure RESOURCE_INTROSPECTION_URL to point at
// token-introspection-service and use IntrospectionAuthMiddleware instead.
func JWTAuthMiddleware(signingKey []byte, audience, issuer string, logger logging.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw, ok := extractBearer(w, r)
			if !ok {
				return
			}

			claims, err := parseJWT(raw, signingKey, audience, issuer)
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
	if strings.ContainsAny(requiredScope, "\"\r\n\\") {
		panic("RequireScopeMiddleware: requiredScope contains characters illegal in a quoted-string header value")
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
			// with error="insufficient_scope" and the required scope so clients can
			// request broader authorization.
			w.Header().Set("WWW-Authenticate",
				`Bearer realm="example-resource-service", error="insufficient_scope", scope="`+requiredScope+`"`)
			httputil.WriteError(w, apperrors.New(apperrors.ErrCodeForbidden, "insufficient scope"))
		})
	}
}

// RequireACRMiddleware enforces RFC 9470 step-up authentication (ADR-0024 in
// identity-platform-go's auth-server): the token's authentication-context-class
// reference must equal requiredACR, or the caller is challenged to re-authorize
// at the AS with that acr_values. Unlike RequireScopeMiddleware, both "absent
// from context" and "present but mismatched" collapse into the same 401 —
// RFC 9470's insufficient_user_authentication does not distinguish "no
// authentication context available" from "wrong authentication context" the
// way scope's authorization concept distinguishes 401 from 403.
// Panics if requiredACR is empty — an empty ACR matches nothing a real token
// carries and indicates a wiring mistake, not a runtime condition.
func RequireACRMiddleware(requiredACR string) func(http.Handler) http.Handler {
	if requiredACR == "" {
		panic("RequireACRMiddleware: requiredACR must not be empty")
	}
	if strings.ContainsAny(requiredACR, "\"\r\n\\") {
		panic("RequireACRMiddleware: requiredACR contains characters illegal in a quoted-string header value")
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			acr, ok := r.Context().Value(contextKeyAcr).(string)
			if ok && acr == requiredACR {
				next.ServeHTTP(w, r)
				return
			}

			// RFC 9470 §3: challenge names the acr_values that would satisfy it,
			// so the client can re-initiate authorization at the AS with those values.
			w.Header().Set("WWW-Authenticate",
				`Bearer realm="example-resource-service", error="insufficient_user_authentication", `+
					`error_description="stronger authentication is required for this action", acr_values="`+requiredACR+`"`)
			httputil.WriteError(w, apperrors.New(apperrors.ErrCodeUnauthorized, "insufficient user authentication"))
		})
	}
}

// audienceContains reports whether expected appears in the audience slice.
func audienceContains(audience []string, expected string) bool {
	for _, aud := range audience {
		if aud == expected {
			return true
		}
	}
	return false
}

// parseJWT parses and validates a JWT with the given constraints.
// When both audience and issuer are set, audience is validated first, then
// the issuer claim is checked against issuer. golang-jwt/v5 does not support
// combining WithAudience and WithIssuer in a single parse call.
func parseJWT(raw string, signingKey []byte, audience, issuer string) (*jwtutil.Claims, error) {
	switch {
	case audience != "" && issuer != "":
		claims, err := jwtutil.ParseWithAudience(raw, signingKey, audience)
		if err == nil && claims.Issuer != issuer {
			return nil, jwtutil.ErrTokenInvalid
		}
		return claims, err
	case audience != "":
		return jwtutil.ParseWithAudience(raw, signingKey, audience)
	case issuer != "":
		return jwtutil.ParseWithIssuer(raw, signingKey, issuer)
	default:
		return jwtutil.Parse(raw, signingKey)
	}
}

// extractBearer extracts the Bearer token from the Authorization header.
// Writes a 401 and returns false if the header is missing or malformed.
//
// Extra whitespace between "Bearer" and the token value is normalized by
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
