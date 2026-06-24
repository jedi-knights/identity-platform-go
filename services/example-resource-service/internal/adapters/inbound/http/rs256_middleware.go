package http

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/jedi-knights/go-logging/pkg/logging"
	"github.com/jedi-knights/go-platform/apperrors"
	"github.com/jedi-knights/go-platform/httputil"
	"github.com/jedi-knights/go-platform/jwtutil"
)

// RS256AuthMiddleware validates RS256-signed Bearer tokens locally using a
// KeySource (typically a JWKS HTTP fetcher) to resolve verification keys.
// This is the asymmetric-signing counterpart to JWTAuthMiddleware — same
// failure modes and WWW-Authenticate semantics, different signing scheme.
//
// When audience is non-empty, the token's aud claim must include that value
// per RFC 9068 §4. When issuer is non-empty, the iss claim must match
// per RFC 8725 §3.8. Both are validated *after* signature verification so a
// forged token never reaches the claim checks.
//
// NOTE: Like JWTAuthMiddleware, this middleware cannot detect tokens revoked
// via auth-server's /oauth/revoke until they expire. For revocation support,
// configure RESOURCE_INTROSPECTION_URL and use IntrospectionAuthMiddleware.
func RS256AuthMiddleware(keySource jwtutil.KeySource, audience, issuer string, logger logging.Logger) func(http.Handler) http.Handler {
	if keySource == nil {
		panic("RS256AuthMiddleware: keySource must not be nil")
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw, ok := extractBearer(w, r)
			if !ok {
				return
			}

			claims, err := jwtutil.ParseRS256(r.Context(), raw, keySource)
			if err != nil {
				if errors.Is(err, jwtutil.ErrTokenExpired) {
					logger.Info("expired token rejected", "error", err)
				} else {
					logger.Warn("invalid token rejected", "error", err)
				}
				w.Header().Set("WWW-Authenticate", `Bearer realm="example-resource-service", error="invalid_token"`)
				httputil.WriteError(w, apperrors.New(apperrors.ErrCodeUnauthorized, "invalid or expired token"))
				return
			}
			if audience != "" && !audienceContains([]string(claims.Audience), audience) {
				logger.Warn("token audience mismatch", "want", audience, "got", []string(claims.Audience))
				w.Header().Set("WWW-Authenticate", `Bearer realm="example-resource-service", error="invalid_token"`)
				httputil.WriteError(w, apperrors.New(apperrors.ErrCodeUnauthorized, "token audience does not include this resource server"))
				return
			}
			if issuer != "" && claims.Issuer != issuer {
				logger.Warn("token issuer mismatch", "want", issuer, "got", claims.Issuer)
				w.Header().Set("WWW-Authenticate", `Bearer realm="example-resource-service", error="invalid_token"`)
				httputil.WriteError(w, apperrors.New(apperrors.ErrCodeUnauthorized, "invalid token issuer"))
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
