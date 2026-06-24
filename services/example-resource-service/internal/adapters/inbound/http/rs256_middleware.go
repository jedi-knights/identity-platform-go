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
			claims, ok := rs256VerifyClaims(w, r, raw, keySource, audience, issuer, logger)
			if !ok {
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

// rs256VerifyClaims runs the three verification steps (signature, audience,
// issuer) and writes the appropriate WWW-Authenticate / 401 response on any
// failure. Returns the parsed claims and ok=true on success.
//
// Extracted from RS256AuthMiddleware so the middleware constructor stays
// under the cyclomatic complexity cap; the three guards are now visible
// together as the verification pipeline they are.
func rs256VerifyClaims(w http.ResponseWriter, r *http.Request, raw string, keySource jwtutil.KeySource, audience, issuer string, logger logging.Logger) (*jwtutil.Claims, bool) {
	claims, err := jwtutil.ParseRS256(r.Context(), raw, keySource)
	if err != nil {
		if errors.Is(err, jwtutil.ErrTokenExpired) {
			logger.Info("expired token rejected", "error", err)
		} else {
			logger.Warn("invalid token rejected", "error", err)
		}
		writeInvalidToken(w, "invalid or expired token")
		return nil, false
	}
	if audience != "" && !audienceContains([]string(claims.Audience), audience) {
		logger.Warn("token audience mismatch", "want", audience, "got", []string(claims.Audience))
		writeInvalidToken(w, "token audience does not include this resource server")
		return nil, false
	}
	if issuer != "" && claims.Issuer != issuer {
		logger.Warn("token issuer mismatch", "want", issuer, "got", claims.Issuer)
		writeInvalidToken(w, "invalid token issuer")
		return nil, false
	}
	return claims, true
}

// writeInvalidToken sets the RFC 6750 §3 WWW-Authenticate challenge and emits
// a 401. Shared across the three verification failure paths.
func writeInvalidToken(w http.ResponseWriter, msg string) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="example-resource-service", error="invalid_token"`)
	httputil.WriteError(w, apperrors.New(apperrors.ErrCodeUnauthorized, msg))
}
