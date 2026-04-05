package http

import (
	"context"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"

	apperrors "github.com/ocrosby/identity-platform-go/libs/errors"
	"github.com/ocrosby/identity-platform-go/libs/httputil"
	"github.com/ocrosby/identity-platform-go/libs/logging"
)

type contextKey string

const (
	contextKeySubject  contextKey = "subject"
	contextKeyScopes   contextKey = "scopes"
	contextKeyClientID contextKey = "client_id"
)

type jwtClaims struct {
	jwt.RegisteredClaims
	ClientID string   `json:"client_id"`
	Scopes   []string `json:"scopes"`
}

// JWTAuthMiddleware validates the JWT Bearer token (Chain of Responsibility)
func JWTAuthMiddleware(signingKey []byte, logger logging.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
				httputil.WriteError(w, apperrors.New(apperrors.ErrCodeUnauthorized, "missing or invalid authorization header"))
				return
			}

			raw := strings.TrimPrefix(authHeader, "Bearer ")

			token, err := jwt.ParseWithClaims(raw, &jwtClaims{}, func(t *jwt.Token) (interface{}, error) {
				if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, apperrors.New(apperrors.ErrCodeUnauthorized, "invalid signing method")
				}
				return signingKey, nil
			})

			if err != nil || !token.Valid {
				logger.Warn("invalid token", "error", err)
				httputil.WriteError(w, apperrors.New(apperrors.ErrCodeUnauthorized, "invalid token"))
				return
			}

			claims, ok := token.Claims.(*jwtClaims)
			if !ok {
				httputil.WriteError(w, apperrors.New(apperrors.ErrCodeUnauthorized, "invalid token claims"))
				return
			}

			ctx := r.Context()
			ctx = context.WithValue(ctx, contextKeySubject, claims.Subject)
			ctx = context.WithValue(ctx, contextKeyScopes, claims.Scopes)
			ctx = context.WithValue(ctx, contextKeyClientID, claims.ClientID)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireScopeMiddleware enforces that the token has the required scope (Chain of Responsibility)
func RequireScopeMiddleware(requiredScope string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			scopes, ok := r.Context().Value(contextKeyScopes).([]string)
			if !ok {
				httputil.WriteError(w, apperrors.New(apperrors.ErrCodeForbidden, "no scopes in context"))
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
