package ports

import (
	"context"

	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/application"
	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/domain"
)

// TokenIssuer is the inbound port for token issuance.
type TokenIssuer interface {
	IssueToken(ctx context.Context, req domain.GrantRequest) (*domain.GrantResponse, error)
}

// TokenIntrospector is the inbound port for token introspection.
type TokenIntrospector interface {
	Introspect(ctx context.Context, raw string) (*application.IntrospectResponse, error)
}

// TokenRevoker is the inbound port for token revocation.
type TokenRevoker interface {
	Revoke(ctx context.Context, raw string) error
}
