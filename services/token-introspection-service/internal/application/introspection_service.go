package application

import (
	"context"
	"fmt"

	"github.com/jedi-knights/go-platform/audit"

	"github.com/ocrosby/identity-platform-go/services/token-introspection-service/internal/domain"
)

// IntrospectionService implements RFC 7662 token introspection.
// It first validates the JWT signature and claims, then optionally checks the revocation store.
//
// Audit is wired via [IntrospectionService.WithAudit]; when audit is not
// configured the service uses a no-op emitter that always succeeds,
// preserving backwards compatibility for tests and adapters that
// pre-date the audit feature.
type IntrospectionService struct {
	validator  domain.TokenValidator
	revocation domain.RevocationChecker // nil = no revocation check (local dev fallback)

	emitter audit.Emitter
	service string
}

// introspectionCallerActor is the sentinel actor identifier used on every
// introspection emitted by this service. The /introspect endpoint
// authenticates the caller with a shared bearer secret — the secret is a
// single principal shared across all resource servers, so the actor is the
// secret holder rather than a per-RP identity.
const introspectionCallerActor = "bearer-introspection-caller"

// NewIntrospectionService returns an IntrospectionService wired with the given validator and optional revocation checker.
// When revocation is nil, revoked tokens will appear active until their JWT expiry — acceptable for local development.
// The returned service uses a no-op audit emitter; call [IntrospectionService.WithAudit]
// to wire a real emitter at composition time.
func NewIntrospectionService(validator domain.TokenValidator, revocation domain.RevocationChecker) *IntrospectionService {
	return &IntrospectionService{
		validator:  validator,
		revocation: revocation,
		emitter:    audit.New(audit.NoopSink{}),
		service:    "token-introspection-service",
	}
}

// WithAudit configures the service's audit emitter and service name.
// Returns the receiver to allow chained construction at the composition
// root. emitter must be non-nil. service is used as Event.Service on
// every emitted token_introspected event.
//
// Per ADR-0019 token_introspected is a paid event — a durable-sink
// failure surfaces to the caller. The HTTP handler translates that to
// the RFC 7662 §2.2-safe inactive response so no non-2xx status can be
// misread by resource servers as allow-through.
func (s *IntrospectionService) WithAudit(emitter audit.Emitter, service string) *IntrospectionService {
	if emitter == nil {
		panic("application: WithAudit called with nil emitter")
	}
	s.emitter = emitter
	if service != "" {
		s.service = service
	}
	return s
}

// Introspect validates the raw JWT and, if a revocation store is configured, confirms the token
// has not been revoked. Per RFC 7662 §2.2 any infrastructure error is treated as revocation (fail closed).
//
// Every successful path emits a token_introspected event (allow + active in
// attrs). Emission failures propagate so the HTTP layer can translate them
// to RFC 7662 §2.2-safe inactive responses, matching the ADR-0019 paid-
// event policy without leaking a non-2xx status.
func (s *IntrospectionService) Introspect(ctx context.Context, raw string) (*domain.IntrospectionResult, error) {
	result, err := s.validator.Validate(ctx, raw)
	if err != nil {
		return nil, err
	}
	if !result.Active {
		if emitErr := s.emit(ctx, result); emitErr != nil {
			return nil, fmt.Errorf("audit emit (token_introspected): %w", emitErr)
		}
		return result, nil
	}
	// If a revocation store is configured, confirm the token is still present in Redis.
	// auth-server deletes the key on revocation, so a missing key means the token was revoked.
	if s.revocation != nil {
		active, err := s.revocation.IsActive(ctx, raw)
		if err != nil {
			// Propagate so the handler can log with trace ID context.
			// The handler translates this to {active:false} per RFC 7662 §2.2 (fail closed).
			return nil, fmt.Errorf("revocation check: %w", err)
		}
		if !active {
			inactive := &domain.IntrospectionResult{Active: false}
			if emitErr := s.emit(ctx, inactive); emitErr != nil {
				return nil, fmt.Errorf("audit emit (token_introspected): %w", emitErr)
			}
			return inactive, nil
		}
	}
	if emitErr := s.emit(ctx, result); emitErr != nil {
		return nil, fmt.Errorf("audit emit (token_introspected): %w", emitErr)
	}
	return result, nil
}

// emit constructs and dispatches the token_introspected event. Active /
// inactive outcomes are carried in attrs because they are the result of
// the operation, not the authorization decision — the caller has already
// authenticated, so decision is always allow.
func (s *IntrospectionService) emit(ctx context.Context, result *domain.IntrospectionResult) error {
	return s.emitter.Emit(ctx, audit.Event{
		EventType:      "token_introspected",
		Service:        s.service,
		ActorType:      audit.ActorTypeService,
		ActorID:        introspectionCallerActor,
		SubjectID:      result.Subject,
		ClientID:       result.ClientID,
		Resource:       "token:access",
		ResourceKind:   audit.ResourceKindToken,
		ResourceID:     "access",
		ResourceParent: s.service,
		ResourcePath:   s.service + "/token/access",
		Action:         "introspect",
		Decision:       audit.DecisionAllow,
		Attrs: map[string]any{
			"active":              result.Active,
			"introspected_jti":    result.JTI,
			"introspected_client": result.ClientID,
		},
	})
}
