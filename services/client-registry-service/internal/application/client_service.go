package application

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"slices"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/jedi-knights/go-platform/apperrors"
	"github.com/jedi-knights/go-platform/audit"

	"github.com/ocrosby/identity-platform-go/services/client-registry-service/internal/domain"
)

// ClientService handles OAuth client management operations.
//
// The service is the chokepoint for client registration and lifecycle
// operations and therefore the natural emission point for the
// client_registered and client_deleted audit events (ADR-0018 /
// ADR-0019). Audit is wired via [ClientService.WithAudit]; when audit is
// not configured the service uses a no-op emitter that always succeeds,
// preserving backwards compatibility for tests and adapters that
// pre-date the audit feature.
type ClientService struct {
	repo       domain.ClientRepository
	bcryptCost int

	emitter audit.Emitter
	service string
}

// NewClientService creates a ClientService using bcrypt.DefaultCost for secret hashing.
// The returned service uses a no-op audit emitter; call [ClientService.WithAudit]
// to wire a real emitter at composition time.
func NewClientService(repo domain.ClientRepository) *ClientService {
	return &ClientService{
		repo:       repo,
		bcryptCost: bcrypt.DefaultCost,
		emitter:    audit.New(audit.NoopSink{}),
		service:    "client-registry-service",
	}
}

// NewClientServiceWithCost creates a ClientService with a custom bcrypt cost.
// Use bcrypt.MinCost in tests to avoid paying the full bcrypt work factor on every
// CreateClient call. Returns an error if cost is outside [bcrypt.MinCost, bcrypt.MaxCost].
func NewClientServiceWithCost(repo domain.ClientRepository, cost int) (*ClientService, error) {
	if cost < bcrypt.MinCost || cost > bcrypt.MaxCost {
		return nil, apperrors.New(apperrors.ErrCodeBadRequest,
			fmt.Sprintf("bcrypt cost must be between %d and %d", bcrypt.MinCost, bcrypt.MaxCost))
	}
	return &ClientService{
		repo:       repo,
		bcryptCost: cost,
		emitter:    audit.New(audit.NoopSink{}),
		service:    "client-registry-service",
	}, nil
}

// WithAudit configures the service's audit emitter and service name.
// Returns the receiver to allow chained construction at the composition
// root. emitter must be non-nil. service is used as Event.Service on
// every emitted client_registered and client_deleted event.
//
// Per ADR-0019 these are paid events for accounting purposes — a
// durable-sink failure surfaces to the caller and the request fails so
// the meter cannot have gaps.
func (s *ClientService) WithAudit(emitter audit.Emitter, service string) *ClientService {
	if emitter == nil {
		panic("application: WithAudit called with nil emitter")
	}
	s.emitter = emitter
	if service != "" {
		s.service = service
	}
	return s
}

// validateCreateRequest checks that a CreateClientRequest contains the required fields.
func validateCreateRequest(req domain.CreateClientRequest) error {
	if req.Name == "" {
		return apperrors.New(apperrors.ErrCodeBadRequest, "name is required")
	}
	if len(req.GrantTypes) == 0 {
		return apperrors.New(apperrors.ErrCodeBadRequest, "at least one grant type is required")
	}
	if slices.Contains(req.GrantTypes, "") {
		return apperrors.New(apperrors.ErrCodeBadRequest, "grant type must not be blank")
	}
	return nil
}

// CreateClient registers a new OAuth client. It validates the request, generates
// a cryptographically random client ID and secret, bcrypt-hashes the secret, and
// persists the client. The plain-text secret is returned once and is not recoverable.
func (s *ClientService) CreateClient(ctx context.Context, req domain.CreateClientRequest) (*domain.CreateClientResponse, error) {
	if err := validateCreateRequest(req); err != nil {
		return nil, err
	}

	id, err := generateHex(16)
	if err != nil {
		return nil, fmt.Errorf("failed to generate client ID: %w", err)
	}

	clientType := normalizeIncomingClientType(req.ClientType)
	actorType := normalizeIncomingActorType(req.ActorType)
	plainSecret, storedSecret, err := s.generateSecretFor(clientType)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	client := &domain.OAuthClient{
		ID:           id,
		Secret:       storedSecret,
		Name:         req.Name,
		Type:         clientType,
		ActorType:    actorType,
		Scopes:       req.Scopes,
		RedirectURIs: req.RedirectURIs,
		GrantTypes:   req.GrantTypes,
		CreatedAt:    now,
		UpdatedAt:    now,
		Active:       true,
	}

	if err := s.repo.Save(ctx, client); err != nil {
		return nil, fmt.Errorf("failed to save client: %w", err)
	}

	eventType := "client_registered"
	auditActorType := audit.ActorTypeService
	if client.ActorType == domain.ActorTypeAgent {
		// ADR-0015: agents register through the same DCR endpoint as
		// services. The event type and actor classification on the
		// envelope follow ADR-0018's registry so downstream consumers
		// (audit dashboards, Lago billable metrics) can route on
		// agent-specific signals.
		eventType = "agent_registered"
		auditActorType = audit.ActorTypeAgent
	} else if client.ActorType == domain.ActorTypeUser {
		auditActorType = audit.ActorTypeUser
	}
	if err := s.emitter.Emit(ctx, audit.Event{
		EventType:      eventType,
		Service:        s.service,
		ActorType:      auditActorType,
		ActorID:        client.ID,
		SubjectID:      client.ID,
		ClientID:       client.ID,
		Resource:       "endpoint:register",
		ResourceKind:   audit.ResourceKindEndpoint,
		ResourceID:     "register",
		ResourceParent: s.service,
		ResourcePath:   s.service + "/endpoint/register",
		Action:         "register",
		Decision:       audit.DecisionAllow,
		Attrs: map[string]any{
			"name":        client.Name,
			"client_type": string(client.Type),
			"actor_type":  string(client.ActorType),
			"grant_types": client.GrantTypes,
			"scopes":      client.Scopes,
		},
	}); err != nil {
		return nil, fmt.Errorf("audit emit (%s): %w", eventType, err)
	}

	// Return the plain-text secret once — it will not be recoverable from
	// storage. Public clients receive an empty ClientSecret (omitempty in
	// the response struct strips it from the JSON).
	return &domain.CreateClientResponse{
		ClientID:     client.ID,
		ClientSecret: plainSecret,
		Name:         client.Name,
		ClientType:   string(client.Type),
		ActorType:    string(client.ActorType),
		Scopes:       client.Scopes,
		RedirectURIs: client.RedirectURIs,
		GrantTypes:   client.GrantTypes,
	}, nil
}

// GetClient returns the metadata for the client with the given ID.
// Returns an ErrCodeNotFound error if no client exists with that ID.
func (s *ClientService) GetClient(ctx context.Context, id string) (*domain.GetClientResponse, error) {
	client, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("fetching client: %w", err)
	}

	return &domain.GetClientResponse{
		ClientID:     client.ID,
		Name:         client.Name,
		ClientType:   normalizeClientType(client.Type),
		ActorType:    normalizeActorType(client.ActorType),
		Scopes:       client.Scopes,
		RedirectURIs: client.RedirectURIs,
		GrantTypes:   client.GrantTypes,
		Active:       client.Active,
	}, nil
}

// normalizeClientType returns the wire value of t, defaulting to
// "confidential" for empty or unrecognised stored values. This is the
// fail-closed mirror of the application's IsPublic logic and keeps the
// API contract honest for clients persisted before ADR-0009 added the
// column.
func normalizeClientType(t domain.ClientType) string {
	if t == domain.ClientTypePublic {
		return string(domain.ClientTypePublic)
	}
	return string(domain.ClientTypeConfidential)
}

// normalizeIncomingClientType maps the wire value on a CreateClientRequest
// to a domain.ClientType, defaulting empty / unknown to confidential per
// the fail-closed rule in ADR-0009.
func normalizeIncomingClientType(wire string) domain.ClientType {
	if domain.ClientType(wire) == domain.ClientTypePublic {
		return domain.ClientTypePublic
	}
	return domain.ClientTypeConfidential
}

// normalizeActorType returns the wire value of t, defaulting to "service"
// for empty or unrecognised stored values per ADR-0015's fail-closed
// rule. Records persisted before ADR-0015 carry an empty ActorType and
// surface as "service".
func normalizeActorType(t domain.ActorType) string {
	switch t {
	case domain.ActorTypeUser, domain.ActorTypeAgent:
		return string(t)
	default:
		return string(domain.ActorTypeService)
	}
}

// normalizeIncomingActorType maps the wire value on a CreateClientRequest
// to a domain.ActorType, defaulting empty / unknown to "service" per
// ADR-0015's fail-closed rule. Only user / service / agent are recognised
// — any other value is silently coerced to service so a misspelled
// classification cannot accidentally grant agent semantics.
func normalizeIncomingActorType(wire string) domain.ActorType {
	switch domain.ActorType(wire) {
	case domain.ActorTypeUser:
		return domain.ActorTypeUser
	case domain.ActorTypeAgent:
		return domain.ActorTypeAgent
	default:
		return domain.ActorTypeService
	}
}

// generateSecretFor returns (plain, stored) for the given client type.
// Public clients get ("", ""); confidential clients get a fresh 32-byte
// hex secret and its bcrypt hash. Extracted from CreateClient so the
// caller stays under the cyclomatic complexity cap.
func (s *ClientService) generateSecretFor(t domain.ClientType) (plain, stored string, err error) {
	if t != domain.ClientTypeConfidential {
		return "", "", nil
	}
	plain, err = generateHex(32)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate client secret: %w", err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(plain), s.bcryptCost)
	if err != nil {
		return "", "", fmt.Errorf("failed to hash client secret: %w", err)
	}
	return plain, string(hash), nil
}

// ValidateClient checks whether the provided client credentials are valid.
// It returns Valid=false (no error) when the client does not exist or the secret
// is wrong, so callers cannot distinguish the two cases (avoids client-ID enumeration).
// Non-not-found repository errors are propagated as errors rather than Valid=false.
func (s *ClientService) ValidateClient(ctx context.Context, req domain.ValidateClientRequest) (*domain.ValidateClientResponse, error) {
	// Reject empty secrets immediately — bcrypt comparison would always fail anyway,
	// but short-circuiting avoids unnecessary work and locks the contract explicitly.
	if req.ClientSecret == "" {
		return &domain.ValidateClientResponse{Valid: false}, nil
	}

	client, err := s.repo.FindByID(ctx, req.ClientID)
	if err != nil {
		if apperrors.IsNotFound(err) {
			return &domain.ValidateClientResponse{Valid: false}, nil
		}
		return nil, fmt.Errorf("looking up client: %w", err)
	}

	// bcrypt comparison is constant-time and handles the hashed secret stored in persistence.
	if err := bcrypt.CompareHashAndPassword([]byte(client.Secret), []byte(req.ClientSecret)); err != nil {
		return &domain.ValidateClientResponse{Valid: false}, nil
	}
	return &domain.ValidateClientResponse{Valid: client.Active}, nil
}

// ListClients returns metadata for all registered clients. The returned slice
// is never nil; an empty repository returns an empty slice.
func (s *ClientService) ListClients(ctx context.Context) ([]*domain.GetClientResponse, error) {
	clients, err := s.repo.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing clients: %w", err)
	}

	result := make([]*domain.GetClientResponse, 0, len(clients))
	for _, c := range clients {
		result = append(result, &domain.GetClientResponse{
			ClientID:     c.ID,
			Name:         c.Name,
			ClientType:   normalizeClientType(c.Type),
			Scopes:       c.Scopes,
			RedirectURIs: c.RedirectURIs,
			GrantTypes:   c.GrantTypes,
			Active:       c.Active,
		})
	}
	return result, nil
}

// DeleteClient removes the client with the given ID from the repository.
// Returns an ErrCodeNotFound error if no client exists with that ID.
func (s *ClientService) DeleteClient(ctx context.Context, id string) error {
	if err := s.repo.Delete(ctx, id); err != nil {
		return fmt.Errorf("deleting client %s: %w", id, err)
	}
	if err := s.emitter.Emit(ctx, audit.Event{
		EventType:      "client_deleted",
		Service:        s.service,
		ActorType:      audit.ActorTypeService,
		ActorID:        id,
		SubjectID:      id,
		ClientID:       id,
		Resource:       "endpoint:delete",
		ResourceKind:   audit.ResourceKindEndpoint,
		ResourceID:     "delete",
		ResourceParent: s.service,
		ResourcePath:   s.service + "/endpoint/delete",
		Action:         "delete",
		Decision:       audit.DecisionAllow,
	}); err != nil {
		return fmt.Errorf("audit emit (client_deleted): %w", err)
	}
	return nil
}

// generateHex returns a hex-encoded string of n cryptographically random bytes
// sourced from crypto/rand. The result is 2n characters long.
func generateHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
