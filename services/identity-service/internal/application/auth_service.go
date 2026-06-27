package application

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/jedi-knights/go-platform/apperrors"
	"github.com/jedi-knights/go-platform/audit"

	"github.com/ocrosby/identity-platform-go/services/identity-service/internal/domain"
)

// AuthService handles user authentication and registration.
//
// The service is the chokepoint for user identity actions and therefore
// the natural emission point for the user_authenticated and
// user_registered audit events (ADR-0018 + ADR-0019). Audit is wired via
// [AuthService.WithAudit]; when audit is not configured the service uses
// a no-op emitter that always succeeds, preserving backwards
// compatibility for tests and adapters that pre-date the audit feature.
type AuthService struct {
	userRepo domain.UserRepository
	hasher   domain.PasswordHasher

	emitter audit.Emitter
	service string
}

// NewAuthService creates an AuthService with the given user repository and password hasher.
// The returned service uses a no-op audit emitter; call [AuthService.WithAudit]
// to wire a real emitter at composition time.
func NewAuthService(userRepo domain.UserRepository, hasher domain.PasswordHasher) *AuthService {
	return &AuthService{
		userRepo: userRepo,
		hasher:   hasher,
		emitter:  audit.New(audit.NoopSink{}),
		service:  "identity-service",
	}
}

// WithAudit configures the service's audit emitter and service name.
// Returns the receiver to allow chained construction at the composition
// root. emitter must be non-nil. service is used as Event.Service on
// every emitted user_authenticated and user_registered event.
//
// Per ADR-0019 these are paid events for accounting purposes — a
// durable-sink failure surfaces to the caller and the request fails so
// the meter cannot have gaps.
func (s *AuthService) WithAudit(emitter audit.Emitter, service string) *AuthService {
	if emitter == nil {
		panic("application: WithAudit called with nil emitter")
	}
	s.emitter = emitter
	if service != "" {
		s.service = service
	}
	return s
}

// Login verifies credentials and returns the user's identity on success.
// Returns ErrCodeBadRequest for missing fields, ErrCodeUnauthorized for invalid
// credentials, and ErrCodeForbidden when the account is disabled.
func (s *AuthService) Login(ctx context.Context, req domain.LoginRequest) (*domain.LoginResponse, error) {
	if req.Email == "" || req.Password == "" {
		return nil, apperrors.New(apperrors.ErrCodeBadRequest, "email and password are required")
	}

	user, err := s.userRepo.FindByEmail(ctx, req.Email)
	if err != nil {
		if apperrors.IsNotFound(err) {
			return nil, apperrors.New(apperrors.ErrCodeUnauthorized, "invalid credentials")
		}
		return nil, fmt.Errorf("looking up user: %w", err)
	}

	if !user.Active {
		return nil, apperrors.New(apperrors.ErrCodeForbidden, "account is disabled")
	}

	if err := s.hasher.Compare(user.PasswordHash, req.Password); err != nil {
		return nil, apperrors.New(apperrors.ErrCodeUnauthorized, "invalid credentials")
	}

	if err := s.emitter.Emit(ctx, audit.Event{
		EventType:      "user_authenticated",
		Service:        s.service,
		ActorType:      audit.ActorTypeUser,
		ActorID:        user.ID,
		SubjectID:      user.ID,
		Resource:       "endpoint:authenticate",
		ResourceKind:   audit.ResourceKindEndpoint,
		ResourceID:     "authenticate",
		ResourceParent: s.service,
		ResourcePath:   s.service + "/endpoint/authenticate",
		Action:         "authenticate",
		Decision:       audit.DecisionAllow,
		Attrs: map[string]any{
			"email":          user.Email,
			"email_verified": user.IsEmailVerified(),
		},
	}); err != nil {
		return nil, fmt.Errorf("audit emit (user_authenticated): %w", err)
	}

	return &domain.LoginResponse{
		UserID: user.ID,
		Email:  user.Email,
		Name:   user.Name,
	}, nil
}

// Register creates a new user account with a bcrypt-hashed password.
// Returns ErrCodeBadRequest for missing fields and ErrCodeConflict if the email
// is already registered.
func (s *AuthService) Register(ctx context.Context, req domain.RegisterRequest) (*domain.RegisterResponse, error) {
	if req.Email == "" || req.Password == "" || req.Name == "" {
		return nil, apperrors.New(apperrors.ErrCodeBadRequest, "email, password, and name are required")
	}

	if err := s.assertEmailAvailable(ctx, req.Email); err != nil {
		return nil, err
	}

	user, err := s.buildUser(req)
	if err != nil {
		return nil, err
	}

	if err := s.userRepo.Save(ctx, user); err != nil {
		return nil, fmt.Errorf("saving user: %w", err)
	}

	if err := s.emitter.Emit(ctx, audit.Event{
		EventType:      "user_registered",
		Service:        s.service,
		ActorType:      audit.ActorTypeUser,
		ActorID:        user.ID,
		SubjectID:      user.ID,
		Resource:       "endpoint:register",
		ResourceKind:   audit.ResourceKindEndpoint,
		ResourceID:     "register",
		ResourceParent: s.service,
		ResourcePath:   s.service + "/endpoint/register",
		Action:         "register",
		Decision:       audit.DecisionAllow,
		Attrs: map[string]any{
			"email": user.Email,
		},
	}); err != nil {
		return nil, fmt.Errorf("audit emit (user_registered): %w", err)
	}

	return &domain.RegisterResponse{
		UserID: user.ID,
		Email:  user.Email,
		Name:   user.Name,
	}, nil
}

// GetUserClaims returns the OIDC claim projection for the user with the
// given subject ID. ADR-0010's auth-server /userinfo endpoint and ID-token
// issuer both call this through the UserClaimsProvider port; the response
// shape mirrors OIDC Core §5.1.
//
// Identity-service is intentionally OIDC-scope-agnostic — it returns the
// full claim set on every call and lets auth-server filter by what the
// access token's scopes permit. Keeping scope-aware filtering at the auth
// boundary preserves the "identity-service does not understand OAuth"
// rule from CLAUDE.md.
//
// Returns ErrCodeNotFound when no user has the supplied ID.
func (s *AuthService) GetUserClaims(ctx context.Context, userID string) (*domain.UserClaims, error) {
	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("fetching user: %w", err)
	}
	return &domain.UserClaims{
		Subject:       user.ID,
		Email:         user.Email,
		EmailVerified: user.IsEmailVerified(),
		Name:          user.Name,
		UpdatedAt:     user.UpdatedAt,
	}, nil
}

// assertEmailAvailable returns an error if the email is already taken or if
// the repository check fails for a reason other than "not found".
func (s *AuthService) assertEmailAvailable(ctx context.Context, email string) error {
	existing, err := s.userRepo.FindByEmail(ctx, email)
	if err != nil && !apperrors.IsNotFound(err) {
		return fmt.Errorf("checking existing user: %w", err)
	}
	if existing != nil {
		return apperrors.New(apperrors.ErrCodeConflict, "email already registered")
	}
	return nil
}

// buildUser creates a new User value from a RegisterRequest by hashing the
// password and generating a random ID. Separating this keeps Register's
// cyclomatic complexity within bounds.
func (s *AuthService) buildUser(req domain.RegisterRequest) (*domain.User, error) {
	hash, err := s.hasher.Hash(req.Password)
	if err != nil {
		return nil, fmt.Errorf("hashing password: %w", err)
	}

	id, err := generateID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate user id: %w", err)
	}

	now := time.Now()
	return &domain.User{
		ID:           id,
		Email:        req.Email,
		PasswordHash: hash,
		Name:         req.Name,
		CreatedAt:    now,
		UpdatedAt:    now,
		Active:       true,
	}, nil
}

func generateID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating id: %w", err)
	}
	return hex.EncodeToString(b), nil
}
