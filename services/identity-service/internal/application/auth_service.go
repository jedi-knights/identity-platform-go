package application

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	apperrors "github.com/ocrosby/identity-platform-go/libs/errors"
	"github.com/ocrosby/identity-platform-go/services/identity-service/internal/domain"
)

// AuthService handles user authentication and registration.
type AuthService struct {
	userRepo domain.UserRepository
	hasher   domain.PasswordHasher
}

func NewAuthService(userRepo domain.UserRepository, hasher domain.PasswordHasher) *AuthService {
	return &AuthService{userRepo: userRepo, hasher: hasher}
}

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

	return &domain.LoginResponse{
		UserID: user.ID,
		Email:  user.Email,
		Name:   user.Name,
	}, nil
}

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
		return nil, fmt.Errorf("failed to save user: %w", err)
	}

	return &domain.RegisterResponse{
		UserID: user.ID,
		Email:  user.Email,
		Name:   user.Name,
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
		return nil, fmt.Errorf("failed to hash password: %w", err)
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
