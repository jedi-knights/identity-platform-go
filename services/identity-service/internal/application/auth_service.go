package application

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/ocrosby/identity-platform-go/services/identity-service/internal/domain"
)

// AuthService handles user authentication and registration
type AuthService struct {
	userRepo domain.UserRepository
	hasher   domain.PasswordHasher
}

func NewAuthService(userRepo domain.UserRepository, hasher domain.PasswordHasher) *AuthService {
	return &AuthService{userRepo: userRepo, hasher: hasher}
}

// LoginRequest contains login credentials
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// LoginResponse contains login result
type LoginResponse struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	Name   string `json:"name"`
}

// RegisterRequest contains registration data
type RegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Name     string `json:"name"`
}

// RegisterResponse contains registration result
type RegisterResponse struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	Name   string `json:"name"`
}

func (s *AuthService) Login(_ context.Context, req LoginRequest) (*LoginResponse, error) {
	user, err := s.userRepo.FindByEmail(req.Email)
	if err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	if !user.Active {
		return nil, fmt.Errorf("account is disabled")
	}

	if err := s.hasher.Compare(user.PasswordHash, req.Password); err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	return &LoginResponse{
		UserID: user.ID,
		Email:  user.Email,
		Name:   user.Name,
	}, nil
}

func (s *AuthService) Register(_ context.Context, req RegisterRequest) (*RegisterResponse, error) {
	existing, _ := s.userRepo.FindByEmail(req.Email)
	if existing != nil {
		return nil, fmt.Errorf("email already registered")
	}

	hash, err := s.hasher.Hash(req.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	user := &domain.User{
		ID:           generateID(),
		Email:        req.Email,
		PasswordHash: hash,
		Name:         req.Name,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
		Active:       true,
	}

	if err := s.userRepo.Save(user); err != nil {
		return nil, fmt.Errorf("failed to save user: %w", err)
	}

	return &RegisterResponse{
		UserID: user.ID,
		Email:  user.Email,
		Name:   user.Name,
	}, nil
}

func generateID() string {
	b := make([]byte, 16)
	rand.Read(b) //nolint:errcheck
	return hex.EncodeToString(b)
}
