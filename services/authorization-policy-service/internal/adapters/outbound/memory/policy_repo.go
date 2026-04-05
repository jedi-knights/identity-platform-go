package memory

import (
	"context"
	"sync"

	apperrors "github.com/ocrosby/identity-platform-go/libs/errors"
	"github.com/ocrosby/identity-platform-go/services/authorization-policy-service/internal/domain"
)

// PolicyRepository is an in-memory PolicyRepository implementation.
type PolicyRepository struct {
	mu       sync.RWMutex
	policies map[string]*domain.Policy
}

// NewPolicyRepository creates a PolicyRepository seeded with default policies.
func NewPolicyRepository() *PolicyRepository {
	r := &PolicyRepository{
		policies: make(map[string]*domain.Policy),
	}
	// Seed directly to avoid unnecessary locking through the public Save method.
	r.policies["user-1"] = &domain.Policy{SubjectID: "user-1", Roles: []string{"admin"}}
	r.policies["user-2"] = &domain.Policy{SubjectID: "user-2", Roles: []string{"viewer"}}
	return r
}

// FindBySubject returns the policy for the given subject, or ErrCodeNotFound.
func (r *PolicyRepository) FindBySubject(_ context.Context, subjectID string) (*domain.Policy, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.policies[subjectID]
	if !ok {
		return nil, apperrors.New(apperrors.ErrCodeNotFound, "policy not found")
	}
	// Return a copy to prevent callers from mutating internal state.
	result := *p
	result.Roles = make([]string, len(p.Roles))
	copy(result.Roles, p.Roles)
	return &result, nil
}

// Save persists the policy, overwriting any existing entry for the same subject.
func (r *PolicyRepository) Save(_ context.Context, policy *domain.Policy) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.policies[policy.SubjectID] = policy
	return nil
}

// RoleRepository is an in-memory RoleRepository implementation.
type RoleRepository struct {
	mu    sync.RWMutex
	roles map[string]*domain.Role
}

// NewRoleRepository creates a RoleRepository seeded with default roles.
func NewRoleRepository() *RoleRepository {
	r := &RoleRepository{
		roles: make(map[string]*domain.Role),
	}
	// Seed directly to avoid unnecessary locking through the public Save method.
	r.roles["admin"] = &domain.Role{
		Name: "admin",
		Permissions: []domain.Permission{
			{Resource: "resource", Action: "read"},
			{Resource: "resource", Action: "write"},
			{Resource: "resource", Action: "delete"},
		},
	}
	r.roles["viewer"] = &domain.Role{
		Name: "viewer",
		Permissions: []domain.Permission{
			{Resource: "resource", Action: "read"},
		},
	}
	return r
}

// FindByName returns the role with the given name, or ErrCodeNotFound.
func (r *RoleRepository) FindByName(_ context.Context, name string) (*domain.Role, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	role, ok := r.roles[name]
	if !ok {
		return nil, apperrors.New(apperrors.ErrCodeNotFound, "role not found")
	}
	// Return a copy to prevent callers from mutating internal state.
	result := *role
	result.Permissions = make([]domain.Permission, len(role.Permissions))
	copy(result.Permissions, role.Permissions)
	return &result, nil
}

// Save persists the role, overwriting any existing entry with the same name.
func (r *RoleRepository) Save(_ context.Context, role *domain.Role) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.roles[role.Name] = role
	return nil
}
