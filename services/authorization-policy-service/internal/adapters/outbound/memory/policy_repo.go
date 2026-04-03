package memory

import (
	"sync"

	apperrors "github.com/ocrosby/identity-platform-go/libs/errors"
	"github.com/ocrosby/identity-platform-go/services/authorization-policy-service/internal/domain"
)

// PolicyRepository is an in-memory PolicyRepository implementation.
type PolicyRepository struct {
	mu       sync.RWMutex
	policies map[string]*domain.Policy
}

func NewPolicyRepository() *PolicyRepository {
	r := &PolicyRepository{
		policies: make(map[string]*domain.Policy),
	}
	_ = r.Save(&domain.Policy{SubjectID: "user-1", Roles: []string{"admin"}})
	_ = r.Save(&domain.Policy{SubjectID: "user-2", Roles: []string{"viewer"}})
	return r
}

func (r *PolicyRepository) FindBySubject(subjectID string) (*domain.Policy, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.policies[subjectID]
	if !ok {
		return nil, apperrors.New(apperrors.ErrCodeNotFound, "policy not found")
	}
	return p, nil
}

func (r *PolicyRepository) Save(policy *domain.Policy) error {
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

func NewRoleRepository() *RoleRepository {
	r := &RoleRepository{
		roles: make(map[string]*domain.Role),
	}
	_ = r.Save(&domain.Role{
		Name: "admin",
		Permissions: []domain.Permission{
			{Resource: "resource", Action: "read"},
			{Resource: "resource", Action: "write"},
			{Resource: "resource", Action: "delete"},
		},
	})
	_ = r.Save(&domain.Role{
		Name: "viewer",
		Permissions: []domain.Permission{
			{Resource: "resource", Action: "read"},
		},
	})
	return r
}

func (r *RoleRepository) FindByName(name string) (*domain.Role, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	role, ok := r.roles[name]
	if !ok {
		return nil, apperrors.New(apperrors.ErrCodeNotFound, "role not found")
	}
	return role, nil
}

func (r *RoleRepository) Save(role *domain.Role) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.roles[role.Name] = role
	return nil
}
