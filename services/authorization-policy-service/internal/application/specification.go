package application

import (
	"context"

	"github.com/ocrosby/identity-platform-go/services/authorization-policy-service/internal/domain"
)

// specification is the interface for permission specifications (Specification pattern).
// It is unexported because it has a single implementer in this package and is not used
// as a parameter type anywhere outside of it.
type specification interface {
	IsSatisfiedBy(ctx context.Context, permissions []string) bool
}

// PermissionSpecification checks if any role grants the required permission.
type PermissionSpecification struct {
	roleRepo domain.RoleRepository
	resource string
	action   string
}

// Verify that PermissionSpecification satisfies the specification interface at compile time.
var _ specification = (*PermissionSpecification)(nil)

// NewPermissionSpecification creates a specification that checks resource/action permission.
func NewPermissionSpecification(roleRepo domain.RoleRepository, resource, action string) *PermissionSpecification {
	return &PermissionSpecification{roleRepo: roleRepo, resource: resource, action: action}
}

// IsSatisfiedBy returns true if any of the given roles grants the configured permission.
func (s *PermissionSpecification) IsSatisfiedBy(ctx context.Context, roles []string) bool {
	for _, roleName := range roles {
		role, err := s.roleRepo.FindByName(ctx, roleName)
		if err != nil {
			continue
		}
		for _, perm := range role.Permissions {
			if perm.Resource == s.resource && perm.Action == s.action {
				return true
			}
		}
	}
	return false
}
