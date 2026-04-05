package application

import (
	"context"

	"github.com/ocrosby/identity-platform-go/services/authorization-policy-service/internal/domain"
)

// Specification is the interface for permission specifications (Specification pattern).
type Specification interface {
	IsSatisfiedBy(roles []string) bool
}

// PermissionSpecification checks if any role grants the required permission.
type PermissionSpecification struct {
	ctx      context.Context
	roleRepo domain.RoleRepository
	resource string
	action   string
}

// NewPermissionSpecification creates a specification that checks resource/action permission.
func NewPermissionSpecification(ctx context.Context, roleRepo domain.RoleRepository, resource, action string) *PermissionSpecification {
	return &PermissionSpecification{ctx: ctx, roleRepo: roleRepo, resource: resource, action: action}
}

// IsSatisfiedBy returns true if any of the given roles grants the configured permission.
func (s *PermissionSpecification) IsSatisfiedBy(roles []string) bool {
	for _, roleName := range roles {
		role, err := s.roleRepo.FindByName(s.ctx, roleName)
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
