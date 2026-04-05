package application

import "github.com/ocrosby/identity-platform-go/services/authorization-policy-service/internal/domain"

// Specification is the interface for permission specifications (Specification pattern).
type Specification interface {
	IsSatisfiedBy(roles []string) bool
}

// PermissionSpecification checks if any role grants the required permission.
type PermissionSpecification struct {
	roleRepo domain.RoleRepository
	resource string
	action   string
}

func NewPermissionSpecification(roleRepo domain.RoleRepository, resource, action string) *PermissionSpecification {
	return &PermissionSpecification{roleRepo: roleRepo, resource: resource, action: action}
}

func (s *PermissionSpecification) IsSatisfiedBy(roles []string) bool {
	for _, roleName := range roles {
		role, err := s.roleRepo.FindByName(roleName)
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
