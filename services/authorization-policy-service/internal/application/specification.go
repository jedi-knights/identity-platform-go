package application

import (
	"context"
	"fmt"

	"github.com/jedi-knights/go-platform/apperrors"

	"github.com/ocrosby/identity-platform-go/services/authorization-policy-service/internal/domain"
)

// specification is the interface for permission specifications (Specification pattern).
type specification interface {
	// IsSatisfiedBy returns the name of the first role that grants the
	// configured permission, or "" when none match. An error indicates an
	// infrastructure failure (as distinct from a genuine access denial,
	// which returns "" with a nil error).
	IsSatisfiedBy(ctx context.Context, roles []string) (string, error)
}

// permissionSpecification checks if any role grants the required permission.
type permissionSpecification struct {
	roleRepo domain.RoleRepository
	resource string
	action   string
}

// Verify that permissionSpecification satisfies the specification interface at compile time.
var _ specification = (*permissionSpecification)(nil)

// newPermissionSpecification creates a specification that checks resource/action permission.
func newPermissionSpecification(roleRepo domain.RoleRepository, resource, action string) *permissionSpecification {
	return &permissionSpecification{roleRepo: roleRepo, resource: resource, action: action}
}

// IsSatisfiedBy returns the first role name that grants the configured
// permission, or "" if none do. Returning the role name (instead of a bool)
// lets the caller surface it on the audit event's matched_rule attr for
// forensic tracing per ADR-0018.
//
// A not-found error for a role is treated as "no permission" and iteration
// continues. Any other repository error is propagated so callers can
// distinguish infrastructure failures from genuine access denials.
func (s *permissionSpecification) IsSatisfiedBy(ctx context.Context, roles []string) (string, error) {
	for _, roleName := range roles {
		role, err := s.roleRepo.FindByName(ctx, roleName)
		if err != nil {
			if apperrors.IsNotFound(err) {
				continue
			}
			return "", fmt.Errorf("finding role %q: %w", roleName, err)
		}
		for _, perm := range role.Permissions {
			if perm.Resource == s.resource && perm.Action == s.action {
				return roleName, nil
			}
		}
	}
	return "", nil
}
