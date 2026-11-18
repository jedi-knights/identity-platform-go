package application

import (
	"context"
	"fmt"

	"github.com/ocrosby/identity-platform-go/services/authorization-policy-service/internal/domain"
)

// rolesByName fetches the named roles in one repository call and indexes them
// by name. Names with no role are simply absent from the result, preserving the
// "unknown roles are silently skipped" behavior; callers iterate their own
// ordered name list and look each up here, so the order of roles in a policy —
// not the repository's return order — still decides which role matches first.
// O(n) time and space in the number of role names; one query regardless of n.
func rolesByName(ctx context.Context, repo domain.RoleRepository, names []string) (map[string]*domain.Role, error) {
	if len(names) == 0 {
		return map[string]*domain.Role{}, nil
	}
	roles, err := repo.FindByNames(ctx, names)
	if err != nil {
		return nil, fmt.Errorf("finding roles: %w", err)
	}
	byName := make(map[string]*domain.Role, len(roles))
	for _, r := range roles {
		byName[r.Name] = r
	}
	return byName, nil
}
