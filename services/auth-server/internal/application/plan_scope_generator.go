package application

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/domain"
)

// PlanScopeProjectionGenerator wraps a TokenGenerator and, when a
// namespace is configured, projects cutline-style prefixed scope
// strings (tier:, sport:, div:, group:, feature:, history-depth:)
// into a JSON object attached to the token under that namespace via
// AdditionalFields. When the namespace is empty the wrapper is a
// pass-through, so the deploy stays opt-in.
//
// Deliberately narrow — the projection shape is the one cutline needs
// today. A second resource server that wants the same pattern should
// add its own projection layer or a projector interface rather than
// generalise this one; the config surface explodes once the mapping
// between scope-string prefixes and claim-object field names becomes
// per-deploy configurable.
type PlanScopeProjectionGenerator struct {
	inner     TokenGenerator
	namespace string // empty => pass-through
}

// NewPlanScopeProjectionGenerator wires the wrapper. Empty namespace
// is a valid configuration — the resulting generator is a pass-through
// over inner so a deploy that does not opt in sees no behaviour change.
func NewPlanScopeProjectionGenerator(inner TokenGenerator, namespace string) *PlanScopeProjectionGenerator {
	return &PlanScopeProjectionGenerator{
		inner:     inner,
		namespace: strings.TrimSpace(namespace),
	}
}

// Generate projects the token's scope strings into a plan_scope claim
// under the configured namespace, then delegates to the inner
// generator. When no recognised prefixes are present the claim is
// omitted — the empty projection would otherwise ride as a noise
// field on every issued token.
//
// The projection is additive to token.AdditionalFields: if the caller
// pre-populated the map, existing entries are preserved except for
// the namespace key, which is overwritten (the projection is
// authoritative for its own namespace).
func (g *PlanScopeProjectionGenerator) Generate(ctx context.Context, token *domain.Token) (string, error) {
	if g.namespace == "" {
		return g.inner.Generate(ctx, token)
	}
	raw, err := ProjectScopesToClaim(token.Scopes)
	if err != nil {
		return "", fmt.Errorf("project plan_scope claim: %w", err)
	}
	if raw != nil {
		// Copy-on-write: never mutate the caller's token value. The
		// caller may re-use the same *domain.Token after Generate (the
		// grant strategies do, for refresh token generation).
		augmented := *token
		if augmented.AdditionalFields == nil {
			augmented.AdditionalFields = make(map[string]json.RawMessage, 1)
		} else {
			// Shallow copy so our writes don't leak back into the
			// caller's map.
			cp := make(map[string]json.RawMessage, len(augmented.AdditionalFields)+1)
			for k, v := range augmented.AdditionalFields {
				cp[k] = v
			}
			augmented.AdditionalFields = cp
		}
		augmented.AdditionalFields[g.namespace] = raw
		return g.inner.Generate(ctx, &augmented)
	}
	return g.inner.Generate(ctx, token)
}
