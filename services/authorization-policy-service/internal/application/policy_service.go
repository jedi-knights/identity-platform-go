package application

import (
	"context"
	"fmt"

	"github.com/jedi-knights/go-platform/apperrors"
	"github.com/jedi-knights/go-platform/audit"

	"github.com/ocrosby/identity-platform-go/services/authorization-policy-service/internal/domain"
)

// PolicyService evaluates authorization policies.
//
// Audit is wired via [PolicyService.WithAudit]; when audit is not
// configured the service uses a no-op emitter that always succeeds,
// preserving backwards compatibility for tests and adapters that
// pre-date the audit feature.
type PolicyService struct {
	policyRepo domain.PolicyRepository
	roleRepo   domain.RoleRepository

	emitter audit.Emitter
	service string
}

// policyCallerActor is the sentinel actor identifier used on every
// policy_evaluated event. This service does not authenticate its
// callers (the gateway authenticates resource servers before they
// reach the policy endpoint); using a stable sentinel keeps the
// audit envelope honest about what we know.
const policyCallerActor = "policy-caller"

// NewPolicyService creates a PolicyService backed by the given repositories.
// The returned service uses a no-op audit emitter; call [PolicyService.WithAudit]
// to wire a real emitter at composition time.
func NewPolicyService(policyRepo domain.PolicyRepository, roleRepo domain.RoleRepository) *PolicyService {
	return &PolicyService{
		policyRepo: policyRepo,
		roleRepo:   roleRepo,
		emitter:    audit.New(audit.NoopSink{}),
		service:    "authorization-policy-service",
	}
}

// WithAudit configures the service's audit emitter and service name.
// Returns the receiver to allow chained construction at the composition
// root. emitter must be non-nil. service is used as Event.Service on
// every emitted policy_evaluated event.
//
// Per ADR-0019 policy_evaluated is a billable event — a durable-sink
// failure surfaces to the caller and the request fails so the meter
// cannot have gaps.
func (s *PolicyService) WithAudit(emitter audit.Emitter, service string) *PolicyService {
	if emitter == nil {
		panic("application: WithAudit called with nil emitter")
	}
	s.emitter = emitter
	if service != "" {
		s.service = service
	}
	return s
}

// GetSubjectPermissions returns all roles assigned to subjectID and the full set of
// permissions those roles grant. Permissions are formatted as "resource:action".
// Returns an empty SubjectPermissions (not an error) when the subject has no policy.
func (s *PolicyService) GetSubjectPermissions(ctx context.Context, subjectID string) (*domain.SubjectPermissions, error) {
	policy, err := s.policyRepo.FindBySubject(ctx, subjectID)
	if err != nil {
		if apperrors.IsNotFound(err) {
			return &domain.SubjectPermissions{SubjectID: subjectID, Roles: []string{}, Permissions: []string{}}, nil
		}
		return nil, fmt.Errorf("finding policy for subject %q: %w", subjectID, err)
	}

	permissions, err := s.collectPermissions(ctx, policy.Roles)
	if err != nil {
		return nil, err
	}

	return &domain.SubjectPermissions{
		SubjectID:   subjectID,
		Roles:       policy.Roles,
		Permissions: permissions,
	}, nil
}

// collectPermissions resolves the deduplicated permission set for a list of role names.
// Unknown roles (not found in the repository) are silently skipped — see CLAUDE.md.
// Permissions are formatted as "resource:action". Extracted from GetSubjectPermissions
// to keep its cyclomatic complexity within bounds.
func (s *PolicyService) collectPermissions(ctx context.Context, roles []string) ([]string, error) {
	seen := make(map[string]struct{})
	var permissions []string
	for _, roleName := range roles {
		role, err := s.roleRepo.FindByName(ctx, roleName)
		if err != nil {
			if apperrors.IsNotFound(err) {
				continue // role assigned but not defined — skip silently
			}
			return nil, fmt.Errorf("finding role %q: %w", roleName, err)
		}
		for _, perm := range role.Permissions {
			key := perm.Resource + ":" + perm.Action
			if _, exists := seen[key]; !exists {
				seen[key] = struct{}{}
				permissions = append(permissions, key)
			}
		}
	}
	if permissions == nil {
		permissions = []string{}
	}
	return permissions, nil
}

// Evaluate checks whether the subject in req is permitted to perform the requested action.
// Every evaluation emits a policy_evaluated audit event carrying the
// decision (allow/deny) and the resource taxonomy needed for billing
// per ADR-0018 + ADR-0019.
func (s *PolicyService) Evaluate(ctx context.Context, req domain.EvaluationRequest) (*domain.EvaluationResponse, error) {
	policy, err := s.policyRepo.FindBySubject(ctx, req.SubjectID)
	if err != nil {
		if apperrors.IsNotFound(err) {
			resp := &domain.EvaluationResponse{Allowed: false, Reason: "no policy found for subject"}
			if emitErr := s.emit(ctx, req, resp); emitErr != nil {
				return nil, fmt.Errorf("audit emit (policy_evaluated): %w", emitErr)
			}
			return resp, nil
		}
		return nil, fmt.Errorf("finding policy for subject %q: %w", req.SubjectID, err)
	}

	spec := newPermissionSpecification(s.roleRepo, req.Resource, req.Action)

	allowed, err := spec.IsSatisfiedBy(ctx, policy.Roles)
	if err != nil {
		return nil, fmt.Errorf("evaluating permissions: %w", err)
	}
	var resp *domain.EvaluationResponse
	if allowed {
		resp = &domain.EvaluationResponse{Allowed: true}
	} else {
		resp = &domain.EvaluationResponse{Allowed: false, Reason: "insufficient permissions"}
	}
	if emitErr := s.emit(ctx, req, resp); emitErr != nil {
		return nil, fmt.Errorf("audit emit (policy_evaluated): %w", emitErr)
	}
	return resp, nil
}

// emit constructs and dispatches the policy_evaluated event. The
// decision field reflects the authorization outcome itself — this is the
// one event type where decision genuinely tracks allow/deny rather than
// "the caller was authenticated".
func (s *PolicyService) emit(ctx context.Context, req domain.EvaluationRequest, resp *domain.EvaluationResponse) error {
	decision := audit.DecisionAllow
	if !resp.Allowed {
		decision = audit.DecisionDeny
	}
	return s.emitter.Emit(ctx, audit.Event{
		EventType:      "policy_evaluated",
		Service:        s.service,
		ActorType:      audit.ActorTypeService,
		ActorID:        policyCallerActor,
		SubjectID:      req.SubjectID,
		Resource:       "endpoint:evaluate",
		ResourceKind:   audit.ResourceKindEndpoint,
		ResourceID:     "evaluate",
		ResourceParent: s.service,
		ResourcePath:   s.service + "/endpoint/evaluate",
		Action:         "evaluate",
		Decision:       decision,
		Reason:         resp.Reason,
		Attrs: map[string]any{
			"requested_resource": req.Resource,
			"requested_action":   req.Action,
		},
	})
}
