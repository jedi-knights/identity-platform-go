package application_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jedi-knights/go-platform/apperrors"
	"github.com/jedi-knights/go-platform/audit"

	"github.com/ocrosby/identity-platform-go/services/authorization-policy-service/internal/application"
	"github.com/ocrosby/identity-platform-go/services/authorization-policy-service/internal/domain"
)

type fakePolicyRepo struct {
	policies map[string]*domain.Policy
}

func newFakePolicyRepo() *fakePolicyRepo {
	return &fakePolicyRepo{policies: make(map[string]*domain.Policy)}
}

func (f *fakePolicyRepo) FindBySubject(_ context.Context, subjectID string) (*domain.Policy, error) {
	p, ok := f.policies[subjectID]
	if !ok {
		return nil, apperrors.New(apperrors.ErrCodeNotFound, "policy not found for subject: "+subjectID)
	}
	return p, nil
}

func (f *fakePolicyRepo) Save(_ context.Context, p *domain.Policy) error {
	f.policies[p.SubjectID] = p
	return nil
}

type fakeRoleRepo struct {
	roles map[string]*domain.Role
}

func newFakeRoleRepo() *fakeRoleRepo {
	return &fakeRoleRepo{roles: make(map[string]*domain.Role)}
}

func (f *fakeRoleRepo) FindByName(_ context.Context, name string) (*domain.Role, error) {
	r, ok := f.roles[name]
	if !ok {
		return nil, apperrors.New(apperrors.ErrCodeNotFound, "role not found: "+name)
	}
	return r, nil
}

func (f *fakeRoleRepo) Save(_ context.Context, r *domain.Role) error {
	f.roles[r.Name] = r
	return nil
}

// assertSubjectPermissions validates that result contains exactly the expected roles and
// permissions. Permissions are compared as a set because deduplication order is not
// guaranteed. Extracted from TestPolicyService_GetSubjectPermissions to keep its
// cyclomatic complexity within the project limit of 7.
func assertSubjectPermissions(t *testing.T, result *domain.SubjectPermissions, subjectID string, wantRoles, wantPermissions []string) {
	t.Helper()
	if result.SubjectID != subjectID {
		t.Errorf("SubjectID = %q, want %q", result.SubjectID, subjectID)
	}
	if len(result.Roles) != len(wantRoles) {
		t.Errorf("Roles = %v, want %v", result.Roles, wantRoles)
	}
	gotPerms := make(map[string]struct{}, len(result.Permissions))
	for _, p := range result.Permissions {
		gotPerms[p] = struct{}{}
	}
	for _, want := range wantPermissions {
		if _, ok := gotPerms[want]; !ok {
			t.Errorf("permission %q missing from result %v", want, result.Permissions)
		}
	}
	if len(result.Permissions) != len(wantPermissions) {
		t.Errorf("len(Permissions) = %d, want %d: got %v", len(result.Permissions), len(wantPermissions), result.Permissions)
	}
}

func TestPolicyService_GetSubjectPermissions(t *testing.T) {
	adminRole := &domain.Role{
		Name: "admin",
		Permissions: []domain.Permission{
			{Resource: "articles", Action: "read"},
			{Resource: "articles", Action: "write"},
		},
	}
	readerRole := &domain.Role{
		Name: "reader",
		Permissions: []domain.Permission{
			{Resource: "articles", Action: "read"},
		},
	}

	tests := []struct {
		name            string
		setupPolicy     func(*fakePolicyRepo)
		setupRole       func(*fakeRoleRepo)
		subjectID       string
		wantRoles       []string
		wantPermissions []string
		wantErr         bool
	}{
		{
			name:            "returns empty permissions when subject has no policy",
			setupPolicy:     func(*fakePolicyRepo) {},
			setupRole:       func(*fakeRoleRepo) {},
			subjectID:       "unknown-subject",
			wantRoles:       []string{},
			wantPermissions: []string{},
		},
		{
			name: "returns permissions for subject with single role",
			setupPolicy: func(r *fakePolicyRepo) {
				r.policies["user-123"] = &domain.Policy{SubjectID: "user-123", Roles: []string{"reader"}}
			},
			setupRole:       func(r *fakeRoleRepo) { r.roles["reader"] = readerRole },
			subjectID:       "user-123",
			wantRoles:       []string{"reader"},
			wantPermissions: []string{"articles:read"},
		},
		{
			name: "returns deduplicated permissions for subject with multiple roles",
			setupPolicy: func(r *fakePolicyRepo) {
				r.policies["user-multi"] = &domain.Policy{SubjectID: "user-multi", Roles: []string{"reader", "admin"}}
			},
			setupRole: func(r *fakeRoleRepo) {
				r.roles["reader"] = readerRole
				r.roles["admin"] = adminRole
			},
			subjectID:       "user-multi",
			wantRoles:       []string{"reader", "admin"},
			wantPermissions: []string{"articles:read", "articles:write"},
		},
		{
			name: "skips undefined roles and returns empty permissions",
			setupPolicy: func(r *fakePolicyRepo) {
				r.policies["user-ghost"] = &domain.Policy{SubjectID: "user-ghost", Roles: []string{"nonexistent"}}
			},
			setupRole:       func(*fakeRoleRepo) {},
			subjectID:       "user-ghost",
			wantRoles:       []string{"nonexistent"},
			wantPermissions: []string{},
		},
		{
			name: "returns empty permissions when subject has no roles",
			setupPolicy: func(r *fakePolicyRepo) {
				r.policies["user-empty"] = &domain.Policy{SubjectID: "user-empty", Roles: []string{}}
			},
			setupRole:       func(*fakeRoleRepo) {},
			subjectID:       "user-empty",
			wantRoles:       []string{},
			wantPermissions: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policyRepo := newFakePolicyRepo()
			roleRepo := newFakeRoleRepo()
			tt.setupPolicy(policyRepo)
			tt.setupRole(roleRepo)

			svc := application.NewPolicyService(policyRepo, roleRepo)
			result, err := svc.GetSubjectPermissions(context.Background(), tt.subjectID)

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			assertSubjectPermissions(t, result, tt.subjectID, tt.wantRoles, tt.wantPermissions)
		})
	}
}

func TestPolicyService_Evaluate(t *testing.T) {
	adminRole := &domain.Role{
		Name: "admin",
		Permissions: []domain.Permission{
			{Resource: "articles", Action: "read"},
			{Resource: "articles", Action: "write"},
		},
	}
	readerRole := &domain.Role{
		Name: "reader",
		Permissions: []domain.Permission{
			{Resource: "articles", Action: "read"},
		},
	}

	tests := []struct {
		name        string
		setupPolicy func(*fakePolicyRepo)
		setupRole   func(*fakeRoleRepo)
		req         domain.EvaluationRequest
		wantAllowed bool
		wantErr     bool
	}{
		{
			name: "allowed when role grants permission",
			setupPolicy: func(r *fakePolicyRepo) {
				r.policies["user-123"] = &domain.Policy{SubjectID: "user-123", Roles: []string{"admin"}}
			},
			setupRole:   func(r *fakeRoleRepo) { r.roles["admin"] = adminRole },
			req:         domain.EvaluationRequest{SubjectID: "user-123", Resource: "articles", Action: "read"},
			wantAllowed: true,
		},
		{
			name:        "denied when no policy found for subject",
			setupPolicy: func(*fakePolicyRepo) {},
			setupRole:   func(*fakeRoleRepo) {},
			req:         domain.EvaluationRequest{SubjectID: "unknown-user", Resource: "articles", Action: "write"},
			wantAllowed: false,
		},
		{
			name: "denied when role does not grant requested permission",
			setupPolicy: func(r *fakePolicyRepo) {
				r.policies["user-456"] = &domain.Policy{SubjectID: "user-456", Roles: []string{"reader"}}
			},
			setupRole:   func(r *fakeRoleRepo) { r.roles["reader"] = readerRole },
			req:         domain.EvaluationRequest{SubjectID: "user-456", Resource: "articles", Action: "delete"},
			wantAllowed: false,
		},
		{
			name: "denied when subject has no roles",
			setupPolicy: func(r *fakePolicyRepo) {
				r.policies["user-789"] = &domain.Policy{SubjectID: "user-789", Roles: []string{}}
			},
			setupRole:   func(*fakeRoleRepo) {},
			req:         domain.EvaluationRequest{SubjectID: "user-789", Resource: "articles", Action: "read"},
			wantAllowed: false,
		},
		{
			name: "allowed when second role grants permission",
			setupPolicy: func(r *fakePolicyRepo) {
				r.policies["user-multi"] = &domain.Policy{SubjectID: "user-multi", Roles: []string{"reader", "admin"}}
			},
			setupRole: func(r *fakeRoleRepo) {
				r.roles["reader"] = readerRole
				r.roles["admin"] = adminRole
			},
			req:         domain.EvaluationRequest{SubjectID: "user-multi", Resource: "articles", Action: "write"},
			wantAllowed: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policyRepo := newFakePolicyRepo()
			roleRepo := newFakeRoleRepo()
			tt.setupPolicy(policyRepo)
			tt.setupRole(roleRepo)

			svc := application.NewPolicyService(policyRepo, roleRepo)
			resp, err := svc.Evaluate(context.Background(), tt.req)

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if resp.Allowed != tt.wantAllowed {
				t.Errorf("Allowed = %v, want %v (reason: %q)", resp.Allowed, tt.wantAllowed, resp.Reason)
			}
		})
	}
}

// --- Audit emission (ADR-0018 / ADR-0019) ---

type captureSink struct {
	events []audit.Event
	err    error
}

func (c *captureSink) Sink(_ context.Context, e audit.Event) error {
	c.events = append(c.events, e)
	return c.err
}

var errAuditFailure = errors.New("simulated audit transport failure")

func TestEvaluate_EmitsPolicyEvaluated_Allow(t *testing.T) {
	policyRepo := newFakePolicyRepo()
	roleRepo := newFakeRoleRepo()
	roleRepo.roles["editor"] = &domain.Role{
		Name: "editor",
		Permissions: []domain.Permission{
			{Resource: "articles", Action: "write"},
		},
	}
	policyRepo.policies["u-1"] = &domain.Policy{
		SubjectID: "u-1",
		Roles:     []string{"editor"},
	}
	sink := &captureSink{}
	svc := application.NewPolicyService(policyRepo, roleRepo).
		WithAudit(audit.New(sink), "authorization-policy-service")

	resp, err := svc.Evaluate(context.Background(), domain.EvaluationRequest{
		SubjectID: "u-1",
		Resource:  "articles",
		Action:    "write",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Allowed {
		t.Fatalf("expected allowed=true, got %v (reason: %q)", resp.Allowed, resp.Reason)
	}
	if len(sink.events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(sink.events))
	}
	e := sink.events[0]
	if e.EventType != "policy_evaluated" {
		t.Errorf("event_type = %q, want policy_evaluated", e.EventType)
	}
	if e.Decision != audit.DecisionAllow {
		t.Errorf("decision = %q, want allow", e.Decision)
	}
	if e.SubjectID != "u-1" {
		t.Errorf("subject_id = %q, want u-1", e.SubjectID)
	}
	if e.ResourcePath != "authorization-policy-service/endpoint/evaluate" {
		t.Errorf("resource_path = %q, want authorization-policy-service/endpoint/evaluate", e.ResourcePath)
	}
	if r, _ := e.Attrs["requested_resource"].(string); r != "articles" {
		t.Errorf("attrs.requested_resource = %v, want articles", e.Attrs["requested_resource"])
	}
	if a, _ := e.Attrs["requested_action"].(string); a != "write" {
		t.Errorf("attrs.requested_action = %v, want write", e.Attrs["requested_action"])
	}
}

func TestEvaluate_EmitsPolicyEvaluated_Deny_InsufficientPermissions(t *testing.T) {
	policyRepo := newFakePolicyRepo()
	roleRepo := newFakeRoleRepo()
	roleRepo.roles["reader"] = &domain.Role{
		Name: "reader",
		Permissions: []domain.Permission{
			{Resource: "articles", Action: "read"},
		},
	}
	policyRepo.policies["u-1"] = &domain.Policy{
		SubjectID: "u-1",
		Roles:     []string{"reader"},
	}
	sink := &captureSink{}
	svc := application.NewPolicyService(policyRepo, roleRepo).
		WithAudit(audit.New(sink), "authorization-policy-service")

	resp, err := svc.Evaluate(context.Background(), domain.EvaluationRequest{
		SubjectID: "u-1",
		Resource:  "articles",
		Action:    "write",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Allowed {
		t.Fatal("expected deny")
	}
	if len(sink.events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(sink.events))
	}
	e := sink.events[0]
	if e.Decision != audit.DecisionDeny {
		t.Errorf("decision = %q, want deny", e.Decision)
	}
	if e.Reason != "insufficient permissions" {
		t.Errorf("reason = %q, want insufficient permissions", e.Reason)
	}
}

func TestEvaluate_EmitsPolicyEvaluated_Deny_NoPolicy(t *testing.T) {
	policyRepo := newFakePolicyRepo()
	roleRepo := newFakeRoleRepo()
	sink := &captureSink{}
	svc := application.NewPolicyService(policyRepo, roleRepo).
		WithAudit(audit.New(sink), "authorization-policy-service")

	resp, err := svc.Evaluate(context.Background(), domain.EvaluationRequest{
		SubjectID: "unknown-subject",
		Resource:  "articles",
		Action:    "read",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Allowed {
		t.Fatal("expected deny on missing policy")
	}
	if len(sink.events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(sink.events))
	}
	if sink.events[0].Decision != audit.DecisionDeny {
		t.Errorf("decision = %q, want deny", sink.events[0].Decision)
	}
	if sink.events[0].Reason != "no policy found for subject" {
		t.Errorf("reason = %q, want no policy found for subject", sink.events[0].Reason)
	}
}

func TestEvaluate_AuditFailureSurfaces(t *testing.T) {
	policyRepo := newFakePolicyRepo()
	roleRepo := newFakeRoleRepo()
	sink := &captureSink{err: errAuditFailure}
	svc := application.NewPolicyService(policyRepo, roleRepo).
		WithAudit(audit.New(sink), "authorization-policy-service")

	_, err := svc.Evaluate(context.Background(), domain.EvaluationRequest{
		SubjectID: "u-1",
		Resource:  "articles",
		Action:    "read",
	})
	if err == nil {
		t.Fatal("expected error when audit emit fails")
	}
	if !errors.Is(err, errAuditFailure) {
		t.Errorf("expected wrapped audit error, got %v", err)
	}
}

func TestPolicyService_WithAudit_NilEmitterPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic")
		}
	}()
	_ = application.NewPolicyService(newFakePolicyRepo(), newFakeRoleRepo()).
		WithAudit(nil, "authorization-policy-service")
}
