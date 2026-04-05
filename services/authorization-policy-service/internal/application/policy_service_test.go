package application_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/ocrosby/identity-platform-go/services/authorization-policy-service/internal/application"
	"github.com/ocrosby/identity-platform-go/services/authorization-policy-service/internal/domain"
)

type mockPolicyRepo struct {
	policies map[string]*domain.Policy
}

func newMockPolicyRepo() *mockPolicyRepo {
	return &mockPolicyRepo{policies: make(map[string]*domain.Policy)}
}

func (m *mockPolicyRepo) FindBySubject(_ context.Context, subjectID string) (*domain.Policy, error) {
	p, ok := m.policies[subjectID]
	if !ok {
		return nil, fmt.Errorf("policy not found for subject: %s", subjectID)
	}
	return p, nil
}

func (m *mockPolicyRepo) Save(_ context.Context, p *domain.Policy) error {
	m.policies[p.SubjectID] = p
	return nil
}

type mockRoleRepo struct {
	roles map[string]*domain.Role
}

func newMockRoleRepo() *mockRoleRepo {
	return &mockRoleRepo{roles: make(map[string]*domain.Role)}
}

func (m *mockRoleRepo) FindByName(_ context.Context, name string) (*domain.Role, error) {
	r, ok := m.roles[name]
	if !ok {
		return nil, fmt.Errorf("role not found: %s", name)
	}
	return r, nil
}

func (m *mockRoleRepo) Save(_ context.Context, r *domain.Role) error {
	m.roles[r.Name] = r
	return nil
}

func TestPolicyService_Evaluate_Allowed(t *testing.T) {
	policyRepo := newMockPolicyRepo()
	roleRepo := newMockRoleRepo()

	roleRepo.roles["admin"] = &domain.Role{
		Name: "admin",
		Permissions: []domain.Permission{
			{Resource: "articles", Action: "read"},
		},
	}
	policyRepo.policies["user-123"] = &domain.Policy{
		SubjectID: "user-123",
		Roles:     []string{"admin"},
	}

	svc := application.NewPolicyService(policyRepo, roleRepo)
	resp, err := svc.Evaluate(context.Background(), domain.EvaluationRequest{
		SubjectID: "user-123",
		Resource:  "articles",
		Action:    "read",
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Allowed {
		t.Errorf("expected Allowed=true, got false. Reason: %s", resp.Reason)
	}
}

func TestPolicyService_Evaluate_Denied_NoPolicyFound(t *testing.T) {
	policyRepo := newMockPolicyRepo()
	roleRepo := newMockRoleRepo()

	svc := application.NewPolicyService(policyRepo, roleRepo)
	resp, err := svc.Evaluate(context.Background(), domain.EvaluationRequest{
		SubjectID: "unknown-user",
		Resource:  "articles",
		Action:    "write",
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Allowed {
		t.Error("expected Allowed=false for unknown subject")
	}
}

func TestPolicyService_Evaluate_Denied_PermissionMismatch(t *testing.T) {
	policyRepo := newMockPolicyRepo()
	roleRepo := newMockRoleRepo()

	roleRepo.roles["reader"] = &domain.Role{
		Name: "reader",
		Permissions: []domain.Permission{
			{Resource: "articles", Action: "read"},
		},
	}
	policyRepo.policies["user-456"] = &domain.Policy{
		SubjectID: "user-456",
		Roles:     []string{"reader"},
	}

	svc := application.NewPolicyService(policyRepo, roleRepo)
	resp, err := svc.Evaluate(context.Background(), domain.EvaluationRequest{
		SubjectID: "user-456",
		Resource:  "articles",
		Action:    "delete",
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Allowed {
		t.Error("expected Allowed=false for delete when only read is granted")
	}
}
