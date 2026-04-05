package application_test

import (
	"context"
	"testing"

	apperrors "github.com/ocrosby/identity-platform-go/libs/errors"
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
