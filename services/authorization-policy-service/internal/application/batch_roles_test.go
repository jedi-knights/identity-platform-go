package application_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jedi-knights/go-platform/audit"

	"github.com/ocrosby/identity-platform-go/services/authorization-policy-service/internal/application"
	"github.com/ocrosby/identity-platform-go/services/authorization-policy-service/internal/domain"
)

// countingRoleRepo wraps the shared fake, counts how roles are fetched, and can
// return batched results in reverse order to prove callers do not depend on
// repository ordering.
type countingRoleRepo struct {
	*fakeRoleRepo
	byNameCalls  int
	byNamesCalls int
	reverse      bool
	err          error
}

func (c *countingRoleRepo) FindByName(ctx context.Context, name string) (*domain.Role, error) {
	c.byNameCalls++
	return c.fakeRoleRepo.FindByName(ctx, name)
}

func (c *countingRoleRepo) FindByNames(_ context.Context, names []string) ([]*domain.Role, error) {
	c.byNamesCalls++
	if c.err != nil {
		return nil, c.err
	}
	var out []*domain.Role
	for _, n := range names {
		if r, ok := c.roles[n]; ok {
			out = append(out, r)
		}
	}
	if c.reverse {
		for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
			out[i], out[j] = out[j], out[i]
		}
	}
	return out, nil
}

func grant(name, resource, action string) *domain.Role {
	return &domain.Role{Name: name, Permissions: []domain.Permission{{Resource: resource, Action: action}}}
}

func newBatchFixture(roles ...*domain.Role) (*fakePolicyRepo, *countingRoleRepo) {
	rr := &countingRoleRepo{fakeRoleRepo: newFakeRoleRepo()}
	var names []string
	for _, r := range roles {
		rr.roles[r.Name] = r
		names = append(names, r.Name)
	}
	pr := newFakePolicyRepo()
	pr.policies["u-1"] = &domain.Policy{SubjectID: "u-1", Roles: names}
	return pr, rr
}

func TestEvaluate_LooksUpAllRolesInOneQuery(t *testing.T) {
	pr, rr := newBatchFixture(
		grant("r1", "a", "x"), grant("r2", "b", "x"), grant("r3", "c", "x"),
		grant("r4", "d", "x"), grant("r5", "e", "x"),
	)
	svc := application.NewPolicyService(pr, rr).WithAudit(audit.New(&captureSink{}), "svc")

	resp, err := svc.Evaluate(context.Background(), domain.EvaluationRequest{SubjectID: "u-1", Resource: "zzz", Action: "x"})

	if err != nil || resp.Allowed {
		t.Fatalf("want a clean deny, got resp=%+v err=%v", resp, err)
	}
	if rr.byNameCalls != 0 || rr.byNamesCalls != 1 {
		t.Fatalf("role lookups: FindByName=%d FindByNames=%d; want 0 and 1 for 5 roles", rr.byNameCalls, rr.byNamesCalls)
	}
}

func TestEvaluate_MatchedRoleFollowsSubjectOrderNotRepositoryOrder(t *testing.T) {
	pr, rr := newBatchFixture(grant("first", "doc", "read"), grant("second", "doc", "read"))
	rr.reverse = true
	sink := &captureSink{}
	svc := application.NewPolicyService(pr, rr).WithAudit(audit.New(sink), "svc")

	resp, err := svc.Evaluate(context.Background(), domain.EvaluationRequest{SubjectID: "u-1", Resource: "doc", Action: "read"})

	if err != nil || !resp.Allowed {
		t.Fatalf("want allow, got resp=%+v err=%v", resp, err)
	}
	if got, _ := sink.events[0].Attrs["matched_rule"].(string); got != "role:first" {
		t.Fatalf("matched_rule = %q, want role:first (subject order decides)", got)
	}
}

func TestEvaluate_UnknownRolesAreSkipped(t *testing.T) {
	pr, rr := newBatchFixture(grant("real", "doc", "read"))
	pr.policies["u-1"].Roles = []string{"ghost", "real"}
	svc := application.NewPolicyService(pr, rr).WithAudit(audit.New(&captureSink{}), "svc")

	resp, err := svc.Evaluate(context.Background(), domain.EvaluationRequest{SubjectID: "u-1", Resource: "doc", Action: "read"})

	if err != nil || !resp.Allowed {
		t.Fatalf("want allow despite an unknown role, got resp=%+v err=%v", resp, err)
	}
}

func TestEvaluate_RoleLookupFailureIsAnErrorNotADeny(t *testing.T) {
	pr, rr := newBatchFixture(grant("r1", "doc", "read"))
	rr.err = errors.New("db down")
	svc := application.NewPolicyService(pr, rr).WithAudit(audit.New(&captureSink{}), "svc")

	_, err := svc.Evaluate(context.Background(), domain.EvaluationRequest{SubjectID: "u-1", Resource: "doc", Action: "read"})

	if err == nil {
		t.Fatal("expected an infrastructure error, got nil (must not fail open or silently deny)")
	}
}

func TestGetSubjectPermissions_LooksUpAllRolesInOneQueryAndDeduplicates(t *testing.T) {
	pr, rr := newBatchFixture(grant("r1", "doc", "read"), grant("r2", "doc", "read"), grant("r3", "doc", "write"))
	svc := application.NewPolicyService(pr, rr)

	got, err := svc.GetSubjectPermissions(context.Background(), "u-1")

	if err != nil {
		t.Fatalf("GetSubjectPermissions: %v", err)
	}
	if rr.byNameCalls != 0 || rr.byNamesCalls != 1 {
		t.Fatalf("role lookups: FindByName=%d FindByNames=%d; want 0 and 1", rr.byNameCalls, rr.byNamesCalls)
	}
	if len(got.Permissions) != 2 {
		t.Fatalf("permissions = %v, want 2 deduplicated entries", got.Permissions)
	}
}
