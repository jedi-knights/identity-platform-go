package application_test

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/application"
)

func TestProjectScopesToPlanScope_RecognizesEveryPrefix(t *testing.T) {
	t.Parallel()
	scopes := []string{
		"tier:pro",
		"sport:soccer-women", "sport:soccer-men",
		"div:d1", "div:d2",
		"group:standings", "group:people",
		"feature:player_journey",
		"history-depth:1",
	}
	got := application.ProjectScopesToPlanScope(scopes)
	want := application.PlanScope{
		Tier:           "pro",
		Sports:         []string{"soccer-women", "soccer-men"},
		Divisions:      []string{"d1", "d2"},
		EndpointGroups: []string{"standings", "people"},
		Features:       []string{"player_journey"},
		HistoryDepth:   1,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v\nwant %+v", got, want)
	}
}

func TestProjectScopesToPlanScope_IgnoresUnknownPrefixes(t *testing.T) {
	t.Parallel()
	scopes := []string{"tier:free", "openid", "offline_access", "unexpected:value"}
	got := application.ProjectScopesToPlanScope(scopes)
	if got.Tier != "free" {
		t.Errorf("Tier = %q, want free", got.Tier)
	}
	if len(got.Sports) != 0 || len(got.Divisions) != 0 {
		t.Errorf("non-prefixed scopes leaked into PlanScope: %+v", got)
	}
}

func TestProjectScopesToPlanScope_DedupesLists(t *testing.T) {
	t.Parallel()
	scopes := []string{"sport:soccer-women", "sport:soccer-women", "div:d1", "div:d1"}
	got := application.ProjectScopesToPlanScope(scopes)
	if !reflect.DeepEqual(got.Sports, []string{"soccer-women"}) {
		t.Errorf("Sports = %v, want [soccer-women]", got.Sports)
	}
	if !reflect.DeepEqual(got.Divisions, []string{"d1"}) {
		t.Errorf("Divisions = %v, want [d1]", got.Divisions)
	}
}

func TestProjectScopesToPlanScope_LastTierWinsOnCollision(t *testing.T) {
	t.Parallel()
	got := application.ProjectScopesToPlanScope([]string{"tier:free", "tier:pro"})
	if got.Tier != "pro" {
		t.Errorf("Tier = %q, want pro (last-wins)", got.Tier)
	}
}

func TestProjectScopesToPlanScope_MalformedHistoryDepthResolvesToZero(t *testing.T) {
	t.Parallel()
	got := application.ProjectScopesToPlanScope([]string{"history-depth:nope"})
	if got.HistoryDepth != 0 {
		t.Errorf("HistoryDepth = %d, want 0 for malformed input", got.HistoryDepth)
	}
}

func TestProjectScopesToClaim_EmptyProjectionReturnsNil(t *testing.T) {
	t.Parallel()
	// Only OAuth-standard scopes — none of the recognized prefixes.
	raw, err := application.ProjectScopesToClaim([]string{"openid", "offline_access"})
	if err != nil {
		t.Fatalf("ProjectScopesToClaim: %v", err)
	}
	if raw != nil {
		t.Errorf("raw = %s, want nil (no fields projected)", raw)
	}
}

func TestProjectScopesToClaim_MatchesPlanScopeJSON(t *testing.T) {
	t.Parallel()
	raw, err := application.ProjectScopesToClaim([]string{
		"tier:pro", "sport:soccer-women", "div:d1", "group:standings",
	})
	if err != nil {
		t.Fatalf("ProjectScopesToClaim: %v", err)
	}
	// Resource servers must be able to unmarshal the claim byte-for-
	// byte into a struct with the same field tags; keep the shape
	// documented by round-tripping through a sibling struct.
	var got struct {
		Tier           string   `json:"tier"`
		Sports         []string `json:"sports"`
		Divisions      []string `json:"divisions"`
		EndpointGroups []string `json:"endpoint_groups"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	assertStringEqual(t, "tier", got.Tier, "pro")
	assertSingleton(t, "sports", got.Sports, "soccer-women")
	assertSingleton(t, "divisions", got.Divisions, "d1")
	assertSingleton(t, "endpoint_groups", got.EndpointGroups, "standings")
}

// assertStringEqual fails the test if got != want, naming the field.
func assertStringEqual(t *testing.T, field, got, want string) {
	t.Helper()
	if got != want {
		t.Errorf("%s = %q, want %q", field, got, want)
	}
}

// assertSingleton fails the test if got does not contain exactly one
// element equal to want.
func assertSingleton(t *testing.T, field string, got []string, want string) {
	t.Helper()
	if len(got) != 1 || got[0] != want {
		t.Errorf("%s = %v, want [%s]", field, got, want)
	}
}

// omitempty behavior: a projection with only tier should not emit
// null slices for the unused list-shaped dimensions.
func TestProjectScopesToClaim_OmitemptyKeepsWireCompact(t *testing.T) {
	t.Parallel()
	raw, err := application.ProjectScopesToClaim([]string{"tier:free"})
	if err != nil {
		t.Fatalf("ProjectScopesToClaim: %v", err)
	}
	s := string(raw)
	// The projected object must not carry "sports":null etc. — only
	// the tier field.
	if s != `{"tier":"free"}` {
		t.Errorf("raw = %s, want {\"tier\":\"free\"}", s)
	}
}
