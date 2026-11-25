package application_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/application"
	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/domain"
)

// fakeTokenGenerator captures the token handed to Generate so tests
// can assert on the AdditionalFields the wrapper installed.
type fakeTokenGenerator struct {
	gotToken *domain.Token
	err      error
}

func (f *fakeTokenGenerator) Generate(_ context.Context, token *domain.Token) (string, error) {
	// Deep enough copy for our assertions — we only look at
	// AdditionalFields, which is a shallow map; copying the map is
	// enough to decouple our state from a wrapper that later mutates
	// its local augmented token.
	copyToken := *token
	if token.AdditionalFields != nil {
		copyToken.AdditionalFields = make(map[string]json.RawMessage, len(token.AdditionalFields))
		for k, v := range token.AdditionalFields {
			copyToken.AdditionalFields[k] = v
		}
	}
	f.gotToken = &copyToken
	if f.err != nil {
		return "", f.err
	}
	return "signed-jwt", nil
}

func TestPlanScopeProjectionGenerator_EmptyNamespaceIsPassThrough(t *testing.T) {
	t.Parallel()
	inner := &fakeTokenGenerator{}
	gen := application.NewPlanScopeProjectionGenerator(inner, "")
	tok := &domain.Token{Scopes: []string{"tier:pro"}}
	if _, err := gen.Generate(context.Background(), tok); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(inner.gotToken.AdditionalFields) != 0 {
		t.Errorf("empty namespace must not add fields; got %v", inner.gotToken.AdditionalFields)
	}
}

func TestPlanScopeProjectionGenerator_InjectsAtNamespaceKey(t *testing.T) {
	t.Parallel()
	inner := &fakeTokenGenerator{}
	gen := application.NewPlanScopeProjectionGenerator(inner, "https://thecutline.app/plan_scope")
	tok := &domain.Token{Scopes: []string{"tier:pro", "sport:soccer-women"}}
	if _, err := gen.Generate(context.Background(), tok); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	raw, ok := inner.gotToken.AdditionalFields["https://thecutline.app/plan_scope"]
	if !ok {
		t.Fatalf("plan_scope claim missing; got %v", inner.gotToken.AdditionalFields)
	}
	var ps struct {
		Tier   string   `json:"tier"`
		Sports []string `json:"sports"`
	}
	if err := json.Unmarshal(raw, &ps); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if ps.Tier != "pro" {
		t.Errorf("tier = %q, want pro", ps.Tier)
	}
	if len(ps.Sports) != 1 || ps.Sports[0] != "soccer-women" {
		t.Errorf("sports = %v, want [soccer-women]", ps.Sports)
	}
}

// When every scope is an OAuth-standard scope (no recognised prefix),
// the projection is empty and the claim must be omitted entirely — a
// noise empty-object would ride on every token otherwise.
func TestPlanScopeProjectionGenerator_EmptyProjectionOmitsClaim(t *testing.T) {
	t.Parallel()
	inner := &fakeTokenGenerator{}
	gen := application.NewPlanScopeProjectionGenerator(inner, "https://thecutline.app/plan_scope")
	tok := &domain.Token{Scopes: []string{"openid", "offline_access"}}
	if _, err := gen.Generate(context.Background(), tok); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if _, ok := inner.gotToken.AdditionalFields["https://thecutline.app/plan_scope"]; ok {
		t.Errorf("empty projection must not emit the claim")
	}
}

// Pre-existing AdditionalFields from the caller must survive — the
// wrapper is additive, not replacing. Only the namespace key the
// wrapper owns is overwritten.
func TestPlanScopeProjectionGenerator_PreservesOtherAdditionalFields(t *testing.T) {
	t.Parallel()
	inner := &fakeTokenGenerator{}
	gen := application.NewPlanScopeProjectionGenerator(inner, "https://thecutline.app/plan_scope")
	tok := &domain.Token{
		Scopes: []string{"tier:free"},
		AdditionalFields: map[string]json.RawMessage{
			"https://example.com/other": json.RawMessage(`"keep-me"`),
		},
	}
	if _, err := gen.Generate(context.Background(), tok); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if string(inner.gotToken.AdditionalFields["https://example.com/other"]) != `"keep-me"` {
		t.Errorf("pre-existing field was dropped: %v", inner.gotToken.AdditionalFields)
	}
	if _, ok := inner.gotToken.AdditionalFields["https://thecutline.app/plan_scope"]; !ok {
		t.Errorf("projection missing; got %v", inner.gotToken.AdditionalFields)
	}
}

// Copy-on-write: the caller's token value must not be mutated. Grant
// strategies re-use the same *domain.Token for the refresh-token path
// after generating the access token; leaking additional fields into
// the refresh token would be a data bug.
func TestPlanScopeProjectionGenerator_DoesNotMutateCallerToken(t *testing.T) {
	t.Parallel()
	inner := &fakeTokenGenerator{}
	gen := application.NewPlanScopeProjectionGenerator(inner, "https://thecutline.app/plan_scope")
	tok := &domain.Token{Scopes: []string{"tier:pro"}}
	if _, err := gen.Generate(context.Background(), tok); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if tok.AdditionalFields != nil {
		t.Errorf("caller token was mutated; AdditionalFields = %v", tok.AdditionalFields)
	}
}

func TestPlanScopeProjectionGenerator_PropagatesInnerError(t *testing.T) {
	t.Parallel()
	innerErr := errors.New("inner boom")
	inner := &fakeTokenGenerator{err: innerErr}
	gen := application.NewPlanScopeProjectionGenerator(inner, "https://thecutline.app/plan_scope")
	tok := &domain.Token{Scopes: []string{"tier:pro"}}
	_, err := gen.Generate(context.Background(), tok)
	if !errors.Is(err, innerErr) {
		t.Errorf("err = %v, want %v", err, innerErr)
	}
}
