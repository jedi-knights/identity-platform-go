package domain_test

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/domain"
)

func TestParseAuthorizationDetails_EmptyReturnsNil(t *testing.T) {
	got, err := domain.ParseAuthorizationDetails("")
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if got != nil {
		t.Errorf("expected nil slice, got %v", got)
	}
}

func TestParseAuthorizationDetails_AcceptsKnownTypes(t *testing.T) {
	raw := `[{"type":"mcp_tool","tool":"get_standings"},{"type":"resource","actions":["read"]}]`
	got, err := domain.ParseAuthorizationDetails(raw)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}
	if got[0].Type != domain.AuthorizationDetailTypeMCPTool {
		t.Errorf("got[0].Type = %q", got[0].Type)
	}
	if got[1].Type != domain.AuthorizationDetailTypeResource {
		t.Errorf("got[1].Type = %q", got[1].Type)
	}
}

func TestParseAuthorizationDetails_PreservesRawJSON(t *testing.T) {
	raw := `[{"type":"mcp_tool","tool":"x","constraints":{"team":"1234"}}]`
	got, err := domain.ParseAuthorizationDetails(raw)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(string(got[0].Raw), `"team":"1234"`) {
		t.Errorf("raw payload not preserved: %s", got[0].Raw)
	}
}

func TestParseAuthorizationDetails_RejectsMalformedJSON(t *testing.T) {
	_, err := domain.ParseAuthorizationDetails("not-json")
	if !errors.Is(err, domain.ErrInvalidAuthorizationDetails) {
		t.Errorf("err = %v, want ErrInvalidAuthorizationDetails", err)
	}
}

func TestParseAuthorizationDetails_RejectsNonArray(t *testing.T) {
	_, err := domain.ParseAuthorizationDetails(`{"type":"mcp_tool"}`)
	if !errors.Is(err, domain.ErrInvalidAuthorizationDetails) {
		t.Errorf("err = %v, want ErrInvalidAuthorizationDetails", err)
	}
}

func TestParseAuthorizationDetails_RejectsMissingType(t *testing.T) {
	_, err := domain.ParseAuthorizationDetails(`[{"tool":"x"}]`)
	if !errors.Is(err, domain.ErrInvalidAuthorizationDetails) {
		t.Errorf("err = %v, want ErrInvalidAuthorizationDetails", err)
	}
}

func TestParseAuthorizationDetails_RejectsUnknownType(t *testing.T) {
	_, err := domain.ParseAuthorizationDetails(`[{"type":"payment","amount":50}]`)
	if !errors.Is(err, domain.ErrInvalidAuthorizationDetails) {
		t.Errorf("err = %v, want ErrInvalidAuthorizationDetails", err)
	}
}

func TestParseAuthorizationDetails_RejectsNonObjectElement(t *testing.T) {
	_, err := domain.ParseAuthorizationDetails(`["mcp_tool"]`)
	if !errors.Is(err, domain.ErrInvalidAuthorizationDetails) {
		t.Errorf("err = %v, want ErrInvalidAuthorizationDetails", err)
	}
}

func TestAuthorizationDetailsToRaw_NilForEmpty(t *testing.T) {
	got := domain.AuthorizationDetailsToRaw(nil)
	if got != nil {
		t.Errorf("expected nil for empty input, got %v", got)
	}
}

func TestAuthorizationDetailsToRaw_PreservesByteForByte(t *testing.T) {
	in := []domain.AuthorizationDetail{
		{Type: "mcp_tool", Raw: json.RawMessage(`{"type":"mcp_tool","tool":"x"}`)},
	}
	got := domain.AuthorizationDetailsToRaw(in)
	if len(got) != 1 {
		t.Fatalf("len = %d", len(got))
	}
	if string(got[0]) != `{"type":"mcp_tool","tool":"x"}` {
		t.Errorf("wire form changed: %s", got[0])
	}
}

func TestSupportedAuthorizationDetailTypes_HasBothPlatformTypes(t *testing.T) {
	if !slices.Contains(domain.SupportedAuthorizationDetailTypes, "mcp_tool") {
		t.Error("registry missing mcp_tool")
	}
	if !slices.Contains(domain.SupportedAuthorizationDetailTypes, "resource") {
		t.Error("registry missing resource")
	}
}

// ---------------------------------------------------------------------------
// Per-type schema validation (ADR-0017)
// ---------------------------------------------------------------------------

func TestParseAuthorizationDetails_MCPTool_RejectsMissingTool(t *testing.T) {
	_, err := domain.ParseAuthorizationDetails(`[{"type":"mcp_tool"}]`)
	if !errors.Is(err, domain.ErrInvalidAuthorizationDetails) {
		t.Errorf("err = %v, want ErrInvalidAuthorizationDetails", err)
	}
	if !strings.Contains(err.Error(), "tool is required") {
		t.Errorf("err = %v, want message naming the required field", err)
	}
}

func TestParseAuthorizationDetails_MCPTool_AcceptsValidActions(t *testing.T) {
	raw := `[{"type":"mcp_tool","tool":"get_standings","actions":["read","invoke"]}]`
	if _, err := domain.ParseAuthorizationDetails(raw); err != nil {
		t.Errorf("err = %v, want nil for in-range actions", err)
	}
}

func TestParseAuthorizationDetails_MCPTool_RejectsUnknownAction(t *testing.T) {
	raw := `[{"type":"mcp_tool","tool":"get_standings","actions":["delete"]}]`
	_, err := domain.ParseAuthorizationDetails(raw)
	if !errors.Is(err, domain.ErrInvalidAuthorizationDetails) {
		t.Errorf("err = %v, want ErrInvalidAuthorizationDetails", err)
	}
}

func TestParseAuthorizationDetails_MCPTool_AcceptsPositiveExpiresIn(t *testing.T) {
	raw := `[{"type":"mcp_tool","tool":"get_standings","expires_in":300}]`
	if _, err := domain.ParseAuthorizationDetails(raw); err != nil {
		t.Errorf("err = %v, want nil", err)
	}
}

func TestParseAuthorizationDetails_MCPTool_RejectsNonPositiveExpiresIn(t *testing.T) {
	raw := `[{"type":"mcp_tool","tool":"get_standings","expires_in":0}]`
	_, err := domain.ParseAuthorizationDetails(raw)
	if !errors.Is(err, domain.ErrInvalidAuthorizationDetails) {
		t.Errorf("err = %v, want ErrInvalidAuthorizationDetails", err)
	}
}

func TestParseAuthorizationDetails_MCPTool_AcceptsFreeFormConstraints(t *testing.T) {
	// constraints is free-form per ADR-0017 — the validator must
	// not inspect its shape so resource servers can branch on
	// operator-defined keys without coordinating a parser change.
	raw := `[{"type":"mcp_tool","tool":"get_standings","constraints":{"team":"1234","scope":"current"}}]`
	if _, err := domain.ParseAuthorizationDetails(raw); err != nil {
		t.Errorf("err = %v, want nil for free-form constraints", err)
	}
}

func TestParseAuthorizationDetails_Resource_AcceptsLocationsOnly(t *testing.T) {
	raw := `[{"type":"resource","locations":["https://api.example.com/v1"]}]`
	if _, err := domain.ParseAuthorizationDetails(raw); err != nil {
		t.Errorf("err = %v, want nil", err)
	}
}

func TestParseAuthorizationDetails_Resource_AcceptsDatatypesOnly(t *testing.T) {
	raw := `[{"type":"resource","datatypes":["account"]}]`
	if _, err := domain.ParseAuthorizationDetails(raw); err != nil {
		t.Errorf("err = %v, want nil", err)
	}
}

func TestParseAuthorizationDetails_Resource_RejectsEmpty(t *testing.T) {
	// A resource entry with no constraints expresses nothing —
	// reject so clients catch the shape error at the auth-server
	// instead of having resource servers silently ignore it.
	_, err := domain.ParseAuthorizationDetails(`[{"type":"resource"}]`)
	if !errors.Is(err, domain.ErrInvalidAuthorizationDetails) {
		t.Errorf("err = %v, want ErrInvalidAuthorizationDetails", err)
	}
}
