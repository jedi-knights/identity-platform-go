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
