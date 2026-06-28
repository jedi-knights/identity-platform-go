package application

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/domain"
)

// intersectAuthorizationDetails is unexported; the tests live in the
// same package so the helper can be exercised without inflating the
// public surface.

func detail(t string, body string) domain.AuthorizationDetail {
	return domain.AuthorizationDetail{Type: t, Raw: json.RawMessage(body)}
}

func TestIntersect_BothEmpty_ReturnsNil(t *testing.T) {
	got, err := intersectAuthorizationDetails(nil, nil)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if got != nil {
		t.Errorf("expected nil, got %v", got)
	}
}

func TestIntersect_RequestEmptySubjectPresent_PropagatesSubject(t *testing.T) {
	sub := []domain.AuthorizationDetail{detail("mcp_tool", `{"type":"mcp_tool","tool":"x"}`)}
	got, err := intersectAuthorizationDetails(sub, nil)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if len(got) != 1 || got[0].Type != "mcp_tool" {
		t.Errorf("expected subject details to flow through; got %v", got)
	}
}

func TestIntersect_RequestPresentSubjectEmpty_Rejects(t *testing.T) {
	req := []domain.AuthorizationDetail{detail("mcp_tool", `{"type":"mcp_tool"}`)}
	_, err := intersectAuthorizationDetails(nil, req)
	if !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("err = %v, want ErrInvalidRequest", err)
	}
}

func TestIntersect_RequestSubsetOfSubject_ReturnsRequest(t *testing.T) {
	sub := []domain.AuthorizationDetail{
		detail("mcp_tool", `{"type":"mcp_tool","tool":"x"}`),
		detail("resource", `{"type":"resource"}`),
	}
	req := []domain.AuthorizationDetail{detail("mcp_tool", `{"type":"mcp_tool","tool":"narrowed"}`)}
	got, err := intersectAuthorizationDetails(sub, req)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if len(got) != 1 || got[0].Type != "mcp_tool" {
		t.Errorf("expected narrowed mcp_tool; got %v", got)
	}
}

func TestIntersect_RequestTypeNotOnSubject_Rejects(t *testing.T) {
	sub := []domain.AuthorizationDetail{detail("mcp_tool", `{"type":"mcp_tool"}`)}
	req := []domain.AuthorizationDetail{detail("resource", `{"type":"resource"}`)}
	_, err := intersectAuthorizationDetails(sub, req)
	if !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("err = %v, want ErrInvalidRequest", err)
	}
}
