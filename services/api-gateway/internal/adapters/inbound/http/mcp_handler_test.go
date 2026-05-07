package http

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/domain"
)

// --- mocks ---

type mockMCPInvoker struct {
	decision domain.MCPRoutingDecision
	tool     domain.MCPTool
	err      error
}

func (m *mockMCPInvoker) Invoke(_ context.Context, _ domain.MCPToolRequest, _ string) (domain.MCPRoutingDecision, domain.MCPTool, error) {
	return m.decision, m.tool, m.err
}

type mockTransport struct {
	forwardedTo string
	err         error
}

func (m *mockTransport) Forward(w http.ResponseWriter, _ *http.Request, route *domain.Route) error {
	m.forwardedTo = route.Upstream.URL
	w.WriteHeader(http.StatusOK)
	return m.err
}

// --- tests ---

func TestMCPHandler_MissingAuth(t *testing.T) {
	h := NewMCPHandler(&mockMCPInvoker{}, &mockTransport{}, nil)
	r := httptest.NewRequest(http.MethodPost, "/mcp/tools/weather", bytes.NewBufferString("{}"))
	r.SetPathValue("toolName", "weather")
	w := httptest.NewRecorder()

	h.InvokeTool(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestMCPHandler_Allow_ProxiesToUpstream(t *testing.T) {
	tool := domain.MCPTool{Name: "weather", UpstreamURL: "http://wx:8080"}
	invoker := &mockMCPInvoker{
		decision: domain.MCPRoutingDecision{Decision: domain.DecisionAllow, ToolName: "weather"},
		tool:     tool,
	}
	transport := &mockTransport{}

	h := NewMCPHandler(invoker, transport, nil)

	body := bytes.NewBufferString(`{"arguments": {"lat": 40.7}}`)
	r := httptest.NewRequest(http.MethodPost, "/mcp/tools/weather", body)
	r.SetPathValue("toolName", "weather")
	r.Header.Set("Authorization", "Bearer test-token")
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.InvokeTool(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if transport.forwardedTo != "http://wx:8080" {
		t.Errorf("expected forward to http://wx:8080, got %q", transport.forwardedTo)
	}
}

func TestMCPHandler_Deny_Returns403(t *testing.T) {
	invoker := &mockMCPInvoker{
		decision: domain.MCPRoutingDecision{
			Decision:    domain.DecisionDeny,
			UserMessage: "rate limit exceeded",
			Reason:      "rate_limit_exceeded",
		},
	}

	h := NewMCPHandler(invoker, &mockTransport{}, nil)

	r := httptest.NewRequest(http.MethodPost, "/mcp/tools/weather", bytes.NewBufferString("{}"))
	r.SetPathValue("toolName", "weather")
	r.Header.Set("Authorization", "Bearer test-token")
	w := httptest.NewRecorder()

	h.InvokeTool(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}

	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp["error"] != "rate limit exceeded" {
		t.Errorf("expected error message, got %q", resp["error"])
	}
}

func TestMCPHandler_Redirect_ProxiesToAlternative(t *testing.T) {
	tool := domain.MCPTool{Name: "weather", UpstreamURL: "http://wx:8080"}
	invoker := &mockMCPInvoker{
		decision: domain.MCPRoutingDecision{
			Decision: domain.DecisionRedirect,
			ToolName: "weather",
		},
		tool: tool,
	}
	transport := &mockTransport{}

	h := NewMCPHandler(invoker, transport, nil)

	r := httptest.NewRequest(http.MethodPost, "/mcp/tools/forecast", bytes.NewBufferString("{}"))
	r.SetPathValue("toolName", "forecast")
	r.Header.Set("Authorization", "Bearer test-token")
	w := httptest.NewRecorder()

	h.InvokeTool(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if transport.forwardedTo != "http://wx:8080" {
		t.Errorf("expected forward to alternative, got %q", transport.forwardedTo)
	}
}
