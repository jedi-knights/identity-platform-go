package http

import (
	"encoding/json"
	"net/http"

	apperrors "github.com/ocrosby/identity-platform-go/libs/errors"
	"github.com/ocrosby/identity-platform-go/libs/httputil"
	"github.com/ocrosby/identity-platform-go/libs/logging"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/domain"
	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/ports"
)

// mcpInvokeBody is the expected JSON body for POST /mcp/tools/{toolName}.
type mcpInvokeBody struct {
	Arguments map[string]any `json:"arguments"`
	RequestID string         `json:"request_id"`
}

// mcpDenyResponse is the JSON body returned on a routing deny.
type mcpDenyResponse struct {
	Error  string `json:"error"`
	Reason string `json:"reason"`
}

// MCPHandler handles POST /mcp/tools/{toolName} requests.
// It extracts the JWT from the Authorization header, delegates the routing
// decision to MCPInvoker, and either proxies the request to the resolved tool's
// upstream or returns a deny response to the caller.
type MCPHandler struct {
	invoker   ports.MCPInvoker
	transport ports.UpstreamTransport
	logger    logging.Logger
}

// NewMCPHandler creates an MCPHandler with the given port implementations.
// logger may be nil.
func NewMCPHandler(invoker ports.MCPInvoker, transport ports.UpstreamTransport, logger logging.Logger) *MCPHandler {
	return &MCPHandler{
		invoker:   invoker,
		transport: transport,
		logger:    logger,
	}
}

// InvokeTool handles POST /mcp/tools/{toolName}.
//
// @Summary      Invoke an MCP tool
// @Description  Authenticates the caller, evaluates routing rules via Claude or the static decider, and proxies the request to the appropriate upstream.
// @Tags         mcp
// @Accept       json
// @Produce      json
// @Param        toolName  path  string  true  "Tool name"
// @Param        body      body  mcpInvokeBody  false  "Tool arguments"
// @Success      200  "Proxied response from tool upstream"
// @Failure      401  {object}  httputil.ErrorResponse
// @Failure      403  {object}  mcpDenyResponse
// @Failure      500  {object}  httputil.ErrorResponse
// @Router       /mcp/tools/{toolName} [post]
func (h *MCPHandler) InvokeTool(w http.ResponseWriter, r *http.Request) {
	toolName := r.PathValue("toolName")

	rawJWT, ok := extractBearerToken(r)
	if !ok {
		httputil.WriteError(w, apperrors.New(apperrors.ErrCodeUnauthorized, "missing or malformed Authorization header"))
		return
	}

	var body mcpInvokeBody
	if r.ContentLength > 0 {
		_ = json.NewDecoder(r.Body).Decode(&body)
	}

	requestID := body.RequestID
	if requestID == "" {
		requestID = r.Header.Get("X-Trace-ID")
	}

	req := domain.MCPToolRequest{
		ToolName:  toolName,
		Arguments: body.Arguments,
		RequestID: requestID,
	}

	decision, tool, err := h.invoker.Invoke(r.Context(), req, rawJWT)
	if err != nil {
		h.logError("mcp invoke failed", "tool", toolName, "error", err)
		httputil.WriteError(w, apperrors.New(apperrors.ErrCodeUnauthorized, "authentication failed"))
		return
	}

	if decision.Decision == domain.DecisionDeny {
		httputil.WriteJSON(w, http.StatusForbidden, mcpDenyResponse{
			Error:  decision.UserMessage,
			Reason: decision.Reason,
		})
		return
	}

	h.proxyToTool(w, r, tool)
}

// proxyToTool forwards the request to the resolved tool's upstream.
func (h *MCPHandler) proxyToTool(w http.ResponseWriter, r *http.Request, tool domain.MCPTool) {
	route := &domain.Route{
		Name: tool.Name,
		Upstream: domain.UpstreamTarget{
			URL: tool.UpstreamURL,
		},
	}
	if err := h.transport.Forward(w, r, route); err != nil {
		h.logError("mcp upstream error", "tool", tool.Name, "error", err)
		// Only write the error if headers haven't been committed yet.
		// Use a statusRecorder to track this; here we optimistically try.
		httputil.WriteError(w, apperrors.New(apperrors.ErrCodeInternal, "upstream error"))
	}
}

// logError logs at error level when a logger is configured.
func (h *MCPHandler) logError(msg string, args ...any) {
	if h.logger != nil {
		h.logger.Error(msg, args...)
	}
}
