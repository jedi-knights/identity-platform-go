package application

import "errors"

// ErrMCPUnauthorized is returned when the JWT in an MCP tool request is missing,
// malformed, expired, or signed with an unknown key.
var ErrMCPUnauthorized = errors.New("mcp: unauthorized")

// ErrMCPRedirectToolNotFound is returned when the decider returns a redirect
// decision whose ToolName does not resolve to a registered tool.
var ErrMCPRedirectToolNotFound = errors.New("mcp: redirect target tool not found")
