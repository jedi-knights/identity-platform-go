package application

import "github.com/ocrosby/identity-platform-go/services/api-gateway/internal/ports"

// ErrNoRouteMatched is re-exported from ports so that callers (e.g. the HTTP handler)
// can check for it using errors.Is without importing the ports package directly.
var ErrNoRouteMatched = ports.ErrNoRouteMatched
