package ports

import "errors"

// ErrNoRouteMatched is returned by RouteResolver implementations when no configured
// route matches the inbound request attributes. Callers should treat this as a
// client-facing 404 rather than an infrastructure failure.
var ErrNoRouteMatched = errors.New("no route matched")
