package domain

import "strings"

// Route represents a single routing rule that maps an inbound request pattern to an upstream target.
// Routes are pure domain types — they carry no HTTP framework dependency.
type Route struct {
	Name     string
	Match    MatchCriteria
	Upstream UpstreamTarget
}

// MatchCriteria defines the conditions an inbound request must satisfy for a route to apply.
// All specified criteria must match; unset fields are treated as wildcards.
type MatchCriteria struct {
	// PathPrefix is the required URL path prefix (e.g. "/api/users").
	// An empty value matches any path.
	PathPrefix string

	// Methods is the list of allowed HTTP methods (e.g. ["GET", "POST"]).
	// An empty slice allows any method. Comparison is case-insensitive.
	Methods []string

	// Headers is a map of header name → required value.
	// Every entry must be present and matching for the route to apply.
	// An empty map imposes no header constraints.
	Headers map[string]string
}

// UpstreamTarget is the destination to which a matched request is forwarded.
type UpstreamTarget struct {
	// URL is the base URL of the upstream service (e.g. "http://user-service:8080").
	URL string

	// StripPrefix is an optional path prefix to remove before forwarding.
	// For example, if StripPrefix is "/api/users" and the request path is
	// "/api/users/123", the upstream receives "/123".
	StripPrefix string
}

// Matches reports whether the given method, path, and headers satisfy this route's
// match criteria. All three dimensions are evaluated; the request must pass all of them.
//
// This is pure domain logic — callers extract these values from *http.Request.
// The domain itself carries no net/http dependency.
func (r *Route) Matches(method, path string, headers map[string]string) bool {
	return r.matchesMethod(method) && r.matchesPath(path) && r.matchesHeaders(headers)
}

func (r *Route) matchesMethod(method string) bool {
	if len(r.Match.Methods) == 0 {
		return true
	}
	for _, m := range r.Match.Methods {
		if strings.EqualFold(m, method) {
			return true
		}
	}
	return false
}

func (r *Route) matchesPath(path string) bool {
	if r.Match.PathPrefix == "" {
		return true
	}
	return strings.HasPrefix(path, r.Match.PathPrefix)
}

func (r *Route) matchesHeaders(headers map[string]string) bool {
	for k, v := range r.Match.Headers {
		if headers[k] != v {
			return false
		}
	}
	return true
}
