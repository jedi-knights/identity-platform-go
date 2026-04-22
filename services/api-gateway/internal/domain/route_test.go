//go:build unit

package domain_test

import (
	"testing"

	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/domain"
)

func TestRoute_Matches(t *testing.T) {
	tests := []struct {
		name     string
		route    domain.Route
		method   string
		path     string
		headers  map[string]string
		expected bool
	}{
		// --- method matching ---
		{
			name:     "empty methods accepts any method",
			route:    domain.Route{Match: domain.MatchCriteria{}},
			method:   "DELETE",
			path:     "/anything",
			expected: true,
		},
		{
			name:     "single method matches exact",
			route:    domain.Route{Match: domain.MatchCriteria{Methods: []string{"GET"}}},
			method:   "GET",
			path:     "",
			expected: true,
		},
		{
			name:     "method match is case-insensitive",
			route:    domain.Route{Match: domain.MatchCriteria{Methods: []string{"get"}}},
			method:   "GET",
			path:     "",
			expected: true,
		},
		{
			name:     "method match against multiple allowed methods",
			route:    domain.Route{Match: domain.MatchCriteria{Methods: []string{"GET", "POST"}}},
			method:   "POST",
			path:     "",
			expected: true,
		},
		{
			name:     "method not in allowed list",
			route:    domain.Route{Match: domain.MatchCriteria{Methods: []string{"POST"}}},
			method:   "GET",
			path:     "",
			expected: false,
		},
		{
			name:     "method mismatch with multiple allowed",
			route:    domain.Route{Match: domain.MatchCriteria{Methods: []string{"POST", "PUT"}}},
			method:   "DELETE",
			path:     "",
			expected: false,
		},

		// --- path matching ---
		{
			name:     "empty path prefix accepts any path",
			route:    domain.Route{Match: domain.MatchCriteria{}},
			method:   "GET",
			path:     "/any/path",
			expected: true,
		},
		{
			name:     "path prefix matches exactly",
			route:    domain.Route{Match: domain.MatchCriteria{PathPrefix: "/api"}},
			method:   "GET",
			path:     "/api",
			expected: true,
		},
		{
			name:     "path prefix matches longer path",
			route:    domain.Route{Match: domain.MatchCriteria{PathPrefix: "/api"}},
			method:   "GET",
			path:     "/api/users/123",
			expected: true,
		},
		{
			name:     "path does not start with prefix",
			route:    domain.Route{Match: domain.MatchCriteria{PathPrefix: "/api"}},
			method:   "GET",
			path:     "/health",
			expected: false,
		},
		{
			name:     "partial prefix does not match",
			route:    domain.Route{Match: domain.MatchCriteria{PathPrefix: "/api/users"}},
			method:   "GET",
			path:     "/api/orders",
			expected: false,
		},
		{
			name:     "root prefix matches all paths",
			route:    domain.Route{Match: domain.MatchCriteria{PathPrefix: "/"}},
			method:   "GET",
			path:     "/deep/nested/path",
			expected: true,
		},

		// --- header matching ---
		{
			name:     "no header criteria accepts any headers",
			route:    domain.Route{Match: domain.MatchCriteria{}},
			method:   "GET",
			path:     "",
			headers:  map[string]string{"X-Custom": "value"},
			expected: true,
		},
		{
			name:  "required header present with correct value",
			route: domain.Route{Match: domain.MatchCriteria{Headers: map[string]string{"X-Version": "v2"}}},
			headers: map[string]string{"X-Version": "v2"},
			expected: true,
		},
		{
			name:     "required header absent",
			route:    domain.Route{Match: domain.MatchCriteria{Headers: map[string]string{"X-Version": "v2"}}},
			headers:  map[string]string{},
			expected: false,
		},
		{
			name:     "required header present with wrong value",
			route:    domain.Route{Match: domain.MatchCriteria{Headers: map[string]string{"X-Version": "v2"}}},
			headers:  map[string]string{"X-Version": "v1"},
			expected: false,
		},
		{
			name: "all required headers present",
			route: domain.Route{Match: domain.MatchCriteria{Headers: map[string]string{
				"X-Version": "v2",
				"X-Tenant":  "acme",
			}}},
			headers:  map[string]string{"X-Version": "v2", "X-Tenant": "acme", "X-Extra": "ignored"},
			expected: true,
		},
		{
			name: "one of two required headers missing",
			route: domain.Route{Match: domain.MatchCriteria{Headers: map[string]string{
				"X-Version": "v2",
				"X-Tenant":  "acme",
			}}},
			headers:  map[string]string{"X-Version": "v2"},
			expected: false,
		},
		{
			name:     "nil headers with no header criteria",
			route:    domain.Route{Match: domain.MatchCriteria{}},
			method:   "GET",
			path:     "",
			headers:  nil,
			expected: true,
		},

		// --- combined criteria ---
		{
			name: "all three criteria satisfied",
			route: domain.Route{
				Match: domain.MatchCriteria{
					PathPrefix: "/api",
					Methods:    []string{"POST"},
					Headers:    map[string]string{"Content-Type": "application/json"},
				},
			},
			method:  "POST",
			path:    "/api/users",
			headers: map[string]string{"Content-Type": "application/json"},
			expected: true,
		},
		{
			name: "path and headers match but method does not",
			route: domain.Route{
				Match: domain.MatchCriteria{
					PathPrefix: "/api",
					Methods:    []string{"POST"},
				},
			},
			method:   "GET",
			path:     "/api/users",
			expected: false,
		},
		{
			name: "method and headers match but path does not",
			route: domain.Route{
				Match: domain.MatchCriteria{
					PathPrefix: "/api",
					Methods:    []string{"GET"},
				},
			},
			method:   "GET",
			path:     "/health",
			expected: false,
		},
		{
			name: "method and path match but header does not",
			route: domain.Route{
				Match: domain.MatchCriteria{
					PathPrefix: "/api",
					Methods:    []string{"GET"},
					Headers:    map[string]string{"X-Version": "v2"},
				},
			},
			method:  "GET",
			path:    "/api/users",
			headers: map[string]string{"X-Version": "v1"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.route.Matches(tt.method, tt.path, tt.headers)
			if got != tt.expected {
				t.Errorf("Matches(%q, %q, %v) = %v, want %v",
					tt.method, tt.path, tt.headers, got, tt.expected)
			}
		})
	}
}
