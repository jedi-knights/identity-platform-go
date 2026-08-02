package http

import (
	"net/url"
	"strings"
)

// returnURLValidator validates redirect targets against a host allowlist.
// It exists to defend the E5-S4 return_to flow against open-redirect
// attacks (OWASP A01:2025) — an attacker who could steer signup traffic
// through a login-ui URL of the form
// /billing/return?return_to=https://evil/steal would otherwise land the
// user on evil.example after a legitimate provisioning success. Only
// URLs whose scheme is https (http accepted at localhost for dev) and
// whose host appears in the configured allowlist are honoured; every
// other candidate is coerced to a safe fallback.
type returnURLValidator struct {
	// allowedHosts holds the caller-supplied allowlist, lowercased.
	allowedHosts map[string]struct{}
}

// newReturnURLValidator parses a comma-separated hostname list into the
// validator. Empty entries and surrounding whitespace are ignored so a
// misconfigured env value ("host-a, , host-b,") does not silently admit
// the empty string. Case is folded to lower so ".ExAmPle.com" matches
// ".example.com" — hostnames are case-insensitive per RFC 3986.
func newReturnURLValidator(csv string) *returnURLValidator {
	v := &returnURLValidator{allowedHosts: make(map[string]struct{})}
	for _, h := range strings.Split(csv, ",") {
		h = strings.TrimSpace(strings.ToLower(h))
		if h == "" {
			continue
		}
		v.allowedHosts[h] = struct{}{}
	}
	return v
}

// Validate reports whether candidate is a safe redirect target and
// returns it verbatim when allowed. Empty candidate returns ("", false)
// so callers can pick a fallback without a second nil-check. Any parse
// failure, non-http(s) scheme, or host outside the allowlist returns
// ("", false) — the caller must decide the fallback (usually the
// operator-configured billingSuccessURL). Localhost is allowed on http
// so local dev works without a TLS setup; every other http URL is
// rejected.
func (v *returnURLValidator) Validate(candidate string) (string, bool) {
	if candidate == "" {
		return "", false
	}
	u, err := url.Parse(candidate)
	if err != nil || u.Host == "" {
		// Parse failures and relative / protocol-relative URLs both fail
		// closed — the latter would let an attacker jump to
		// //evil.example after a legitimate provisioning success.
		return "", false
	}
	host := strings.ToLower(u.Hostname())
	if !v.schemeAllowed(u.Scheme, host) {
		return "", false
	}
	if !v.hostAllowed(host) {
		return "", false
	}
	return candidate, true
}

// schemeAllowed reports whether scheme is safe for host. https is
// always safe; http is only permitted at loopback so local dev works
// without a TLS setup.
func (v *returnURLValidator) schemeAllowed(scheme, host string) bool {
	if scheme == "https" {
		return true
	}
	return scheme == "http" && isLoopback(host)
}

// hostAllowed reports whether host appears on the allowlist. Loopback
// is always allowed so dev instances need no explicit config entry.
func (v *returnURLValidator) hostAllowed(host string) bool {
	if isLoopback(host) {
		return true
	}
	_, ok := v.allowedHosts[host]
	return ok
}

// isLoopback reports whether host is a loopback address a dev machine
// might legitimately use. Extracted so the two branches of Validate
// stay symmetrical.
func isLoopback(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}
