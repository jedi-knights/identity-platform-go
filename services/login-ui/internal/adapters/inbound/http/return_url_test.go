package http

import "testing"

func TestReturnURLValidator_AllowsListedHost(t *testing.T) {
	v := newReturnURLValidator("touchline.example.com,scout-sleuth.example.com")
	cases := []string{
		"https://touchline.example.com/dashboard",
		"https://scout-sleuth.example.com/",
		"https://TOUCHLINE.example.com/case-insensitive",
	}
	for _, in := range cases {
		got, ok := v.Validate(in)
		if !ok || got != in {
			t.Errorf("Validate(%q) = (%q, %v); want (input, true)", in, got, ok)
		}
	}
}

func TestReturnURLValidator_RejectsUnlistedHost(t *testing.T) {
	v := newReturnURLValidator("touchline.example.com")
	cases := []string{
		"https://evil.example/steal",
		"https://touchline.example.com.evil.example/dashboard",
	}
	for _, in := range cases {
		if got, ok := v.Validate(in); ok {
			t.Errorf("Validate(%q) = (%q, true); want reject", in, got)
		}
	}
}

func TestReturnURLValidator_RejectsMalformedInputs(t *testing.T) {
	v := newReturnURLValidator("touchline.example.com")
	cases := []string{
		"",
		"not a url",
		"/absolute/path",
		"//evil.example/protocol-relative",
		"javascript:alert(1)",
		"ftp://touchline.example.com/",
	}
	for _, in := range cases {
		if _, ok := v.Validate(in); ok {
			t.Errorf("Validate(%q) accepted; want reject", in)
		}
	}
}

func TestReturnURLValidator_RejectsHTTPForNonLoopbackHost(t *testing.T) {
	v := newReturnURLValidator("touchline.example.com")
	if _, ok := v.Validate("http://touchline.example.com/insecure"); ok {
		t.Error("http:// should be rejected for non-loopback host")
	}
}

func TestReturnURLValidator_LocalhostBypassesAllowlist(t *testing.T) {
	v := newReturnURLValidator("")
	cases := []string{
		"http://localhost:3000/dev",
		"http://127.0.0.1:8080/dev",
		"https://localhost/dev",
	}
	for _, in := range cases {
		if _, ok := v.Validate(in); !ok {
			t.Errorf("Validate(%q) rejected; loopback should pass", in)
		}
	}
}

func TestReturnURLValidator_SkipsEmptyEntries(t *testing.T) {
	// A misconfigured allowlist ("host-a, , host-b,") must never admit
	// the empty string as a valid host.
	v := newReturnURLValidator("touchline.example.com, ,scout-sleuth.example.com,")
	if _, ok := v.Validate("https:///"); ok {
		t.Error("empty host must never be admitted")
	}
	if _, ok := v.Validate("https://touchline.example.com/"); !ok {
		t.Error("legitimate host in a partly-empty list must still validate")
	}
}
