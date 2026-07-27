package observability_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/jedi-knights/go-platform/audit"
)

// TestAuditFixtures pins the on-the-wire shape of the audit events auth-server
// emits, per Epic 4 (#141) / E4-S1 (#157) AC "Sample audit events captured in
// test fixtures". Each fixture is the JSON shape a downstream consumer
// (metering shim, forensics query, cross-service audit stream) will see.
//
// If a fixture drifts, either the code changed intentionally (regenerate with
// UPDATE_FIXTURES=1) or a bug was introduced (fix the code, not the fixture).
//
// The dynamic fields SchemaVersion/EventID/Timestamp/TraceID/CorrelationID
// are populated by the emitter runtime, not the event-construction sites, so
// they are cleared before comparison.
func TestAuditFixtures(t *testing.T) {
	cases := []struct {
		name  string
		event audit.Event
	}{
		{
			name:  "token_issued",
			event: sampleTokenIssuedEvent(),
		},
		{
			name:  "token_introspected",
			event: sampleTokenIntrospectedEvent(),
		},
		{
			name:  "token_revoked",
			event: sampleTokenRevokedEvent(),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join("testdata", "audit", tc.name+".json")

			if os.Getenv("UPDATE_FIXTURES") == "1" {
				writeFixture(t, path, tc.event)
				return
			}

			want := loadFixture(t, path)
			got := tc.event
			if diff := diffEvents(want, got); diff != "" {
				t.Errorf("fixture %s drift — code emits differently than the pinned sample.\n%s\n\nRegenerate with: UPDATE_FIXTURES=1 go test ./internal/observability/...", tc.name, diff)
			}
		})
	}
}

// sampleTokenIssuedEvent mirrors the audit.Event produced by
// application/grant_strategy.go:tokenIssuedEvent for a canonical
// client_credentials issuance.
//
// SchemaVersion / EventID / Timestamp are populated by the runtime; the
// values below are illustrative so the fixture reads like a real captured
// event. diffEvents zeros them before comparison.
func sampleTokenIssuedEvent() audit.Event {
	return audit.Event{
		SchemaVersion:  audit.SchemaVersion,
		EventID:        "01JQAZ7Y8XKW4EABCFISSUE0000",
		Timestamp:      sampleTimestamp(),
		EventType:      "token_issued",
		Service:        "auth-server",
		ActorType:      audit.ActorTypeService,
		ActorID:        "sample-client",
		SubjectID:      "sample-client",
		ClientID:       "sample-client",
		Resource:       "token:access",
		ResourceKind:   audit.ResourceKindToken,
		ResourceID:     "access",
		ResourceParent: "auth-server",
		ResourcePath:   "auth-server/token/access",
		Action:         "issue",
		Decision:       audit.DecisionAllow,
		Attrs: map[string]any{
			"grant_type":  "client_credentials",
			"scopes":      "read write",
			"expires_in":  float64(3600),
			"id_token":    false,
			"has_refresh": true,
			"actor_type":  "service",
		},
	}
}

// sampleTokenIntrospectedEvent mirrors the audit.Event produced by
// adapters/inbound/http/handler.go:emitTokenIntrospected for a canonical
// active-token introspection.
func sampleTokenIntrospectedEvent() audit.Event {
	return audit.Event{
		SchemaVersion:  audit.SchemaVersion,
		EventID:        "01JQAZ7Y8XKW4EABCFINTRO0000",
		Timestamp:      sampleTimestamp(),
		EventType:      "token_introspected",
		Service:        "auth-server",
		ActorType:      audit.ActorTypeService,
		ActorID:        "sample-client",
		SubjectID:      "sample-subject",
		ClientID:       "sample-client",
		Resource:       "token:access",
		ResourceKind:   audit.ResourceKindToken,
		ResourceID:     "access",
		ResourceParent: "auth-server",
		ResourcePath:   "auth-server/token/access",
		Action:         "introspect",
		Decision:       audit.DecisionAllow,
		Attrs: map[string]any{
			"active":              true,
			"introspected_jti":    "01JABCDEFGHJKMNPQRSTVWXYZ0",
			"introspected_client": "sample-target-client",
		},
	}
}

// sampleTokenRevokedEvent mirrors the audit.Event produced by
// adapters/inbound/http/handler.go:emitTokenRevoked for a canonical
// access-token revocation.
func sampleTokenRevokedEvent() audit.Event {
	return audit.Event{
		SchemaVersion:  audit.SchemaVersion,
		EventID:        "01JQAZ7Y8XKW4EABCFREVOK0000",
		Timestamp:      sampleTimestamp(),
		EventType:      "token_revoked",
		Service:        "auth-server",
		ActorType:      audit.ActorTypeService,
		ActorID:        "sample-client",
		ClientID:       "sample-client",
		Resource:       "token:access",
		ResourceKind:   audit.ResourceKindToken,
		ResourceID:     "access",
		ResourceParent: "auth-server",
		ResourcePath:   "auth-server/token/access",
		Action:         "revoke",
		Decision:       audit.DecisionAllow,
		Attrs: map[string]any{
			"token_type_hint": "access_token",
		},
	}
}

// sampleTimestamp is a stable illustrative timestamp used in the fixtures so
// they read like real captured events. The value is ignored by diffEvents.
func sampleTimestamp() time.Time {
	return time.Date(2026, time.July, 27, 18, 0, 0, 0, time.UTC)
}

func loadFixture(t *testing.T, path string) audit.Event {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", path, err)
	}
	var e audit.Event
	if err := json.Unmarshal(data, &e); err != nil {
		t.Fatalf("unmarshal fixture %s: %v", path, err)
	}
	return e
}

func writeFixture(t *testing.T, path string, e audit.Event) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	data, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write fixture %s: %v", path, err)
	}
	t.Logf("wrote fixture %s", path)
}

// diffEvents returns "" when want and got match on the fields the
// event-construction sites populate, ignoring the runtime-set fields.
func diffEvents(want, got audit.Event) string {
	var zeroTime time.Time
	want.SchemaVersion, got.SchemaVersion = "", ""
	want.EventID, got.EventID = "", ""
	want.Timestamp, got.Timestamp = zeroTime, zeroTime
	want.TraceID, got.TraceID = "", ""
	want.CorrelationID, got.CorrelationID = "", ""
	if reflect.DeepEqual(want, got) {
		return ""
	}
	wantJSON, _ := json.MarshalIndent(want, "", "  ")
	gotJSON, _ := json.MarshalIndent(got, "", "  ")
	return "-- want --\n" + string(wantJSON) + "\n-- got --\n" + string(gotJSON)
}
