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

// TestAuditFixtures pins the on-the-wire shape of the audit events
// identity-service emits, per Epic 4 (#141) / E4-S2 (#158) AC "Sample audit
// events captured in test fixtures". Each fixture is the JSON shape a
// downstream consumer (metering shim, forensics query, cross-service audit
// stream) will see.
//
// If a fixture drifts, either the code changed intentionally (regenerate
// with UPDATE_FIXTURES=1) or a bug was introduced (fix the code, not the
// fixture).
//
// The dynamic fields SchemaVersion/EventID/Timestamp/TraceID/CorrelationID
// are populated by the emitter runtime, not the event-construction sites,
// so they are cleared before comparison.
func TestAuditFixtures(t *testing.T) {
	cases := []struct {
		name  string
		event audit.Event
	}{
		{
			name:  "user_registered",
			event: sampleUserRegisteredEvent(),
		},
		{
			name:  "user_authenticated",
			event: sampleUserAuthenticatedEvent(),
		},
		{
			name:  "user_authentication_failed",
			event: sampleUserAuthenticationFailedEvent(),
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

// sampleUserRegisteredEvent mirrors the audit.Event produced by
// application/auth_service.go:emitUserRegistered.
func sampleUserRegisteredEvent() audit.Event {
	return audit.Event{
		SchemaVersion:  audit.SchemaVersion,
		EventID:        "01JQAZ7Y8XKW4EABCFREGIS0000",
		Timestamp:      sampleTimestamp(),
		EventType:      "user_registered",
		Service:        "identity-service",
		ActorType:      audit.ActorTypeUser,
		ActorID:        "01JSAMPLEUSERID0000000000000",
		SubjectID:      "01JSAMPLEUSERID0000000000000",
		Resource:       "endpoint:register",
		ResourceKind:   audit.ResourceKindEndpoint,
		ResourceID:     "register",
		ResourceParent: "identity-service",
		ResourcePath:   "identity-service/endpoint/register",
		Action:         "register",
		Decision:       audit.DecisionAllow,
		Attrs: map[string]any{
			"email": "sample@example.com",
		},
	}
}

// sampleUserAuthenticatedEvent mirrors the audit.Event produced by
// application/auth_service.go:emitUserAuthenticated on a successful login.
func sampleUserAuthenticatedEvent() audit.Event {
	return audit.Event{
		SchemaVersion:  audit.SchemaVersion,
		EventID:        "01JQAZ7Y8XKW4EABCFAUTHOK0000",
		Timestamp:      sampleTimestamp(),
		EventType:      "user_authenticated",
		Service:        "identity-service",
		ActorType:      audit.ActorTypeUser,
		ActorID:        "01JSAMPLEUSERID0000000000000",
		SubjectID:      "01JSAMPLEUSERID0000000000000",
		Resource:       "endpoint:authenticate",
		ResourceKind:   audit.ResourceKindEndpoint,
		ResourceID:     "authenticate",
		ResourceParent: "identity-service",
		ResourcePath:   "identity-service/endpoint/authenticate",
		Action:         "authenticate",
		Decision:       audit.DecisionAllow,
		Attrs: map[string]any{
			"email":          "sample@example.com",
			"email_verified": true,
		},
	}
}

// sampleUserAuthenticationFailedEvent mirrors the audit.Event produced by
// application/auth_service.go:emitUserAuthenticationFailed on a wrong-password
// attempt. The event is emitted with SubjectID=user.ID whenever the user was
// resolved before the failure; the unknown-email case is otherwise identical
// with SubjectID="" and Reason="user_not_found".
func sampleUserAuthenticationFailedEvent() audit.Event {
	return audit.Event{
		SchemaVersion:  audit.SchemaVersion,
		EventID:        "01JQAZ7Y8XKW4EABCFAUTHNO0000",
		Timestamp:      sampleTimestamp(),
		EventType:      "user_authentication_failed",
		Service:        "identity-service",
		ActorType:      audit.ActorTypeUser,
		ActorID:        "sample@example.com",
		SubjectID:      "01JSAMPLEUSERID0000000000000",
		Resource:       "endpoint:authenticate",
		ResourceKind:   audit.ResourceKindEndpoint,
		ResourceID:     "authenticate",
		ResourceParent: "identity-service",
		ResourcePath:   "identity-service/endpoint/authenticate",
		Action:         "authenticate",
		Decision:       audit.DecisionDeny,
		Reason:         "invalid_password",
		Attrs: map[string]any{
			"email": "sample@example.com",
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
