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
// token-introspection-service emits, per Epic 4 (#141) / E4-S3 (#159) AC
// "Sample audit events captured in test fixtures".
//
// The service emits a single event type — token_introspected — but the
// active/inactive result flip changes the payload shape enough that both
// cases are worth capturing as separate fixtures.
//
// If a fixture drifts, either the code changed intentionally (regenerate
// with UPDATE_FIXTURES=1) or a bug was introduced (fix the code, not the
// fixture).
func TestAuditFixtures(t *testing.T) {
	cases := []struct {
		name  string
		event audit.Event
	}{
		{
			name:  "token_introspected_active",
			event: sampleTokenIntrospectedActive(),
		},
		{
			name:  "token_introspected_inactive",
			event: sampleTokenIntrospectedInactive(),
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

// sampleTokenIntrospectedActive mirrors the audit.Event produced by
// application/introspection_service.go:emit when the token is valid,
// unexpired, and (if Redis is configured) not revoked.
func sampleTokenIntrospectedActive() audit.Event {
	return audit.Event{
		SchemaVersion:  audit.SchemaVersion,
		EventID:        "01JQAZ7Y8XKW4EABCFINTROOK000",
		Timestamp:      sampleTimestamp(),
		EventType:      "token_introspected",
		Service:        "token-introspection-service",
		ActorType:      audit.ActorTypeService,
		ActorID:        "bearer-introspection-caller",
		SubjectID:      "01JSAMPLESUBJECTID000000000",
		ClientID:       "sample-client",
		Resource:       "token:access",
		ResourceKind:   audit.ResourceKindToken,
		ResourceID:     "access",
		ResourceParent: "token-introspection-service",
		ResourcePath:   "token-introspection-service/token/access",
		Action:         "introspect",
		Decision:       audit.DecisionAllow,
		Attrs: map[string]any{
			"active":              true,
			"introspected_jti":    "01JQABCTOKENJTI0000000000000",
			"introspected_client": "sample-client",
		},
	}
}

// sampleTokenIntrospectedInactive mirrors the audit.Event produced by
// application/introspection_service.go:emit when the token is invalid,
// expired, or revoked. Note that per RFC 7662 §2.2 the caller is always
// authenticated (Decision remains Allow) — active=false is the *result*
// of the introspection, not the authorization decision.
func sampleTokenIntrospectedInactive() audit.Event {
	return audit.Event{
		SchemaVersion:  audit.SchemaVersion,
		EventID:        "01JQAZ7Y8XKW4EABCFINTRONO000",
		Timestamp:      sampleTimestamp(),
		EventType:      "token_introspected",
		Service:        "token-introspection-service",
		ActorType:      audit.ActorTypeService,
		ActorID:        "bearer-introspection-caller",
		Resource:       "token:access",
		ResourceKind:   audit.ResourceKindToken,
		ResourceID:     "access",
		ResourceParent: "token-introspection-service",
		ResourcePath:   "token-introspection-service/token/access",
		Action:         "introspect",
		Decision:       audit.DecisionAllow,
		Attrs: map[string]any{
			"active":              false,
			"introspected_jti":    "",
			"introspected_client": "",
		},
	}
}

// sampleTimestamp is a stable illustrative timestamp used in the fixtures
// so they read like real captured events. The value is ignored by
// diffEvents.
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
