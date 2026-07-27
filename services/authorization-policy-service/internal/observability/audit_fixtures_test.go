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
// authorization-policy-service emits, per Epic 4 (#141) / E4-S4 (#160) AC
// "Sample audit events captured in test fixtures".
//
// Three fixtures cover the meaningful shape variations:
//   - allow:        matched_rule populated, no reason
//   - deny:         no matched_rule, reason=insufficient permissions
//   - no_policy:    no matched_rule, reason=no policy found for subject
//
// If a fixture drifts, either the code changed intentionally (regenerate
// with UPDATE_FIXTURES=1) or a bug was introduced (fix the code, not the
// fixture).
func TestAuditFixtures(t *testing.T) {
	cases := []struct {
		name  string
		event audit.Event
	}{
		{name: "policy_evaluated_allow", event: samplePolicyAllowEvent()},
		{name: "policy_evaluated_deny", event: samplePolicyDenyEvent()},
		{name: "policy_evaluated_no_policy", event: samplePolicyNoPolicyEvent()},
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

// samplePolicyAllowEvent mirrors the audit.Event produced by
// application/policy_service.go:emit for an allowed evaluation.
func samplePolicyAllowEvent() audit.Event {
	return audit.Event{
		SchemaVersion:  audit.SchemaVersion,
		EventID:        "01JQAZ7Y8XKW4EABCFPOLAOK0000",
		Timestamp:      sampleTimestamp(),
		EventType:      "policy_evaluated",
		Service:        "authorization-policy-service",
		ActorType:      audit.ActorTypeService,
		ActorID:        "policy-caller",
		SubjectID:      "01JSAMPLESUBJECTID000000000",
		Resource:       "endpoint:evaluate",
		ResourceKind:   audit.ResourceKindEndpoint,
		ResourceID:     "evaluate",
		ResourceParent: "authorization-policy-service",
		ResourcePath:   "authorization-policy-service/endpoint/evaluate",
		Action:         "evaluate",
		Decision:       audit.DecisionAllow,
		Attrs: map[string]any{
			"requested_resource": "articles",
			"requested_action":   "write",
			"matched_rule":       "role:editor",
		},
	}
}

// samplePolicyDenyEvent mirrors the audit.Event produced when the subject
// has a policy but no role grants the requested permission.
func samplePolicyDenyEvent() audit.Event {
	return audit.Event{
		SchemaVersion:  audit.SchemaVersion,
		EventID:        "01JQAZ7Y8XKW4EABCFPOLDENY000",
		Timestamp:      sampleTimestamp(),
		EventType:      "policy_evaluated",
		Service:        "authorization-policy-service",
		ActorType:      audit.ActorTypeService,
		ActorID:        "policy-caller",
		SubjectID:      "01JSAMPLESUBJECTID000000000",
		Resource:       "endpoint:evaluate",
		ResourceKind:   audit.ResourceKindEndpoint,
		ResourceID:     "evaluate",
		ResourceParent: "authorization-policy-service",
		ResourcePath:   "authorization-policy-service/endpoint/evaluate",
		Action:         "evaluate",
		Decision:       audit.DecisionDeny,
		Reason:         "insufficient permissions",
		Attrs: map[string]any{
			"requested_resource": "articles",
			"requested_action":   "delete",
		},
	}
}

// samplePolicyNoPolicyEvent mirrors the audit.Event produced when the
// subject has no policy record at all — a distinct deny sub-shape.
func samplePolicyNoPolicyEvent() audit.Event {
	return audit.Event{
		SchemaVersion:  audit.SchemaVersion,
		EventID:        "01JQAZ7Y8XKW4EABCFPOLNOPOL00",
		Timestamp:      sampleTimestamp(),
		EventType:      "policy_evaluated",
		Service:        "authorization-policy-service",
		ActorType:      audit.ActorTypeService,
		ActorID:        "policy-caller",
		SubjectID:      "01JUNKNOWNSUBJECTID0000000000",
		Resource:       "endpoint:evaluate",
		ResourceKind:   audit.ResourceKindEndpoint,
		ResourceID:     "evaluate",
		ResourceParent: "authorization-policy-service",
		ResourcePath:   "authorization-policy-service/endpoint/evaluate",
		Action:         "evaluate",
		Decision:       audit.DecisionDeny,
		Reason:         "no policy found for subject",
		Attrs: map[string]any{
			"requested_resource": "articles",
			"requested_action":   "read",
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
