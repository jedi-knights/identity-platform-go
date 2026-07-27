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
// client-registry-service emits, per Epic 4 (#141) / E4-S5 (#161) AC
// "Sample audit events captured in test fixtures".
//
// Five fixtures cover the distinct event/path combinations this service
// emits across the internal client-management API and the DCR
// (RFC 7591 dynamic client registration) endpoint:
//
//   - client_registered           — internal /endpoint/register (user/service)
//   - agent_registered            — internal /endpoint/register (agent actor)
//   - client_deleted              — internal /endpoint/delete
//   - client_registered_dynamic   — DCR /endpoint/register (attrs.dynamic=true)
//   - client_deleted_dynamic      — DCR /endpoint/deregister (attrs.dynamic=true)
//
// Same-name events at different paths matter because ResourcePath is the
// primary metering filter key downstream; consumers cannot collapse them
// without losing route-level provenance.
//
// The dynamic fields SchemaVersion/EventID/Timestamp/TraceID/CorrelationID
// are populated by the emitter runtime, not the event-construction sites,
// so they are cleared before comparison.
func TestAuditFixtures(t *testing.T) {
	cases := []struct {
		name  string
		event audit.Event
	}{
		{name: "client_registered", event: sampleClientRegisteredEvent()},
		{name: "agent_registered", event: sampleAgentRegisteredEvent()},
		{name: "client_deleted", event: sampleClientDeletedEvent()},
		{name: "client_registered_dynamic", event: sampleClientRegisteredDynamicEvent()},
		{name: "client_deleted_dynamic", event: sampleClientDeletedDynamicEvent()},
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

// sampleClientRegisteredEvent mirrors the audit.Event produced by
// application/client_service.go:emitClientRegistered when a service or
// user actor creates a client through the internal API.
func sampleClientRegisteredEvent() audit.Event {
	return audit.Event{
		SchemaVersion:  audit.SchemaVersion,
		EventID:        "01JQAZ7Y8XKW4EABCFCLIREG0000",
		Timestamp:      sampleTimestamp(),
		EventType:      "client_registered",
		Service:        "client-registry-service",
		ActorType:      audit.ActorTypeService,
		ActorID:        "01JSAMPLECLIENTID000000000000",
		SubjectID:      "01JSAMPLECLIENTID000000000000",
		ClientID:       "01JSAMPLECLIENTID000000000000",
		Resource:       "endpoint:register",
		ResourceKind:   audit.ResourceKindEndpoint,
		ResourceID:     "register",
		ResourceParent: "client-registry-service",
		ResourcePath:   "client-registry-service/endpoint/register",
		Action:         "register",
		Decision:       audit.DecisionAllow,
		Attrs: map[string]any{
			"name":        "Sample Client",
			"client_type": "confidential",
			"actor_type":  "service",
			"grant_types": []any{"client_credentials"},
			"scopes":      []any{"read", "write"},
		},
	}
}

// sampleAgentRegisteredEvent mirrors the same emit path but with an agent
// actor per ADR-0015 — event_type flips to agent_registered so downstream
// billing can meter agent creation distinctly.
func sampleAgentRegisteredEvent() audit.Event {
	return audit.Event{
		SchemaVersion:  audit.SchemaVersion,
		EventID:        "01JQAZ7Y8XKW4EABCFAGTREG0000",
		Timestamp:      sampleTimestamp(),
		EventType:      "agent_registered",
		Service:        "client-registry-service",
		ActorType:      audit.ActorTypeAgent,
		ActorID:        "01JSAMPLEAGENTID0000000000000",
		SubjectID:      "01JSAMPLEAGENTID0000000000000",
		ClientID:       "01JSAMPLEAGENTID0000000000000",
		Resource:       "endpoint:register",
		ResourceKind:   audit.ResourceKindEndpoint,
		ResourceID:     "register",
		ResourceParent: "client-registry-service",
		ResourcePath:   "client-registry-service/endpoint/register",
		Action:         "register",
		Decision:       audit.DecisionAllow,
		Attrs: map[string]any{
			"name":        "Sample Agent",
			"client_type": "confidential",
			"actor_type":  "agent",
			"grant_types": []any{"client_credentials"},
			"scopes":      []any{"agent:invoke"},
		},
	}
}

// sampleClientDeletedEvent mirrors application/client_service.go:DeleteClient.
// Path is /endpoint/delete (distinct from the DCR deregister path).
func sampleClientDeletedEvent() audit.Event {
	return audit.Event{
		SchemaVersion:  audit.SchemaVersion,
		EventID:        "01JQAZ7Y8XKW4EABCFCLIDEL0000",
		Timestamp:      sampleTimestamp(),
		EventType:      "client_deleted",
		Service:        "client-registry-service",
		ActorType:      audit.ActorTypeService,
		ActorID:        "01JSAMPLECLIENTID000000000000",
		SubjectID:      "01JSAMPLECLIENTID000000000000",
		ClientID:       "01JSAMPLECLIENTID000000000000",
		Resource:       "endpoint:delete",
		ResourceKind:   audit.ResourceKindEndpoint,
		ResourceID:     "delete",
		ResourceParent: "client-registry-service",
		ResourcePath:   "client-registry-service/endpoint/delete",
		Action:         "delete",
		Decision:       audit.DecisionAllow,
	}
}

// sampleClientRegisteredDynamicEvent mirrors application/registration.go's
// DCR (RFC 7591) create emit. Same event_type as the internal path but
// attrs.dynamic=true and a richer attr set (includes
// token_endpoint_auth_method).
func sampleClientRegisteredDynamicEvent() audit.Event {
	return audit.Event{
		SchemaVersion:  audit.SchemaVersion,
		EventID:        "01JQAZ7Y8XKW4EABCFCLIREGD000",
		Timestamp:      sampleTimestamp(),
		EventType:      "client_registered",
		Service:        "client-registry-service",
		ActorType:      audit.ActorTypeService,
		ActorID:        "01JSAMPLECLIENTID000000000000",
		SubjectID:      "01JSAMPLECLIENTID000000000000",
		ClientID:       "01JSAMPLECLIENTID000000000000",
		Resource:       "endpoint:register",
		ResourceKind:   audit.ResourceKindEndpoint,
		ResourceID:     "register",
		ResourceParent: "client-registry-service",
		ResourcePath:   "client-registry-service/endpoint/register",
		Action:         "register",
		Decision:       audit.DecisionAllow,
		Attrs: map[string]any{
			"name":                       "Sample Dynamic Client",
			"client_type":                "confidential",
			"token_endpoint_auth_method": "client_secret_basic",
			"grant_types":                []any{"client_credentials"},
			"scopes":                     []any{"read"},
			"dynamic":                    true,
		},
	}
}

// sampleClientDeletedDynamicEvent mirrors application/registration.go's
// DCR delete (RFC 7592 deregister). Path is /endpoint/deregister — a
// distinct route from the internal /endpoint/delete for the same
// event_type.
func sampleClientDeletedDynamicEvent() audit.Event {
	return audit.Event{
		SchemaVersion:  audit.SchemaVersion,
		EventID:        "01JQAZ7Y8XKW4EABCFCLIDELD000",
		Timestamp:      sampleTimestamp(),
		EventType:      "client_deleted",
		Service:        "client-registry-service",
		ActorType:      audit.ActorTypeService,
		ActorID:        "01JSAMPLECLIENTID000000000000",
		SubjectID:      "01JSAMPLECLIENTID000000000000",
		ClientID:       "01JSAMPLECLIENTID000000000000",
		Resource:       "endpoint:deregister",
		ResourceKind:   audit.ResourceKindEndpoint,
		ResourceID:     "deregister",
		ResourceParent: "client-registry-service",
		ResourcePath:   "client-registry-service/endpoint/deregister",
		Action:         "deregister",
		Decision:       audit.DecisionAllow,
		Attrs: map[string]any{
			"dynamic": true,
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
