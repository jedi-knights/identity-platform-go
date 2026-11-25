package application

import (
	"encoding/json"
	"sort"
	"strconv"
	"strings"
)

// Scope-string prefixes recognized by the plan_scope projection. Match
// the shape emitted by cutline's auth-admin CLI (see
// cutline/internal/authadmin/client.go). Prefix choices are deliberate:
// the colon-delimited shape is OAuth-scope-string-valid, and the
// prefixes themselves are short so a provisioning call stays well
// under any reasonable scope-string length cap.
const (
	scopePrefixTier         = "tier:"
	scopePrefixSport        = "sport:"
	scopePrefixDivision     = "div:"
	scopePrefixEndpoint     = "group:"
	scopePrefixFeature      = "feature:"
	scopePrefixHistoryDepth = "history-depth:"
)

// PlanScope is the JSON shape resource servers consume from the
// projected namespaced claim. Mirrors the top-level plan_scope JSONB
// shape documented in cutline's docs/pricing-scheme.md — keeping the
// field names and omitempty rules in lockstep is what lets a resource
// server unmarshal the claim into its own PlanScope struct byte-for-
// byte.
type PlanScope struct {
	Tier           string   `json:"tier,omitempty"`
	Sports         []string `json:"sports,omitempty"`
	Divisions      []string `json:"divisions,omitempty"`
	EndpointGroups []string `json:"endpoint_groups,omitempty"`
	Features       []string `json:"features,omitempty"`
	HistoryDepth   int      `json:"history_depth,omitempty"`
}

// scopePrefixHandler captures one recognized prefix and how to apply
// its stripped value onto a PlanScope. Table-driven so the dispatcher
// stays flat regardless of how many dimensions ship.
type scopePrefixHandler struct {
	prefix string
	apply  func(*PlanScope, string)
}

func atoiSilent(s string) int {
	// Malformed history-depth: is a provisioning bug (surfaced via
	// logs), not a reason to refuse a token here. Resolve to 0 and
	// let omitempty drop the field.
	n, _ := strconv.Atoi(s)
	return n
}

// scopePrefixHandlers is the fixed dispatch table. Order of the slice
// does not matter for correctness — each scope string is matched
// against every prefix until one hits — but keep the recognised
// dimensions clustered for readability.
var scopePrefixHandlers = []scopePrefixHandler{
	{scopePrefixTier, func(p *PlanScope, v string) { p.Tier = v }},
	{scopePrefixSport, func(p *PlanScope, v string) { p.Sports = append(p.Sports, v) }},
	{scopePrefixDivision, func(p *PlanScope, v string) { p.Divisions = append(p.Divisions, v) }},
	{scopePrefixEndpoint, func(p *PlanScope, v string) { p.EndpointGroups = append(p.EndpointGroups, v) }},
	{scopePrefixFeature, func(p *PlanScope, v string) { p.Features = append(p.Features, v) }},
	{scopePrefixHistoryDepth, func(p *PlanScope, v string) { p.HistoryDepth = atoiSilent(v) }},
}

// ProjectScopesToPlanScope reads every recognized prefixed scope
// string out of scopes and builds a PlanScope JSON object. Unknown
// prefixes and the OAuth-standard "openid", "offline_access" etc.
// are ignored — they still ride as regular scope strings on the
// issued token's scope claim, so a resource server that cares about
// them can still enforce.
//
// The last tier-prefix wins if the caller passed multiple; order
// within each list-shaped dimension is preserved from scopes (the
// client-registry stores scopes verbatim, so this matches the order
// the operator originally configured). Non-zero history-depth
// overrides only on the last recognized prefix.
func ProjectScopesToPlanScope(scopes []string) PlanScope {
	var ps PlanScope
	for _, s := range scopes {
		for _, h := range scopePrefixHandlers {
			if strings.HasPrefix(s, h.prefix) {
				h.apply(&ps, strings.TrimPrefix(s, h.prefix))
				break
			}
		}
	}
	// Dedupe each list to keep the JSON payload compact — the registry
	// has no uniqueness constraint on scope strings today, so a
	// mis-entered duplicate would otherwise show up in the claim.
	ps.Sports = dedupe(ps.Sports)
	ps.Divisions = dedupe(ps.Divisions)
	ps.EndpointGroups = dedupe(ps.EndpointGroups)
	ps.Features = dedupe(ps.Features)
	return ps
}

// ProjectScopesToClaim marshals the projected PlanScope as
// json.RawMessage ready to be dropped into jwtutil.ClaimsConfig's
// AdditionalFields under the resource-server's namespaced claim key.
// Returns nil, nil when no projection fields matched — callers skip
// the claim entirely in that case rather than emitting
// {"":"","sports":null,...}.
func ProjectScopesToClaim(scopes []string) (json.RawMessage, error) {
	ps := ProjectScopesToPlanScope(scopes)
	if ps.Tier == "" &&
		len(ps.Sports) == 0 && len(ps.Divisions) == 0 &&
		len(ps.EndpointGroups) == 0 && len(ps.Features) == 0 &&
		ps.HistoryDepth == 0 {
		return nil, nil
	}
	return json.Marshal(ps)
}

// dedupe returns a copy of in with duplicate values removed, preserving
// first-occurrence order. Returns nil for an empty input so omitempty
// keeps the wire small.
func dedupe(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

// sortedKeys returns the keys of m in sorted order. Used by tests
// that need a deterministic walk; not called from Project*.
func sortedKeys(m map[string]any) []string { //nolint:unused // reserved for test helper inside this package
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}
