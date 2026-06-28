package domain

import (
	"encoding/json"
	"errors"
	"fmt"
)

// SupportedAuthorizationDetailType is the platform-defined registry of
// RFC 9396 type discriminators per ADR-0017. Adding a type is cheap —
// add it to the slice and register a validator in [perTypeValidators].
// Removing one is a breaking change for every client that requested it.
const (
	AuthorizationDetailTypeMCPTool  = "mcp_tool"
	AuthorizationDetailTypeResource = "resource"
)

// SupportedAuthorizationDetailTypes is the closed set advertised via
// the RFC 9396 `authorization_details_types_supported` metadata field.
// Sorted alphabetically so the metadata document is stable across
// runs.
var SupportedAuthorizationDetailTypes = []string{
	AuthorizationDetailTypeMCPTool,
	AuthorizationDetailTypeResource,
}

// AuthorizationDetail is one element of the RFC 9396 §7
// `authorization_details` array. The struct stores both the typed
// fields the auth-server reasons about (Type, the parsed `expires_in`
// where present) and the raw JSON so resource servers receive the
// operator-supplied payload byte-for-byte.
//
// Raw is the canonical form. The typed fields are convenience
// projections — code that mutates a detail must update both.
type AuthorizationDetail struct {
	Type string
	Raw  json.RawMessage
}

// ErrInvalidAuthorizationDetails is the RFC 9396 §5
// `invalid_authorization_details` token-endpoint error. Returned from
// the parser; the HTTP layer maps it to the RFC-shaped 400 response.
var ErrInvalidAuthorizationDetails = errors.New("invalid_authorization_details")

// ParseAuthorizationDetails decodes the form-supplied JSON array and
// validates each element's type discriminator against the platform
// registry. The function tolerates the empty input (no parameter
// supplied) by returning a nil slice — RFC 9396 §2 makes the parameter
// optional.
//
// Bad JSON, a non-array shape, or an element without a recognised type
// returns [ErrInvalidAuthorizationDetails] so the HTTP layer surfaces
// the spec-shaped error envelope.
func ParseAuthorizationDetails(raw string) ([]AuthorizationDetail, error) {
	if raw == "" {
		return nil, nil
	}
	var rawArr []json.RawMessage
	if err := json.Unmarshal([]byte(raw), &rawArr); err != nil {
		return nil, fmt.Errorf("%w: not a JSON array", ErrInvalidAuthorizationDetails)
	}
	out := make([]AuthorizationDetail, 0, len(rawArr))
	for i, elem := range rawArr {
		d, err := parseDetail(elem)
		if err != nil {
			return nil, fmt.Errorf("%w: element %d: %s", ErrInvalidAuthorizationDetails, i, err.Error())
		}
		out = append(out, d)
	}
	return out, nil
}

// parseDetail validates a single element. Type registration is
// centralised here — adding a type requires adding it to
// [SupportedAuthorizationDetailTypes] and [perTypeValidators].
func parseDetail(elem json.RawMessage) (AuthorizationDetail, error) {
	var head struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(elem, &head); err != nil {
		return AuthorizationDetail{}, fmt.Errorf("not a JSON object")
	}
	if head.Type == "" {
		return AuthorizationDetail{}, fmt.Errorf("type is required")
	}
	validate, ok := perTypeValidators[head.Type]
	if !ok {
		return AuthorizationDetail{}, fmt.Errorf("type %q is not supported", head.Type)
	}
	if err := validate(elem); err != nil {
		return AuthorizationDetail{}, err
	}
	return AuthorizationDetail{Type: head.Type, Raw: append(json.RawMessage(nil), elem...)}, nil
}

// perTypeValidators dispatches per-type schema enforcement after the
// type discriminator passes. The registry is intentionally closed —
// the [SupportedAuthorizationDetailTypes] slice and this map must
// stay in sync, and the parser refuses any type without a registered
// validator so a missed entry surfaces at request time rather than
// as an opaque pass-through.
var perTypeValidators = map[string]func(json.RawMessage) error{
	AuthorizationDetailTypeMCPTool:  validateMCPTool,
	AuthorizationDetailTypeResource: validateResource,
}

// validateMCPTool enforces the ADR-0017 schema for the `mcp_tool`
// type: `tool` is required, `actions` if present must be a subset of
// `{"read","invoke"}`, `expires_in` if present must be a positive
// integer. `constraints` is free-form per the ADR and passes through
// without inspection.
func validateMCPTool(raw json.RawMessage) error {
	var v struct {
		Tool      string   `json:"tool"`
		Actions   []string `json:"actions"`
		ExpiresIn *int     `json:"expires_in"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		return fmt.Errorf("mcp_tool: not a JSON object")
	}
	if v.Tool == "" {
		return fmt.Errorf("mcp_tool: tool is required")
	}
	if err := validateMCPToolActions(v.Actions); err != nil {
		return err
	}
	return validateMCPToolExpiry(v.ExpiresIn)
}

func validateMCPToolActions(actions []string) error {
	for _, a := range actions {
		if a != "read" && a != "invoke" {
			return fmt.Errorf("mcp_tool: action %q is not one of [\"read\",\"invoke\"]", a)
		}
	}
	return nil
}

func validateMCPToolExpiry(expiresIn *int) error {
	if expiresIn != nil && *expiresIn <= 0 {
		return fmt.Errorf("mcp_tool: expires_in must be positive")
	}
	return nil
}

// validateResource enforces the ADR-0017 schema for the `resource`
// type. At least one of `locations`, `actions`, `datatypes` must be
// present — a resource entry with no constraint is meaningless.
// Values inside each array are operator-defined per RFC 9396 §2.2, so
// the validator only enforces the array-of-string shape that
// json.Unmarshal already gives us.
func validateResource(raw json.RawMessage) error {
	var v struct {
		Locations []string `json:"locations"`
		Actions   []string `json:"actions"`
		Datatypes []string `json:"datatypes"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		return fmt.Errorf("resource: not a JSON object")
	}
	if len(v.Locations) == 0 && len(v.Actions) == 0 && len(v.Datatypes) == 0 {
		return fmt.Errorf("resource: at least one of locations, actions, datatypes is required")
	}
	return nil
}

// AuthorizationDetailsToRaw projects the typed slice back to the
// []json.RawMessage form jwtutil.Claims expects on the wire. Returns
// nil when in is empty so the issued token omits the claim.
func AuthorizationDetailsToRaw(in []AuthorizationDetail) []json.RawMessage {
	if len(in) == 0 {
		return nil
	}
	out := make([]json.RawMessage, len(in))
	for i, d := range in {
		out[i] = append(json.RawMessage(nil), d.Raw...)
	}
	return out
}
