package domain

import (
	"encoding/json"
	"errors"
	"fmt"
)

// SupportedAuthorizationDetailType is the platform-defined registry of
// RFC 9396 type discriminators per ADR-0017. Adding a type is cheap —
// add it to the slice and register a validator in
// [validateAuthorizationDetailContents]. Removing one is a breaking
// change for every client that requested it.
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
// [SupportedAuthorizationDetailTypes] and the switch below.
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
	if !isSupportedAuthorizationDetailType(head.Type) {
		return AuthorizationDetail{}, fmt.Errorf("type %q is not supported", head.Type)
	}
	return AuthorizationDetail{Type: head.Type, Raw: append(json.RawMessage(nil), elem...)}, nil
}

func isSupportedAuthorizationDetailType(t string) bool {
	for _, s := range SupportedAuthorizationDetailTypes {
		if s == t {
			return true
		}
	}
	return false
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
