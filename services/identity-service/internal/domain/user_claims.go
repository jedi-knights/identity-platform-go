package domain

import "time"

// UserClaims is the projection of a User used by OIDC consumers — the auth-
// server's /userinfo endpoint and ID-token issuer. Field names are the OIDC
// Core §5.1 standard claim names; only fields the User domain model carries
// are present. Adding address, phone, family_name, etc. is a User-model
// change plus a UserClaims-field add — no protocol change.
//
// EmailVerified is a value (not a pointer) because at this layer we always
// know whether the email was verified: a user record either has
// EmailVerifiedAt set (true) or unset (false). The jwtutil.IDClaims type
// uses *bool for the on-the-wire claim because the issuer may have reason
// to omit it; that distinction lives at the issuance boundary, not here.
type UserClaims struct {
	Subject       string    `json:"sub"`
	Email         string    `json:"email"`
	EmailVerified bool      `json:"email_verified"`
	Name          string    `json:"name"`
	UpdatedAt     time.Time `json:"updated_at"`
}
