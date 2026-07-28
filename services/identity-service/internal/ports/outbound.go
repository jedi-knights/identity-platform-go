package ports

import "context"

// EntitlementsAccountCreator is identity-service's outbound port to
// entitlements-service. Register calls CreatePersonalAccount after
// userRepo.Save so every new user gets a personal account without
// extra client-side calls (E7-S1c / #211).
//
// Implementations must be idempotent — Register retries or duplicate
// signup requests should not produce two accounts for the same userID.
// The upstream entitlements-service endpoint (POST /accounts/personal)
// enforces this on the accounts.user_id partial-unique index.
//
// A no-op implementation exists for deployments where
// IDENTITY_ENTITLEMENTS_SERVICE_URL is unset — Register succeeds and
// AccountID comes back empty. Consumers should treat empty AccountID
// as "entitlements not configured", not as failure.
type EntitlementsAccountCreator interface {
	// CreatePersonalAccount asks entitlements-service to create (or
	// return the existing) personal account for userID + email.
	// Returns the entitlements-service account ID on success.
	CreatePersonalAccount(ctx context.Context, userID, email string) (accountID string, err error)
}
