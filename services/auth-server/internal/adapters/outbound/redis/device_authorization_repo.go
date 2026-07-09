// Package redis: DeviceAuthorizationRepository for RFC 8628 device flow.
//
// Key schema: devicecode:<device_code> holds the JSON record with
// TTL = ExpiresAt - now; devicecode-by-usercode:<user_code> holds the plain
// device_code string as a lookup index, same TTL. Consume reuses
// consumeScript (GET+DEL) on the primary key so token issuance stays
// single-use under concurrent polling — the index cleanup that follows is
// best-effort, since a dangling index entry pointing at an already-deleted
// primary key resolves to not-found on the next FindByUserCode anyway.

package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/domain"
)

// Compile-time interface check — fails to build if the adapter drifts.
var _ domain.DeviceAuthorizationRepository = (*DeviceAuthorizationRepository)(nil)

const (
	deviceCodeKeyPrefix        = "devicecode:"
	deviceCodeByUserCodePrefix = "devicecode-by-usercode:"
)

func deviceCodeKey(deviceCode string) string { return deviceCodeKeyPrefix + deviceCode }
func deviceCodeByUserCodeKey(userCode string) string {
	return deviceCodeByUserCodePrefix + userCode
}

// DeviceAuthorizationRepository is the Redis-backed store for RFC 8628
// device authorization requests.
type DeviceAuthorizationRepository struct {
	client *goredis.Client
}

// NewDeviceAuthorizationRepository wires the adapter to a connected Redis client.
func NewDeviceAuthorizationRepository(client *goredis.Client) *DeviceAuthorizationRepository {
	return &DeviceAuthorizationRepository{client: client}
}

// Save stores auth under both the device-code key and the user-code index,
// each with TTL = ExpiresAt - now. Already-expired records are silently
// dropped — defensive guard mirroring the other Redis adapters.
func (r *DeviceAuthorizationRepository) Save(ctx context.Context, auth *domain.DeviceAuthorization) error {
	ttl := time.Until(auth.ExpiresAt)
	if ttl <= 0 {
		return nil
	}
	data, err := json.Marshal(auth)
	if err != nil {
		return fmt.Errorf("marshalling device authorization: %w", err)
	}
	if err := r.client.Set(ctx, deviceCodeKey(auth.DeviceCode), data, ttl).Err(); err != nil {
		return fmt.Errorf("saving device authorization: %w", err)
	}
	if err := r.client.Set(ctx, deviceCodeByUserCodeKey(auth.UserCode), auth.DeviceCode, ttl).Err(); err != nil {
		return fmt.Errorf("saving device authorization user-code index: %w", err)
	}
	return nil
}

// FindByDeviceCode returns the stored record without removing it, so
// repeated polling can observe "still pending" any number of times.
func (r *DeviceAuthorizationRepository) FindByDeviceCode(ctx context.Context, deviceCode string) (*domain.DeviceAuthorization, error) {
	raw, err := r.client.Get(ctx, deviceCodeKey(deviceCode)).Result()
	if errors.Is(err, goredis.Nil) {
		return nil, domain.ErrDeviceAuthorizationNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("fetching device authorization: %w", err)
	}
	var auth domain.DeviceAuthorization
	if err := json.Unmarshal([]byte(raw), &auth); err != nil {
		return nil, fmt.Errorf("unmarshalling device authorization: %w", err)
	}
	return &auth, nil
}

// FindByUserCode resolves userCode through the index, then fetches the
// underlying record.
func (r *DeviceAuthorizationRepository) FindByUserCode(ctx context.Context, userCode string) (*domain.DeviceAuthorization, error) {
	deviceCode, err := r.client.Get(ctx, deviceCodeByUserCodeKey(userCode)).Result()
	if errors.Is(err, goredis.Nil) {
		return nil, domain.ErrDeviceAuthorizationNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("fetching device authorization user-code index: %w", err)
	}
	return r.FindByDeviceCode(ctx, deviceCode)
}

// Approve transitions the record identified by userCode to Approved,
// preserving the record's remaining TTL.
func (r *DeviceAuthorizationRepository) Approve(ctx context.Context, userCode, subject string) error {
	return r.mutateByUserCode(ctx, userCode, func(auth *domain.DeviceAuthorization) {
		auth.Status = domain.DeviceAuthorizationApproved
		auth.Subject = subject
	})
}

// Deny transitions the record identified by userCode to Denied, preserving
// the record's remaining TTL.
func (r *DeviceAuthorizationRepository) Deny(ctx context.Context, userCode string) error {
	return r.mutateByUserCode(ctx, userCode, func(auth *domain.DeviceAuthorization) {
		auth.Status = domain.DeviceAuthorizationDenied
	})
}

// mutateByUserCode resolves userCode, applies mutate to the record, and
// writes it back with KeepTTL so the rewrite does not reset the record's
// expiry.
func (r *DeviceAuthorizationRepository) mutateByUserCode(ctx context.Context, userCode string, mutate func(*domain.DeviceAuthorization)) error {
	auth, err := r.FindByUserCode(ctx, userCode)
	if err != nil {
		return err
	}
	mutate(auth)
	data, err := json.Marshal(auth)
	if err != nil {
		return fmt.Errorf("marshalling device authorization: %w", err)
	}
	res := r.client.SetArgs(ctx, deviceCodeKey(auth.DeviceCode), data, goredis.SetArgs{Mode: "XX", KeepTTL: true})
	if errors.Is(res.Err(), goredis.Nil) {
		return domain.ErrDeviceAuthorizationNotFound
	}
	if res.Err() != nil {
		return fmt.Errorf("updating device authorization: %w", res.Err())
	}
	return nil
}

// Consume atomically reads and deletes the device-code entry via
// consumeScript, then best-effort deletes the user-code index. Returns
// ErrDeviceAuthorizationNotFound for unknown, expired, or already-consumed
// device codes.
func (r *DeviceAuthorizationRepository) Consume(ctx context.Context, deviceCode string) (*domain.DeviceAuthorization, error) {
	result, err := consumeScript.Run(ctx, r.client, []string{deviceCodeKey(deviceCode)}).Result()
	if errors.Is(err, goredis.Nil) {
		return nil, domain.ErrDeviceAuthorizationNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("consuming device authorization: %w", err)
	}
	if result == nil {
		return nil, domain.ErrDeviceAuthorizationNotFound
	}
	raw, ok := result.(string)
	if !ok {
		return nil, fmt.Errorf("device authorization: unexpected Lua result type %T", result)
	}
	var auth domain.DeviceAuthorization
	if err := json.Unmarshal([]byte(raw), &auth); err != nil {
		return nil, fmt.Errorf("unmarshalling device authorization: %w", err)
	}
	// Best-effort: the primary key is already gone, so a failure or race
	// here only leaves a dangling index entry that resolves to not-found
	// on the next FindByUserCode (its target key no longer exists).
	_ = r.client.Del(ctx, deviceCodeByUserCodeKey(auth.UserCode)).Err()
	return &auth, nil
}
