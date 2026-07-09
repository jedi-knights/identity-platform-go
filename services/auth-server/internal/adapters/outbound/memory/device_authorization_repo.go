package memory

import (
	"context"
	"sync"
	"time"

	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/domain"
)

// Compile-time interface check — fails at build time if DeviceAuthorizationRepository
// drifts from the domain interface. Marks the swap point for the Redis adapter
// (ADR-0005 / ADR-0022).
var _ domain.DeviceAuthorizationRepository = (*DeviceAuthorizationRepository)(nil)

// DeviceAuthorizationRepository is an in-memory store for RFC 8628 device
// authorization requests. Not safe for multi-replica deployments — each
// replica holds an independent copy. Production deployments use the Redis
// adapter; this exists for local development without the full stack.
//
// Two keys point at the same record: byDeviceCode (token endpoint polling)
// and userCodeIndex (verification page lookup, mapping UserCode ->
// DeviceCode). One mutex covers both maps so Approve/Deny/Consume never
// observe them out of sync.
type DeviceAuthorizationRepository struct {
	mu            sync.Mutex
	byDeviceCode  map[string]*domain.DeviceAuthorization
	userCodeIndex map[string]string // UserCode -> DeviceCode
}

// NewDeviceAuthorizationRepository creates an empty store.
func NewDeviceAuthorizationRepository() *DeviceAuthorizationRepository {
	return &DeviceAuthorizationRepository{
		byDeviceCode:  make(map[string]*domain.DeviceAuthorization),
		userCodeIndex: make(map[string]string),
	}
}

// Save persists auth under both its DeviceCode and UserCode keys.
func (r *DeviceAuthorizationRepository) Save(_ context.Context, auth *domain.DeviceAuthorization) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.byDeviceCode[auth.DeviceCode] = auth
	r.userCodeIndex[auth.UserCode] = auth.DeviceCode
	return nil
}

// FindByDeviceCode returns the record for deviceCode without deleting it, so
// repeated polling can observe "still pending" any number of times.
func (r *DeviceAuthorizationRepository) FindByDeviceCode(_ context.Context, deviceCode string) (*domain.DeviceAuthorization, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lookupLocked(deviceCode)
}

// FindByUserCode returns the record for userCode without deleting it.
func (r *DeviceAuthorizationRepository) FindByUserCode(_ context.Context, userCode string) (*domain.DeviceAuthorization, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	deviceCode, ok := r.userCodeIndex[userCode]
	if !ok {
		return nil, domain.ErrDeviceAuthorizationNotFound
	}
	return r.lookupLocked(deviceCode)
}

// Approve transitions the record identified by userCode to Approved.
func (r *DeviceAuthorizationRepository) Approve(_ context.Context, userCode, subject string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	auth, err := r.lookupByUserCodeLocked(userCode)
	if err != nil {
		return err
	}
	auth.Status = domain.DeviceAuthorizationApproved
	auth.Subject = subject
	return nil
}

// Deny transitions the record identified by userCode to Denied.
func (r *DeviceAuthorizationRepository) Deny(_ context.Context, userCode string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	auth, err := r.lookupByUserCodeLocked(userCode)
	if err != nil {
		return err
	}
	auth.Status = domain.DeviceAuthorizationDenied
	return nil
}

// Consume atomically reads and deletes the record identified by deviceCode,
// removing it from both maps. The single mutex held across the lookup and
// the delete is what makes the operation atomic — mirrors
// AuthorizationCodeRepository.Consume.
func (r *DeviceAuthorizationRepository) Consume(_ context.Context, deviceCode string) (*domain.DeviceAuthorization, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	auth, err := r.lookupLocked(deviceCode)
	if err != nil {
		return nil, err
	}
	delete(r.byDeviceCode, deviceCode)
	delete(r.userCodeIndex, auth.UserCode)
	return auth, nil
}

// lookupLocked reads byDeviceCode, treating expired entries as not found.
// Callers must hold r.mu.
func (r *DeviceAuthorizationRepository) lookupLocked(deviceCode string) (*domain.DeviceAuthorization, error) {
	auth, ok := r.byDeviceCode[deviceCode]
	if !ok {
		return nil, domain.ErrDeviceAuthorizationNotFound
	}
	if auth.IsExpiredAt(time.Now()) {
		return nil, domain.ErrDeviceAuthorizationNotFound
	}
	return auth, nil
}

// lookupByUserCodeLocked resolves userCode through the index and returns the
// underlying record. Callers must hold r.mu.
func (r *DeviceAuthorizationRepository) lookupByUserCodeLocked(userCode string) (*domain.DeviceAuthorization, error) {
	deviceCode, ok := r.userCodeIndex[userCode]
	if !ok {
		return nil, domain.ErrDeviceAuthorizationNotFound
	}
	return r.lookupLocked(deviceCode)
}
