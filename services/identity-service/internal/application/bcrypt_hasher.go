package application

import "golang.org/x/crypto/bcrypt"

// BCryptHasher implements PasswordHasher using bcrypt.
type BCryptHasher struct {
	cost int
}

// NewBCryptHasher returns a BCryptHasher with the given work factor.
// If cost is below bcrypt.MinCost it is silently raised to bcrypt.DefaultCost.
// This is a no-error floor, not a security baseline: passing bcrypt.MinCost (4)
// is valid for tests where speed matters; production callers should use
// bcrypt.DefaultCost (10) or higher.
func NewBCryptHasher(cost int) *BCryptHasher {
	if cost < bcrypt.MinCost {
		cost = bcrypt.DefaultCost
	}
	return &BCryptHasher{cost: cost}
}

// Hash returns a bcrypt hash of password using the configured work factor.
func (h *BCryptHasher) Hash(password string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(password), h.cost)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// Compare returns nil if hash is the bcrypt hash of password, or an error otherwise.
func (h *BCryptHasher) Compare(hash, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}
