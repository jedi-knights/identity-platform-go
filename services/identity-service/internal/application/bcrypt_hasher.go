package application

import "golang.org/x/crypto/bcrypt"

// BCryptHasher implements PasswordHasher using bcrypt.
type BCryptHasher struct {
	cost int
}

func NewBCryptHasher(cost int) *BCryptHasher {
	return &BCryptHasher{cost: cost}
}

func (h *BCryptHasher) Hash(password string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(password), h.cost)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func (h *BCryptHasher) Compare(hash, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}
