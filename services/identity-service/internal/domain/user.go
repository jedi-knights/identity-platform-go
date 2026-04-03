package domain

import "time"

// User represents an identity user
type User struct {
	ID           string
	Email        string
	PasswordHash string
	Name         string
	CreatedAt    time.Time
	UpdatedAt    time.Time
	Active       bool
}

// UserRepository defines persistence operations for users
type UserRepository interface {
	FindByID(id string) (*User, error)
	FindByEmail(email string) (*User, error)
	Save(user *User) error
	Update(user *User) error
}

// PasswordHasher defines the password hashing strategy (Strategy pattern)
type PasswordHasher interface {
	Hash(password string) (string, error)
	Compare(hash, password string) error
}
