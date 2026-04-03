package domain

import "time"

// Resource is an example protected resource
type Resource struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	OwnerID     string    `json:"owner_id"`
	CreatedAt   time.Time `json:"created_at"`
}

// ResourceRepository defines persistence for resources
type ResourceRepository interface {
	FindByID(id string) (*Resource, error)
	FindAll() ([]*Resource, error)
	Save(resource *Resource) error
}
