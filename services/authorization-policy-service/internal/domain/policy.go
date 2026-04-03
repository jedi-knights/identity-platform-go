package domain

// Permission represents a specific action on a resource
type Permission struct {
	Resource string
	Action   string
}

// Role represents a named set of permissions
type Role struct {
	Name        string
	Permissions []Permission
}

// Policy maps subjects (users/clients) to roles
type Policy struct {
	SubjectID string
	Roles     []string
}

// PolicyRepository stores policies
type PolicyRepository interface {
	FindBySubject(subjectID string) (*Policy, error)
	Save(policy *Policy) error
}

// RoleRepository stores role definitions
type RoleRepository interface {
	FindByName(name string) (*Role, error)
	Save(role *Role) error
}
