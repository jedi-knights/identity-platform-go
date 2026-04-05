package domain

import "context"

// Permission represents a specific action on a resource.
type Permission struct {
	Resource string
	Action   string
}

// Role represents a named set of permissions.
type Role struct {
	Name        string
	Permissions []Permission
}

// Policy maps subjects (users/clients) to roles.
type Policy struct {
	SubjectID string
	Roles     []string
}

// SubjectPermissions holds the resolved RBAC state for a subject.
// Roles are the role names assigned to the subject.
// Permissions are the fully-expanded (resource:action) pairs granted by those roles.
// Auth-server embeds both in the JWT at token issuance so resource services can
// evaluate authorization locally without an outbound policy call.
type SubjectPermissions struct {
	SubjectID   string   `json:"subject_id"`
	Roles       []string `json:"roles"`
	Permissions []string `json:"permissions"`
}

// EvaluationRequest is the input for policy evaluation.
type EvaluationRequest struct {
	SubjectID string `json:"subject_id"`
	Resource  string `json:"resource"`
	Action    string `json:"action"`
}

// EvaluationResponse is the result of policy evaluation.
type EvaluationResponse struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason,omitempty"`
}

// PolicyRepository stores policies.
type PolicyRepository interface {
	FindBySubject(ctx context.Context, subjectID string) (*Policy, error)
	Save(ctx context.Context, policy *Policy) error
}

// RoleRepository stores role definitions.
type RoleRepository interface {
	FindByName(ctx context.Context, name string) (*Role, error)
	Save(ctx context.Context, role *Role) error
}
