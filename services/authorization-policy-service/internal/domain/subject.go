package domain

// Subject represents an entity requesting authorization.
type Subject struct {
	ID     string
	Type   string // "user" or "client"
	Scopes []string
}
