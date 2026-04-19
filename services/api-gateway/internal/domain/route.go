package domain

// Route maps a path prefix to a backend service URL.
type Route struct {
	PathPrefix  string
	BackendURL  string
	StripPrefix bool
}
