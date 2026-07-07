package support

import (
	"net/http"
	"os"
	"time"
)

// World is the per-scenario state container. A fresh World is constructed
// for every scenario (see main_test.go's Before hook) and never shared
// across scenarios or stored in a package-level variable — this is what
// makes godog's parallel runner (`-c N`) safe: each goroutine gets its own
// World, its own service processes, its own SQLite file.
type World struct {
	// Services maps a logical name (e.g. "auth-server") to its running
	// process for this scenario.
	Services map[string]*RunningService

	// HTTPClient is shared across all outbound calls a scenario makes.
	HTTPClient *http.Client

	// TempDir holds this scenario's SQLite database file(s); removed in
	// the After hook.
	TempDir string

	// LastResponse is the most recent HTTP response's status and headers;
	// LastBody is its decoded (or raw) body, set by "When" steps and read
	// by "Then" steps.
	LastResponse *http.Response
	LastBody     []byte

	// Vars holds values captured across steps within one scenario, e.g.
	// a client_id/client_secret from a "Given a registered client" step
	// that a later "When" step needs.
	Vars map[string]string
}

// NewWorld constructs an empty World for one scenario.
func NewWorld() *World {
	return &World{
		Services:   map[string]*RunningService{},
		HTTPClient: &http.Client{Timeout: 10 * time.Second},
		Vars:       map[string]string{},
	}
}

// Close stops every service this scenario started and removes its temp
// directory. Safe to call even if some services were never started.
func (w *World) Close() {
	for _, svc := range w.Services {
		svc.Stop()
	}
	if w.TempDir != "" {
		_ = os.RemoveAll(w.TempDir)
	}
}
