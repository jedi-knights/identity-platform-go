package ports

import "context"

// URLUpdater is the write-side port for service discovery adapters.
// Implementations update the URL pool for a named route, replacing
// the existing pool with the newly discovered set of endpoints.
// Callers must not retain or mutate the urls slice after the call.
type URLUpdater interface {
	UpdateURLs(routeName string, urls []string)
}

// DiscoveryRefresher manages background service discovery for a single route.
// Start performs an initial lookup synchronously and then launches the
// background refresh loop; the loop exits when ctx is cancelled.
type DiscoveryRefresher interface {
	Start(ctx context.Context)
}
