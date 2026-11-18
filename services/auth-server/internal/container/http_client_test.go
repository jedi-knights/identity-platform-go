package container_test

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	platform "github.com/jedi-knights/go-platform/container"

	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/container"
)

// TestSharedHTTPClient_ReusesConnectionsUnderConcurrency verifies the shared
// outbound client keeps enough idle connections that a burst of concurrent
// calls to one upstream (client-registry-service) does not dial a fresh TCP
// connection per request. net/http's default keeps only 2 idle per host.
func TestSharedHTTPClient_ReusesConnectionsUnderConcurrency(t *testing.T) {
	const (
		concurrency = 32
		rounds      = 20
	)
	var dialed int64
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			atomic.AddInt64(&dialed, 1)
		}
	}
	srv.Start()
	t.Cleanup(srv.Close)

	ctx := context.Background()
	c, err := container.New(ctx, minimalConfig(), testLogger(t))
	if err != nil {
		t.Fatalf("container.New: %v", err)
	}
	client := platform.MustResolve[*http.Client](ctx, c)

	for r := 0; r < rounds; r++ {
		var wg sync.WaitGroup
		for i := 0; i < concurrency; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				resp, err := client.Get(srv.URL)
				if err != nil {
					t.Errorf("GET: %v", err)
					return
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
			}()
		}
		wg.Wait()
	}

	// A pool sized for the burst dials at most ~concurrency connections once;
	// the 2-idle default re-dials on nearly every request (hundreds).
	if got := atomic.LoadInt64(&dialed); got > 2*concurrency {
		t.Fatalf("dialed %d connections for %d requests; want <= %d (idle pool too small)",
			got, concurrency*rounds, 2*concurrency)
	}
}
