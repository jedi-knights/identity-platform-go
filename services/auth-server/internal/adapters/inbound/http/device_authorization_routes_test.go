//go:build unit

package http_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jedi-knights/go-logging/pkg/logging"

	authhttp "github.com/ocrosby/identity-platform-go/services/auth-server/internal/adapters/inbound/http"
	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/domain"
)

func TestNewRouter_DeviceAuthorizationRoute_RegisteredWhenHandlerNonNil(t *testing.T) {
	// Arrange
	logger := logging.New(logging.Config{Output: io.Discard})
	clientAuth := &fakeDeviceClientAuth{client: deviceCapableClient("cli-client")}
	deviceAuth := authhttp.NewDeviceAuthorizationHandler(clientAuth, &fakeDeviceAuthRepo{}, "https://login-ui.example.com/device", time.Minute, 5, testDeviceServiceToken, logger)
	router := authhttp.NewRouter(&authhttp.Handler{}, nil, nil, nil, deviceAuth, quietLogger())
	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)

	// Act
	resp, err := http.Post(srv.URL+"/device_authorization", "application/x-www-form-urlencoded",
		strings.NewReader(url.Values{"client_id": {"cli-client"}}.Encode()))

	// Assert
	if err != nil {
		t.Fatalf("POST /device_authorization: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

func TestNewRouter_DeviceAuthorizationRoute_404WhenHandlerNil(t *testing.T) {
	// Arrange — AUTH_LOGIN_UI_URL unset: handler resolved as nil, route not registered.
	router := authhttp.NewRouter(&authhttp.Handler{}, nil, nil, nil, nil, quietLogger())
	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)

	// Act
	resp, err := http.Post(srv.URL+"/device_authorization", "application/x-www-form-urlencoded", strings.NewReader(""))

	// Assert
	if err != nil {
		t.Fatalf("POST /device_authorization: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

var _ domain.DeviceAuthorizationRepository = (*fakeDeviceAuthRepo)(nil)
