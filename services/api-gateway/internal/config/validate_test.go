//go:build unit

package config

import "testing"

func TestValidateUpstreamTLS(t *testing.T) {
	tests := []struct {
		name    string
		cfg     TLSConfig
		wantErr bool
	}{
		{
			name:    "insecure_skip_verify with ca_file is rejected",
			cfg:     TLSConfig{InsecureSkipVerify: true, CAFile: "/path/to/ca.pem"},
			wantErr: true,
		},
		{
			name:    "insecure_skip_verify with cert_file is rejected",
			cfg:     TLSConfig{InsecureSkipVerify: true, CertFile: "/path/cert.pem"},
			wantErr: true,
		},
		{
			name: "insecure_skip_verify alone is accepted",
			cfg:  TLSConfig{InsecureSkipVerify: true},
		},
		{
			name:    "cert_file without key_file is rejected",
			cfg:     TLSConfig{CertFile: "/path/cert.pem"},
			wantErr: true,
		},
		{
			name:    "key_file without cert_file is rejected",
			cfg:     TLSConfig{KeyFile: "/path/key.pem"},
			wantErr: true,
		},
		{
			name: "cert_file and key_file together are accepted",
			cfg:  TLSConfig{CertFile: "/path/cert.pem", KeyFile: "/path/key.pem"},
		},
		{
			name: "zero value is accepted",
			cfg:  TLSConfig{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange

			// Act
			err := validateUpstreamTLS(tt.cfg)

			// Assert
			if tt.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestValidateServer(t *testing.T) {
	tests := []struct {
		name    string
		cfg     ServerConfig
		wantErr bool
	}{
		{
			name:    "port 0 is rejected",
			cfg:     ServerConfig{Port: 0},
			wantErr: true,
		},
		{
			name:    "port 65536 is rejected",
			cfg:     ServerConfig{Port: 65536},
			wantErr: true,
		},
		{
			name:    "negative port is rejected",
			cfg:     ServerConfig{Port: -1},
			wantErr: true,
		},
		{
			name:    "cert_file without key_file is rejected",
			cfg:     ServerConfig{Port: 8080, TLSCertFile: "/cert.pem"},
			wantErr: true,
		},
		{
			name:    "key_file without cert_file is rejected",
			cfg:     ServerConfig{Port: 8080, TLSKeyFile: "/key.pem"},
			wantErr: true,
		},
		{
			name: "valid port with both TLS files accepted",
			cfg:  ServerConfig{Port: 443, TLSCertFile: "/cert.pem", TLSKeyFile: "/key.pem"},
		},
		{
			name: "valid port without TLS is accepted",
			cfg:  ServerConfig{Port: 8080},
		},
		{
			name: "port 1 is accepted",
			cfg:  ServerConfig{Port: 1},
		},
		{
			name: "port 65535 is accepted",
			cfg:  ServerConfig{Port: 65535},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange

			// Act
			err := validateServer(tt.cfg)

			// Assert
			if tt.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestValidateRateLimit(t *testing.T) {
	tests := []struct {
		name    string
		cfg     RateLimitConfig
		wantErr bool
	}{
		{
			name: "disabled rate limiting is accepted without checking strategy",
			cfg:  RateLimitConfig{Enabled: false, Strategy: ""},
		},
		{
			name:    "unknown strategy is rejected",
			cfg:     RateLimitConfig{Enabled: true, Strategy: "magic_bucket"},
			wantErr: true,
		},
		{
			name: "token_bucket with valid params is accepted",
			cfg: RateLimitConfig{
				Enabled:           true,
				Strategy:          "token_bucket",
				RequestsPerSecond: 100,
				BurstSize:         200,
			},
		},
		{
			name: "token_bucket with zero requests_per_second is rejected",
			cfg: RateLimitConfig{
				Enabled:           true,
				Strategy:          "token_bucket",
				RequestsPerSecond: 0,
				BurstSize:         10,
			},
			wantErr: true,
		},
		{
			name: "token_bucket with zero burst_size is rejected",
			cfg: RateLimitConfig{
				Enabled:           true,
				Strategy:          "token_bucket",
				RequestsPerSecond: 10,
				BurstSize:         0,
			},
			wantErr: true,
		},
		{
			name: "concurrency with valid max_in_flight is accepted",
			cfg: RateLimitConfig{
				Enabled:     true,
				Strategy:    "concurrency",
				MaxInFlight: 50,
			},
		},
		{
			name: "concurrency with zero max_in_flight is rejected",
			cfg: RateLimitConfig{
				Enabled:     true,
				Strategy:    "concurrency",
				MaxInFlight: 0,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange

			// Act
			err := validateRateLimit(tt.cfg)

			// Assert
			if tt.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
