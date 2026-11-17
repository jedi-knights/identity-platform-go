package config_test

import (
	"testing"

	"github.com/ocrosby/identity-platform-go/services/identity-service/internal/config"
)

func TestLoad_RateLimitDefaults(t *testing.T) {
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	got := cfg.RateLimit
	want := config.RateLimitConfig{
		ResetRequestMax: 5, ResetRequestWindowSecs: 3600,
		ResetRedeemMax: 10, ResetRedeemWindowSecs: 900,
	}
	if got != want {
		t.Errorf("RateLimit defaults = %+v, want %+v", got, want)
	}
}

func TestLoad_RateLimitReadFromEnv(t *testing.T) {
	t.Setenv("IDENTITY_RATELIMIT_RESET_REQUEST_MAX", "2")
	t.Setenv("IDENTITY_RATELIMIT_RESET_REQUEST_WINDOW_SECS", "60")
	t.Setenv("IDENTITY_RATELIMIT_RESET_REDEEM_MAX", "0")
	t.Setenv("IDENTITY_RATELIMIT_RESET_REDEEM_WINDOW_SECS", "30")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	got := cfg.RateLimit
	want := config.RateLimitConfig{
		ResetRequestMax: 2, ResetRequestWindowSecs: 60,
		ResetRedeemMax: 0, ResetRedeemWindowSecs: 30,
	}
	if got != want {
		t.Errorf("RateLimit from env = %+v, want %+v (0 must survive as 'disabled')", got, want)
	}
}
