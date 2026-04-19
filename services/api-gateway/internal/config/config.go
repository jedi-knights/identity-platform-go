package config

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

// Config holds all configuration for the API gateway.
type Config struct {
	Server    ServerConfig    `mapstructure:"server"`
	Log       LogConfig       `mapstructure:"log"`
	RateLimit RateLimitConfig `mapstructure:"rate_limit"`
	CORS      CORSConfig      `mapstructure:"cors"`
	Routes    []RouteConfig
}

// ServerConfig holds HTTP server settings.
type ServerConfig struct {
	Host string `mapstructure:"host"`
	Port int    `mapstructure:"port"`
}

// LogConfig holds logging settings.
type LogConfig struct {
	Level       string `mapstructure:"level"`
	Format      string `mapstructure:"format"`
	Environment string `mapstructure:"environment"`
}

// RateLimitConfig holds rate limiting settings.
type RateLimitConfig struct {
	RequestsPerSecond float64 `mapstructure:"requests_per_second"`
	BurstSize         int     `mapstructure:"burst_size"`
}

// CORSConfig holds CORS settings.
type CORSConfig struct {
	AllowedOrigins []string `mapstructure:"allowed_origins"`
	AllowedMethods []string `mapstructure:"allowed_methods"`
	AllowedHeaders []string `mapstructure:"allowed_headers"`
	MaxAgeSecs     int      `mapstructure:"max_age_secs"`
}

// RouteConfig maps a gateway path prefix to a backend service URL.
// This struct is populated programmatically by buildRouteTable, not by Viper.
type RouteConfig struct {
	PathPrefix  string
	BackendURL  string
	StripPrefix bool
}

// backendURLs holds the individual service URL configs read from env vars.
type backendURLs struct {
	AuthServerURL                  string `mapstructure:"auth_server_url"`
	IdentityServiceURL             string `mapstructure:"identity_service_url"`
	ClientRegistryServiceURL       string `mapstructure:"client_registry_service_url"`
	TokenIntrospectionServiceURL   string `mapstructure:"token_introspection_service_url"`
	AuthorizationPolicyServiceURL  string `mapstructure:"authorization_policy_service_url"`
	ExampleResourceServiceURL      string `mapstructure:"example_resource_service_url"`
}

// Load reads configuration from environment variables and optional config file.
func Load() (*Config, error) {
	v := viper.New()

	// Server defaults
	v.SetDefault("server.host", "0.0.0.0")
	v.SetDefault("server.port", 8086)

	// Logging defaults
	v.SetDefault("log.level", "info")
	v.SetDefault("log.format", "text")
	v.SetDefault("log.environment", "development")

	// Rate limit defaults
	v.SetDefault("rate_limit.requests_per_second", 10.0)
	v.SetDefault("rate_limit.burst_size", 20)

	// CORS defaults
	v.SetDefault("cors.allowed_origins", []string{"*"})
	v.SetDefault("cors.allowed_methods", []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"})
	v.SetDefault("cors.allowed_headers", []string{"Content-Type", "Authorization", "X-Trace-ID"})
	v.SetDefault("cors.max_age_secs", 3600)

	// Backend URL defaults
	v.SetDefault("auth_server_url", "http://localhost:8080")
	v.SetDefault("identity_service_url", "http://localhost:8081")
	v.SetDefault("client_registry_service_url", "http://localhost:8082")
	v.SetDefault("token_introspection_service_url", "http://localhost:8083")
	v.SetDefault("authorization_policy_service_url", "http://localhost:8084")
	v.SetDefault("example_resource_service_url", "http://localhost:8085")

	// Config file (optional)
	v.SetConfigName("config")
	v.SetConfigType("yaml")
	v.AddConfigPath(".")
	v.AddConfigPath("./config")

	// Environment variables
	v.SetEnvPrefix("GATEWAY")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	if err := v.ReadInConfig(); err != nil {
		var notFound viper.ConfigFileNotFoundError
		if !errors.As(err, &notFound) {
			return nil, fmt.Errorf("reading config: %w", err)
		}
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshalling config: %w", err)
	}

	var urls backendURLs
	if err := v.Unmarshal(&urls); err != nil {
		return nil, fmt.Errorf("unmarshalling backend urls: %w", err)
	}

	cfg.Routes = buildRouteTable(urls)

	return &cfg, nil
}

// buildRouteTable creates the route table from backend URL configuration.
func buildRouteTable(urls backendURLs) []RouteConfig {
	return []RouteConfig{
		{PathPrefix: "/oauth/", BackendURL: urls.AuthServerURL, StripPrefix: false},
		{PathPrefix: "/auth/", BackendURL: urls.IdentityServiceURL, StripPrefix: false},
		{PathPrefix: "/clients/", BackendURL: urls.ClientRegistryServiceURL, StripPrefix: false},
		{PathPrefix: "/introspect", BackendURL: urls.TokenIntrospectionServiceURL, StripPrefix: false},
		{PathPrefix: "/policies/", BackendURL: urls.AuthorizationPolicyServiceURL, StripPrefix: true},
		{PathPrefix: "/resources/", BackendURL: urls.ExampleResourceServiceURL, StripPrefix: false},
	}
}
