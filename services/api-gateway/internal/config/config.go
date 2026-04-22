package config

import (
	"fmt"
	"strings"

	"github.com/spf13/viper"

	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/domain"
)

// Config holds all api-gateway configuration.
type Config struct {
	Server ServerConfig  `mapstructure:"server"`
	Log    LogConfig     `mapstructure:"log"`
	Routes []RouteConfig `mapstructure:"routes"`
}

// ServerConfig holds HTTP listener settings.
type ServerConfig struct {
	Host string `mapstructure:"host"`
	Port int    `mapstructure:"port"`
}

// LogConfig holds structured logging settings.
type LogConfig struct {
	Level       string `mapstructure:"level"`
	Format      string `mapstructure:"format"`
	Environment string `mapstructure:"environment"`
}

// RouteConfig is the configuration representation of a single routing rule.
// It is separate from domain.Route so that config concerns (YAML tags,
// validation) do not leak into the domain layer.
type RouteConfig struct {
	Name     string         `mapstructure:"name"`
	Match    MatchConfig    `mapstructure:"match"`
	Upstream UpstreamConfig `mapstructure:"upstream"`
}

// MatchConfig mirrors domain.MatchCriteria for configuration purposes.
type MatchConfig struct {
	PathPrefix string            `mapstructure:"path_prefix"`
	Methods    []string          `mapstructure:"methods"`
	Headers    map[string]string `mapstructure:"headers"`
}

// UpstreamConfig mirrors domain.UpstreamTarget for configuration purposes.
type UpstreamConfig struct {
	URL         string `mapstructure:"url"`
	StripPrefix string `mapstructure:"strip_prefix"`
}

// Load reads configuration from environment variables and, if present, from a
// YAML config file. Environment variables are prefixed with GATEWAY_ and use
// underscores as separators (e.g. GATEWAY_SERVER_PORT overrides server.port).
//
// Config file search order:
//  1. Path in GATEWAY_CONFIG_FILE env var
//  2. ./gateway.yaml (current working directory)
//  3. /etc/gateway/gateway.yaml
//
// Missing config files are silently ignored; all settings have defaults.
func Load() (*Config, error) {
	v := viper.New()

	setDefaults(v)
	bindEnv(v)

	v.SetConfigName("gateway")
	v.SetConfigType("yaml")
	v.AddConfigPath(".")
	v.AddConfigPath("/etc/gateway")

	if cfgFile := v.GetString("config_file"); cfgFile != "" {
		v.SetConfigFile(cfgFile)
	}

	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("reading config file: %w", err)
		}
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshalling config: %w", err)
	}

	if err := validate(&cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func setDefaults(v *viper.Viper) {
	v.SetDefault("server.host", "0.0.0.0")
	v.SetDefault("server.port", 8080)
	v.SetDefault("log.level", "info")
	v.SetDefault("log.format", "json")
	v.SetDefault("log.environment", "production")
}

func bindEnv(v *viper.Viper) {
	v.SetEnvPrefix("GATEWAY")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()
}

// validate checks that the loaded configuration is consistent.
func validate(cfg *Config) error {
	if cfg.Server.Port < 1 || cfg.Server.Port > 65535 {
		return fmt.Errorf("server.port %d is out of range [1, 65535]", cfg.Server.Port)
	}
	seen := make(map[string]struct{}, len(cfg.Routes))
	for i, r := range cfg.Routes {
		if r.Name == "" {
			return fmt.Errorf("routes[%d]: name is required", i)
		}
		if _, dup := seen[r.Name]; dup {
			return fmt.Errorf("routes[%d]: duplicate route name %q", i, r.Name)
		}
		seen[r.Name] = struct{}{}
		if r.Upstream.URL == "" {
			return fmt.Errorf("routes[%d] (%q): upstream.url is required", i, r.Name)
		}
	}
	return nil
}

// ToDomainRoutes converts the config-layer route definitions to domain.Route values.
// This is the single translation point between config concerns and domain concerns.
func (c *Config) ToDomainRoutes() []*domain.Route {
	routes := make([]*domain.Route, len(c.Routes))
	for i, rc := range c.Routes {
		routes[i] = &domain.Route{
			Name: rc.Name,
			Match: domain.MatchCriteria{
				PathPrefix: rc.Match.PathPrefix,
				Methods:    rc.Match.Methods,
				Headers:    rc.Match.Headers,
			},
			Upstream: domain.UpstreamTarget{
				URL:         rc.Upstream.URL,
				StripPrefix: rc.Upstream.StripPrefix,
			},
		}
	}
	return routes
}
