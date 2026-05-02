package main

import "github.com/spf13/cobra"

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "api-gateway",
		Short: "HTTP reverse-proxy gateway for the identity platform",
		Long: `api-gateway is a production-grade HTTP reverse proxy that routes inbound
requests to upstream services based on configurable rules.

Configuration is layered (highest priority first):
  1. CLI flags  (--port, --log-level, …)
  2. Environment variables  (GATEWAY_SERVER_PORT, GATEWAY_LOG_LEVEL, …)
  3. Config file  (./gateway.yaml or /etc/gateway/gateway.yaml)
  4. Built-in defaults`,
	}

	root.AddCommand(newServeCmd())
	root.AddCommand(newVersionCmd())

	return root
}
