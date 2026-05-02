package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

// Version, BuildTime, and Commit are injected at build time via -ldflags:
//
//	go build -ldflags "-X main.Version=1.2.3 -X main.BuildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ) -X main.Commit=$(git rev-parse --short HEAD)"
var (
	Version   = "dev"
	BuildTime = "unknown"
	Commit    = "unknown"
)

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(_ *cobra.Command, _ []string) {
			fmt.Printf("api-gateway %s (commit: %s, built: %s)\n", Version, Commit, BuildTime)
		},
	}
}
