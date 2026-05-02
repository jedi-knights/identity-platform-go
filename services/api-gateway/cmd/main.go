package main

import (
	"fmt"
	"os"
)

// @title           API Gateway
// @version         1.0
// @description     HTTP reverse-proxy gateway — resolves inbound requests to upstream services.
// @host            localhost:8080
// @BasePath        /
func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
