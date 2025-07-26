// Package main implements a QSSH client that acts as an SSH ProxyCommand.
//
// This client establishes a secure tunnel through a QSSH server, allowing
// SSH connections to be proxied through the server to reach the target host.
// It's designed to be used as an SSH ProxyCommand in SSH client configuration.
//
// Usage:
//   qssh-client <host:port>
//
// Example SSH config usage:
//   Host myserver
//     ProxyCommand qssh-client qssh-server.example.com:8080
//     Hostname target-server.internal
package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"crypto/tls"

	"github.com/cvhariharan/qssh"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <host:port>\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "This program is intended to be used as SSH ProxyCommand\n")
		os.Exit(1)
	}

	addr := os.Args[1]
	if !strings.Contains(addr, ":") {
		fmt.Fprintf(os.Stderr, "Address must include port (host:port)\n")
		os.Exit(1)
	}

	if err := qssh.Proxy(context.Background(), addr, qssh.ProxyConfig{
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true, // WARNING: Only for development/testing
		},
	}, os.Stdin, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "Proxy error: %v\n", err)
		os.Exit(1)
	}
}
