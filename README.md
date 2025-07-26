# QSSH - QUIC SSH Proxy

QSSH is a Go library and tool that provides SSH connections over QUIC transport, improving SSH reliability and performance over low-quality network connections.

## Features

- Better performance over unreliable networks compared to traditional TCP-based SSH
- mTLS support
- SSH ProxyCommand support
- Works with existing SSH authentication methods. Client library returns a standard ssh.Client making it easy to use with existing packages transparently.

## Installation

```bash
go get github.com/cvhariharan/qssh
```

## Usage

### As a Library

#### Basic SSH Client

```go
package main

import (
    "log"
    "github.com/cvhariharan/qssh"
)

func main() {
    config := qssh.PasswordConfig("user", "password")
    client, conn, err := qssh.Dial("server:8080", config)
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()
    defer conn.Close()

    // Use the SSH client as normal
    session, err := client.NewSession()
    if err != nil {
        log.Fatal(err)
    }
    defer session.Close()

    output, err := session.Output("ls -la")
    if err != nil {
        log.Fatal(err)
    }

    log.Println(string(output))
}
```

#### Public Key Authentication

```go
privateKey, err := ssh.ParsePrivateKey(keyBytes)
if err != nil {
    log.Fatal(err)
}

config := qssh.KeyConfig("user", privateKey)
client, conn, err := qssh.Dial("server:8080", config)
```

#### mTLS Configuration

```go
config := qssh.PasswordConfig("user", "password")
err := config.WithClientCert("client.crt", "client.key")
if err != nil {
    log.Fatal(err)
}
err = config.WithServerCA("server-ca.crt")
if err != nil {
    log.Fatal(err)
}

client, conn, err := qssh.Dial("server:8080", config)
```

### As SSH ProxyCommand

Build the client:

```bash
go build -o qssh-client ./cmd/client
```

Configure SSH to use QSSH as a proxy:

```
# ~/.ssh/config
Host myserver
    ProxyCommand qssh-client qssh-server.example.com:4433
    Hostname target-server.internal
```

Then connect normally:

```bash
ssh myserver
```

### Proxy Mode

Use QSSH in proxy mode to tunnel connections. `qssh.Proxy` can tunnel any `io.Reader` and `io.Writer`.

```go
err := qssh.Proxy(ctx, "proxy-server:8080", qssh.ProxyConfig{
    TLSConfig: &tls.Config{InsecureSkipVerify: true},
}, os.Stdin, os.Stdout)
```

## QSSH Server

QSSH requires a compatible QSSH server running on the target node. The server handles the QUIC-to-SSH translation and forwards connections to the local SSH daemon.

### Installing the Server

```bash
go install github.com/cvhariharan/qssh/server@latest
```

Or build from source:

```bash
go build ./server
```

### Server Configuration

The server uses a TOML configuration file. Create a `config.toml` file based on the example:

```toml
[server]
# QUIC server listen address
quic_addr = ":4433"

# SSH server to forward connections to
ssh_addr = "127.0.0.1:22"

[tls]
cert_file = "/etc/qssh/server.crt"
key_file = "/etc/qssh/server.key"
# Optional: Enable mutual TLS (mTLS) for client authentication
# client_ca = "/etc/qssh/client-ca.crt"
# require_mtls = false

[quic]
max_idle_timeout = 30
max_incoming_streams = 100
keep_alive_period = 10
```

### Running the Server

```bash
./server -config-file /path/to/config.toml
```

### Certificate Setup

For production deployment, you'll need TLS certificates. Refer to [generate_certs.sh](testdata/generate_certs.sh)

## Security Considerations

- The default `cmd/client` uses `InsecureSkipVerify: true` for development/testing
- For production use, implement proper certificate validation using `WithServerCA()`
- Use mTLS with `WithClientCert()` for enhanced security
- QSSH acts as a transparent proxy, existing SSH best practices should be followed.
