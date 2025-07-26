package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net"
	"time"

	"github.com/quic-go/quic-go"
	"golang.org/x/crypto/ssh"
)

type Config struct {
	// SSH configuration
	SSHConfig *ssh.ClientConfig

	// TLS configuration for QUIC
	TLSConfig *tls.Config

	// QUIC configuration
	QUICConfig *quic.Config

	DialTimeout time.Duration
}

type QSSHConnection struct {
	*quic.Stream
	conn *quic.Conn
	localAddr net.Addr
	remoteAddr  net.Addr
}

func (q QSSHConnection) LocalAddr() net.Addr {
	return q.localAddr
}

func (q QSSHConnection) RemoteAddr() net.Addr {
	return q.remoteAddr
}

func (q QSSHConnection) Close() error {
	if err := q.Stream.Close(); err != nil {
		return fmt.Errorf("error closing QUIC stream: %w", err)
	}

	if err := q.conn.CloseWithError(0, "connection closed"); err != nil {
		return fmt.Errorf("error closing QUIC connection: %w", err)
	}

	return nil
}

func Dial(addr string, config *Config) (*ssh.Client, *QSSHConnection, error) {
	return DialContext(context.Background(), addr, config)
}

func DialContext(ctx context.Context, addr string, config *Config) (*ssh.Client, *QSSHConnection, error) {
	dialCtx := ctx
	if config.DialTimeout > 0 {
		var cancel context.CancelFunc
		dialCtx, cancel = context.WithTimeout(ctx, config.DialTimeout)
		defer cancel()
	}
	conn, err := quic.DialAddr(dialCtx, addr, config.TLSConfig, config.QUICConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating QUIC connection with %s: %w", addr, err)
	}

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating QUIC stream with %s: %w", addr, err)
	}

	qssh := QSSHConnection{
		conn: conn,
		Stream: stream,
		localAddr: conn.LocalAddr(),
		remoteAddr: conn.RemoteAddr(),
	}

	c, nc, r, err := ssh.NewClientConn(qssh, addr, config.SSHConfig)
	if err != nil {
		return nil, nil, err
	}

	return ssh.NewClient(c, nc, r), &qssh, nil
}

// DefaultConfig returns a configuration with sensible defaults
func DefaultConfig(user string, auth []ssh.AuthMethod) *Config {
	return &Config{
		SSHConfig: &ssh.ClientConfig{
			User:            user,
			Auth:            auth,
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Timeout:         30 * time.Second,
		},
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		QUICConfig: nil, // Use defaults
		DialTimeout: 10 * time.Second,
	}
}

// PasswordConfig creates a config with password authentication
func PasswordConfig(user, password string) *Config {
	return DefaultConfig(user, []ssh.AuthMethod{
		ssh.Password(password),
	})
}

// KeyConfig creates a config with public key authentication
func KeyConfig(user string, privateKey ssh.Signer) *Config {
	return DefaultConfig(user, []ssh.AuthMethod{
		ssh.PublicKeys(privateKey),
	})
}

// WithClientCert adds client certificate authentication to the TLS config for mTLS
func (c *Config) WithClientCert(certFile, keyFile string) error {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return fmt.Errorf("failed to load client certificate: %w", err)
	}

	if c.TLSConfig == nil {
		c.TLSConfig = &tls.Config{}
	}

	c.TLSConfig.Certificates = append(c.TLSConfig.Certificates, cert)
	return nil
}

// WithServerCA adds server CA verification to the TLS config
func (c *Config) WithServerCA(caFile string) error {
	caCert, err := ioutil.ReadFile(caFile)
	if err != nil {
		return fmt.Errorf("failed to read server CA file: %w", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return fmt.Errorf("failed to parse server CA certificate")
	}

	if c.TLSConfig == nil {
		c.TLSConfig = &tls.Config{}
	}

	c.TLSConfig.RootCAs = caCertPool
	c.TLSConfig.InsecureSkipVerify = false
	return nil
}
