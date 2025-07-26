package main

import (
	"context"
	"crypto/tls"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"golang.org/x/crypto/ssh"
)

type testContainer struct {
	container testcontainers.Container
	host      string
	port      string
}

func setupTestContainer(t *testing.T) *testContainer {
	ctx := context.Background()

	req := testcontainers.ContainerRequest{
		FromDockerfile: testcontainers.FromDockerfile{
			Context:    ".",
			Dockerfile: "Dockerfile.test",
		},
		ExposedPorts: []string{"22/tcp", "4433/udp"},
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatalf("Failed to start container: %v", err)
	}

	host, err := container.Host(ctx)
	if err != nil {
		t.Fatalf("Failed to get container host: %v", err)
	}

	port, err := container.MappedPort(ctx, "4433/udp")
	if err != nil {
		t.Fatalf("Failed to get mapped port: %v", err)
	}

	// Wait a bit for services to be ready
	time.Sleep(2 * time.Second)

	return &testContainer{
		container: container,
		host:      host,
		port:      port.Port(),
	}
}

func (tc *testContainer) cleanup(t *testing.T) {
	ctx := context.Background()
	if err := tc.container.Terminate(ctx); err != nil {
		t.Errorf("Failed to terminate container: %v", err)
	}
}

func TestDefaultConfig(t *testing.T) {
	auth := []ssh.AuthMethod{ssh.Password("test")}
	config := DefaultConfig("testuser", auth)

	if config.SSHConfig.User != "testuser" {
		t.Errorf("Expected user 'testuser', got '%s'", config.SSHConfig.User)
	}

	if len(config.SSHConfig.Auth) != 1 {
		t.Errorf("Expected 1 auth method, got %d", len(config.SSHConfig.Auth))
	}

	if config.SSHConfig.Timeout != 30*time.Second {
		t.Errorf("Expected timeout 30s, got %v", config.SSHConfig.Timeout)
	}

	if !config.TLSConfig.InsecureSkipVerify {
		t.Error("Expected InsecureSkipVerify to be true")
	}

	if config.DialTimeout != 10*time.Second {
		t.Errorf("Expected dial timeout 10s, got %v", config.DialTimeout)
	}
}

func TestPasswordConfig(t *testing.T) {
	config := PasswordConfig("testuser", "testpass")

	if config.SSHConfig.User != "testuser" {
		t.Errorf("Expected user 'testuser', got '%s'", config.SSHConfig.User)
	}

	if len(config.SSHConfig.Auth) != 1 {
		t.Errorf("Expected 1 auth method, got %d", len(config.SSHConfig.Auth))
	}
}

func TestDialContextWithInvalidAddress(t *testing.T) {
	config := PasswordConfig("testuser", "testpass")

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	_, _, err := DialContext(ctx, "invalid:1234", config)
	if err == nil {
		t.Error("Expected error for invalid address")
	}
}

func TestDialContextWithTimeout(t *testing.T) {
	config := PasswordConfig("testuser", "testpass")
	config.DialTimeout = 1 * time.Millisecond

	_, _, err := DialContext(context.Background(), "127.0.0.1:4433", config)
	if err == nil {
		t.Error("Expected timeout error")
	}
}

func testDialIntegration(t *testing.T, ctx context.Context) {
	tc := setupTestContainer(t)
	defer tc.cleanup(t)

	config := PasswordConfig("testuser", "testpass")
	addr := tc.host + ":" + tc.port

	// Only for testing
	config.SSHConfig.HostKeyCallback = ssh.InsecureIgnoreHostKey()

	var client *ssh.Client
	var conn *QSSHConnection
	var err error

	if ctx != nil {
		client, conn, err = DialContext(ctx, addr, config)
	} else {
		client, conn, err = Dial(addr, config)
	}
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	defer client.Close()
	defer conn.Close()

	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}
	defer session.Close()

	output, err := session.Output("echo hello")
	if err != nil {
		t.Fatalf("Failed to run command: %v", err)
	}

	if string(output) != "hello\n" {
		t.Errorf("Expected 'hello\\n', got '%s'", string(output))
	}
}

func TestDialIntegration(t *testing.T) {
	testDialIntegration(t, nil)
}

func TestDialContextIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	testDialIntegration(t, ctx)
}

func TestQSSHConnectionMethods(t *testing.T) {
	tc := setupTestContainer(t)
	defer tc.cleanup(t)

	config := PasswordConfig("testuser", "testpass")
	addr := tc.host + ":" + tc.port

	client, conn, err := Dial(addr, config)
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	defer client.Close()

	localAddr := conn.LocalAddr()
	if localAddr == nil {
		t.Error("Expected non-nil local address")
	}

	remoteAddr := conn.RemoteAddr()
	if remoteAddr == nil {
		t.Error("Expected non-nil remote address")
	}

	if err := conn.Close(); err != nil {
		t.Errorf("Failed to close connection: %v", err)
	}
}

func TestConfigWithCustomTLS(t *testing.T) {
	auth := []ssh.AuthMethod{ssh.Password("testpass")}
	config := DefaultConfig("testuser", auth)

	config.TLSConfig = &tls.Config{
		InsecureSkipVerify: false,
		ServerName:         "localhost",
	}

	if config.TLSConfig.InsecureSkipVerify {
		t.Error("Expected InsecureSkipVerify to be false")
	}

	if config.TLSConfig.ServerName != "localhost" {
		t.Errorf("Expected ServerName 'localhost', got '%s'", config.TLSConfig.ServerName)
	}
}
