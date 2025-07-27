package qssh

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
	return setupTestContainerWithConfig(t, "/etc/qssh/config.toml")
}

func setupTestContainerWithMTLS(t *testing.T) *testContainer {
	return setupTestContainerWithConfig(t, "/etc/qssh/config-mtls.toml")
}

func setupTestContainerWithConfig(t *testing.T, configPath string) *testContainer {
	ctx := context.Background()

	req := testcontainers.ContainerRequest{
		FromDockerfile: testcontainers.FromDockerfile{
			Context:    ".",
			Dockerfile: "Dockerfile.test",
		},
		ExposedPorts: []string{"22/tcp", "4433/udp"},
		Cmd:          []string{configPath},
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
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
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

func TestWithClientCert(t *testing.T) {
	config := PasswordConfig("testuser", "testpass")

	err := config.WithClientCert("testdata/client.crt", "testdata/client.key")
	if err != nil {
		t.Fatalf("Failed to add client certificate: %v", err)
	}

	if len(config.TLSConfig.Certificates) != 1 {
		t.Errorf("Expected 1 client certificate, got %d", len(config.TLSConfig.Certificates))
	}
}

func TestWithClientCertInvalidFiles(t *testing.T) {
	config := PasswordConfig("testuser", "testpass")

	err := config.WithClientCert("nonexistent.crt", "nonexistent.key")
	if err == nil {
		t.Error("Expected error for nonexistent certificate files")
	}
}

func TestWithServerCA(t *testing.T) {
	config := PasswordConfig("testuser", "testpass")

	err := config.WithServerCA("testdata/ca.crt")
	if err != nil {
		t.Fatalf("Failed to add server CA: %v", err)
	}

	if config.TLSConfig.RootCAs == nil {
		t.Error("Expected RootCAs to be set")
	}

	if config.TLSConfig.InsecureSkipVerify {
		t.Error("Expected InsecureSkipVerify to be false after adding CA")
	}
}

func TestWithServerCAInvalidFile(t *testing.T) {
	config := PasswordConfig("testuser", "testpass")

	err := config.WithServerCA("nonexistent.crt")
	if err == nil {
		t.Error("Expected error for nonexistent CA file")
	}
}

func TestMTLSIntegration(t *testing.T) {
	tc := setupTestContainerWithMTLS(t)
	defer tc.cleanup(t)

	config := PasswordConfig("testuser", "testpass")
	addr := tc.host + ":" + tc.port

	// Configure mTLS
	err := config.WithClientCert("testdata/client.crt", "testdata/client.key")
	if err != nil {
		t.Fatalf("Failed to add client certificate: %v", err)
	}

	err = config.WithServerCA("testdata/ca.crt")
	if err != nil {
		t.Fatalf("Failed to add server CA: %v", err)
	}

	config.SSHConfig.HostKeyCallback = ssh.InsecureIgnoreHostKey()

	client, conn, err := Dial(addr, config)
	if err != nil {
		t.Fatalf("Failed to dial with mTLS: %v", err)
	}
	defer client.Close()
	defer conn.Close()

	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}
	defer session.Close()

	output, err := session.Output("echo mtls_test")
	if err != nil {
		t.Fatalf("Failed to run command: %v", err)
	}

	if string(output) != "mtls_test\n" {
		t.Errorf("Expected 'mtls_test\\n', got '%s'", string(output))
	}
}

func TestMTLSIntegrationWithoutClientCert(t *testing.T) {
	tc := setupTestContainerWithMTLS(t)
	defer tc.cleanup(t)

	config := PasswordConfig("testuser", "testpass")
	addr := tc.host + ":" + tc.port

	// Configure server CA but no client certificate
	err := config.WithServerCA("testdata/ca.crt")
	if err != nil {
		t.Fatalf("Failed to add server CA: %v", err)
	}

	// Only for testing
	config.SSHConfig.HostKeyCallback = ssh.InsecureIgnoreHostKey()

	// This should fail because server requires mTLS but client doesn't provide certificate
	_, _, err = Dial(addr, config)
	if err == nil {
		t.Error("Expected error when connecting without client certificate to mTLS-enabled server")
	}
}

func TestSSHClientDial(t *testing.T) {
	tc := setupTestContainer(t)
	defer tc.cleanup(t)

	config := PasswordConfig("testuser", "testpass")
	addr := tc.host + ":" + tc.port

	// Only for testing
	config.SSHConfig.HostKeyCallback = ssh.InsecureIgnoreHostKey()

	// First establish connection to the SSH server
	client, conn, err := Dial(addr, config)
	if err != nil {
		t.Fatalf("Failed to connect to SSH server: %v", err)
	}
	defer client.Close()
	defer conn.Close()

	// Test ssh.Client.Dial to connect to nginx HTTP service from the remote host
	remoteConn, err := client.Dial("tcp", "localhost:8080")
	if err != nil {
		t.Fatalf("ssh.Client.Dial failed to connect to remote HTTP service: %v", err)
	}
	defer remoteConn.Close()

	// Test that the connection works by making an HTTP request
	httpRequest := "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
	_, err = remoteConn.Write([]byte(httpRequest))
	if err != nil {
		t.Fatalf("Failed to write HTTP request: %v", err)
	}

	// Read HTTP response
	buffer := make([]byte, 1024)
	n, err := remoteConn.Read(buffer)
	if err != nil {
		t.Fatalf("Failed to read HTTP response: %v", err)
	}

	response := string(buffer[:n])
	if len(response) == 0 {
		t.Error("Expected non-empty HTTP response")
	}

	// Check for HTTP status line
	if !contains(response, "HTTP/1.1 200") {
		t.Errorf("Expected HTTP 200 response, got: %s", response[:min(len(response), 100)])
	}

	// Check for our custom content
	if !contains(response, "Hello from nginx") {
		t.Errorf("Expected 'Hello from nginx' in response, got: %s", response)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && findSubstring(s, substr)
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
