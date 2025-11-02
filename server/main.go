package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/knadh/koanf/parsers/toml"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
	"github.com/quic-go/quic-go"
)

type TLSConfig struct {
	CertFile      string `koanf:"cert_file"`
	KeyFile       string `koanf:"key_file"`
	ClientCA      string `koanf:"client_ca"`
	RequireMTLS   bool   `koanf:"require_mtls"`
	GenerateCerts bool   `koanf:"generate_certs"`
}

type Config struct {
	Server struct {
		QuicAddr string `koanf:"quic_addr"`
		SSHAddr  string `koanf:"ssh_addr"`
	} `koanf:"server"`

	TLS TLSConfig `koanf:"tls"`

	QUIC struct {
		MaxIdleTimeout     int64 `koanf:"max_idle_timeout"`
		MaxIncomingStreams int64 `koanf:"max_incoming_streams"`
		KeepAlivePeriod    int64 `koanf:"keep_alive_period"`
	} `koanf:"quic"`
}

type Server struct {
	config   *Config
	tlsConf  *tls.Config
	listener *quic.Listener
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	configPath := flag.String("config-file", "config.toml", "Path to config file")
	flag.Parse()

	config, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	tlsConf, err := loadTLSConfig(config.TLS)
	if err != nil {
		log.Fatalf("Failed to load TLS config: %v", err)
	}

	srv := &Server{
		config:  config,
		tlsConf: tlsConf,
	}

	if err := srv.Start(); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh

	log.Println("Shutting down...")
	if err := srv.Stop(); err != nil {
		log.Printf("Error during shutdown: %v", err)
	}
}

func loadConfig(configFile string) (*Config, error) {
	k := koanf.New(".")

	if err := k.Load(file.Provider(configFile), toml.Parser()); err != nil {
		return nil, fmt.Errorf("error loading config: %w", err)
	}

	var config Config
	if err := k.Unmarshal("", &config); err != nil {
		return nil, fmt.Errorf("error unmarshaling config: %w", err)
	}

	if config.QUIC.MaxIdleTimeout > 0 {
		config.QUIC.MaxIdleTimeout = config.QUIC.MaxIdleTimeout * int64(time.Second)
	}

	if config.QUIC.KeepAlivePeriod > 0 {
		config.QUIC.KeepAlivePeriod = config.QUIC.KeepAlivePeriod * int64(time.Second)
	}

	// Defaults
	if config.Server.QuicAddr == "" {
		config.Server.QuicAddr = ":4433"
	}
	if config.Server.SSHAddr == "" {
		config.Server.SSHAddr = "127.0.0.1:22"
	}
	if config.QUIC.MaxIdleTimeout == 0 {
		config.QUIC.MaxIdleTimeout = 30 * int64(time.Second)
	}
	if config.QUIC.MaxIncomingStreams == 0 {
		config.QUIC.MaxIncomingStreams = 100
	}
	if config.QUIC.KeepAlivePeriod == 0 {
		config.QUIC.KeepAlivePeriod = 10 * int64(time.Second)
	}

	return &config, nil
}

func (s *Server) Start() error {
	quicConf := &quic.Config{
		MaxIdleTimeout:        time.Duration(s.config.QUIC.MaxIdleTimeout),
		MaxIncomingStreams:    s.config.QUIC.MaxIncomingStreams,
		MaxIncomingUniStreams: -1, // Disable unidirectional streams
		KeepAlivePeriod:       time.Duration(s.config.QUIC.KeepAlivePeriod),
	}

	listener, err := quic.ListenAddr(s.config.Server.QuicAddr, s.tlsConf, quicConf)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", s.config.Server.QuicAddr, err)
	}
	s.listener = listener

	go s.acceptLoop()
	return nil
}

func (s *Server) Stop() error {
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

func (s *Server) acceptLoop() {
	for {
		conn, err := s.listener.Accept(context.Background())
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			return
		}

		go s.handleConnection(conn)
	}
}

func (s *Server) handleConnection(qConn *quic.Conn) {
	defer qConn.CloseWithError(0, "")

	stream, err := qConn.AcceptStream(context.Background())
	if err != nil {
		log.Printf("Failed to accept stream: %v", err)
		return
	}
	defer stream.Close()

	// Connect to SSH server
	sshConn, err := net.Dial("tcp", s.config.Server.SSHAddr)
	if err != nil {
		log.Printf("Failed to connect to SSH server at %s: %v", s.config.Server.SSHAddr, err)
		return
	}
	defer sshConn.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	// QUIC -> SSH
	go func() {
		defer wg.Done()
		if _, err := io.Copy(sshConn, stream); err != nil && err != io.EOF {
			log.Printf("Error copying from QUIC to SSH: %v", err)
		}
		sshConn.(*net.TCPConn).CloseWrite()
	}()

	// SSH -> QUIC
	go func() {
		defer wg.Done()
		if _, err := io.Copy(stream, sshConn); err != nil && err != io.EOF {
			log.Printf("Error copying from SSH to QUIC: %v", err)
		}
	}()

	wg.Wait()
}

// generateSelfSignedCert creates x509 certificate and private key and writes to the provided cert and key file.
// The files will be overwritten.
func generateSelfSignedCert(certFile, keyFile string) error {
	// Ensure parent directories exist
	certDir := filepath.Dir(certFile)
	if err := os.MkdirAll(certDir, 0755); err != nil {
		return fmt.Errorf("failed to create certificate directory: %w", err)
	}

	keyDir := filepath.Dir(keyFile)
	if err := os.MkdirAll(keyDir, 0755); err != nil {
		return fmt.Errorf("failed to create key directory: %w", err)
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"QUIC SSH Proxy"},
			CommonName:   "localhost",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // Valid for 1 year
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	certOut, err := os.Create(certFile)
	if err != nil {
		return fmt.Errorf("failed to create certificate file: %w", err)
	}
	defer certOut.Close()

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return fmt.Errorf("failed to write certificate to file: %w", err)
	}

	keyOut, err := os.Create(keyFile)
	if err != nil {
		return fmt.Errorf("failed to create key file: %w", err)
	}
	defer keyOut.Close()

	privBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes}); err != nil {
		return fmt.Errorf("failed to write private key to file: %w", err)
	}

	log.Printf("Generated self-signed certificate: %s and key: %s", certFile, keyFile)
	return nil
}

func loadTLSConfig(tlsConfig TLSConfig) (*tls.Config, error) {
	// Check if certificates exist, generate if needed
	if tlsConfig.GenerateCerts {
		certExists := true
		keyExists := true

		if _, err := os.Stat(tlsConfig.CertFile); os.IsNotExist(err) {
			certExists = false
		}
		if _, err := os.Stat(tlsConfig.KeyFile); os.IsNotExist(err) {
			keyExists = false
		}

		if !certExists || !keyExists {
			log.Printf("Certificates not found, generating self-signed certificates...")
			if err := generateSelfSignedCert(tlsConfig.CertFile, tlsConfig.KeyFile); err != nil {
				return nil, fmt.Errorf("failed to generate certificates: %w", err)
			}
		}
	}

	cert, err := tls.LoadX509KeyPair(tlsConfig.CertFile, tlsConfig.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate: %w", err)
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_CHACHA20_POLY1305_SHA256,
		},
		PreferServerCipherSuites: true,
	}

	if tlsConfig.RequireMTLS && tlsConfig.ClientCA != "" {
		caCert, err := ioutil.ReadFile(tlsConfig.ClientCA)
		if err != nil {
			return nil, fmt.Errorf("failed to read client CA file: %w", err)
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse client CA certificate")
		}

		config.ClientAuth = tls.RequireAndVerifyClientCert
		config.ClientCAs = caCertPool
	}

	return config, nil
}
