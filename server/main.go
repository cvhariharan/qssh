package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
	"flag"

	"github.com/knadh/koanf/parsers/toml"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
	"github.com/quic-go/quic-go"
)

type Config struct {
	Server struct {
		QuicAddr string `koanf:"quic_addr"`
		SSHAddr  string `koanf:"ssh_addr"`
	} `koanf:"server"`

	TLS struct {
		CertFile string `koanf:"cert_file"`
		KeyFile  string `koanf:"key_file"`
	} `koanf:"tls"`

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

	tlsConf, err := loadTLSConfig(config.TLS.CertFile, config.TLS.KeyFile)
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

func loadTLSConfig(certFile, keyFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate: %w", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_CHACHA20_POLY1305_SHA256,
		},
		PreferServerCipherSuites: true,
	}, nil
}
