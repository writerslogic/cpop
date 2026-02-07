// Package main provides IPC daemon functionality for witnessd.
//
// This integrates the IPC server with the main daemon, allowing
// witnessctl and GUI clients to communicate with the daemon.
//
// Patent Pending: USPTO Application No. 19/460,364
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"witnessd/internal/config"
	"witnessd/internal/ipc"
	"witnessd/internal/store"
	"witnessd/internal/vdf"
)

// IPCDaemon manages the IPC server for the witnessd daemon
type IPCDaemon struct {
	server  *ipc.Server
	handler *ipc.DaemonHandler
	version string
}

// NewIPCDaemon creates a new IPC daemon
func NewIPCDaemon(version string) *IPCDaemon {
	return &IPCDaemon{
		version: version,
	}
}

// Start starts the IPC daemon
func (d *IPCDaemon) Start() error {
	witnessdDir := config.WitnessdDir()

	// Open secure store
	secureStore, err := d.openSecureStore(witnessdDir)
	if err != nil {
		return fmt.Errorf("open secure store: %w", err)
	}

	// Load VDF parameters
	vdfParams := d.loadVDFParams(witnessdDir)

	// Create handler
	d.handler = ipc.NewDaemonHandler(ipc.DaemonHandlerConfig{
		WitnessdDir: witnessdDir,
		Version:     d.version,
		Store:       secureStore,
		VDFParams:   vdfParams,
	})

	// Create server config
	serverCfg := ipc.DefaultServerConfig(witnessdDir)
	serverCfg.Version = d.version

	// Create and start server
	server, err := ipc.NewServer(serverCfg, d.handler)
	if err != nil {
		return fmt.Errorf("create server: %w", err)
	}
	d.server = server

	// Connect broadcaster
	d.handler.SetBroadcaster(d.server.Broadcast)

	if err := d.server.Start(); err != nil {
		return fmt.Errorf("start server: %w", err)
	}

	return nil
}

// Stop stops the IPC daemon
func (d *IPCDaemon) Stop() error {
	if d.handler != nil {
		d.handler.Shutdown()
	}
	if d.server != nil {
		return d.server.Stop()
	}
	return nil
}

// SocketPath returns the socket path
func (d *IPCDaemon) SocketPath() string {
	if d.server != nil {
		return d.server.SocketPath()
	}
	return ""
}

// openSecureStore opens the secure SQLite database
func (d *IPCDaemon) openSecureStore(witnessdDir string) (*store.SecureStore, error) {
	dbPath := filepath.Join(witnessdDir, "events.db")
	keyPath := filepath.Join(witnessdDir, "signing_key")

	// Check if initialized
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		return nil, nil // Not initialized, return nil store
	}

	// Load signing key
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read signing key: %w", err)
	}

	privKey := ed25519.PrivateKey(keyData)
	hmacKey := deriveHMACKeyFromPrivate(privKey)

	return store.OpenSecure(dbPath, hmacKey)
}

// deriveHMACKeyFromPrivate derives HMAC key from signing key
func deriveHMACKeyFromPrivate(privKey ed25519.PrivateKey) []byte {
	h := sha256.New()
	h.Write([]byte("witnessd-hmac-key-v1"))
	h.Write(privKey.Seed())
	return h.Sum(nil)
}

// loadVDFParams loads VDF parameters from config
func (d *IPCDaemon) loadVDFParams(witnessdDir string) vdf.Parameters {
	configPath := filepath.Join(witnessdDir, "config.json")
	data, err := os.ReadFile(configPath)
	if err != nil {
		return vdf.DefaultParameters()
	}

	var cfg map[string]interface{}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return vdf.DefaultParameters()
	}

	vdfCfg, ok := cfg["vdf"].(map[string]interface{})
	if !ok {
		return vdf.DefaultParameters()
	}

	params := vdf.DefaultParameters()
	if v, ok := vdfCfg["iterations_per_second"].(float64); ok {
		params.IterationsPerSecond = uint64(v)
	}
	if v, ok := vdfCfg["min_iterations"].(float64); ok {
		params.MinIterations = uint64(v)
	}
	if v, ok := vdfCfg["max_iterations"].(float64); ok {
		params.MaxIterations = uint64(v)
	}

	return params
}

// cmdIPCDaemon starts the IPC daemon as a standalone service
func cmdIPCDaemon() {
	fmt.Println("Starting witnessd IPC daemon...")

	daemon := NewIPCDaemon(Version)
	if err := daemon.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to start daemon: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("IPC daemon listening on: %s\n", daemon.SocketPath())
	fmt.Println()
	fmt.Println("Waiting for client connections...")
	fmt.Println("Press Ctrl+C to stop")

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Periodic status output
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-sigChan:
			fmt.Println()
			fmt.Println("Shutting down...")
			if err := daemon.Stop(); err != nil {
				fmt.Fprintf(os.Stderr, "Error during shutdown: %v\n", err)
			}
			fmt.Println("Daemon stopped.")
			return

		case <-ticker.C:
			fmt.Printf("[%s] Clients: %d\n",
				time.Now().Format("15:04:05"),
				daemon.server.ClientCount())

		case <-ctx.Done():
			return
		}
	}
}
