// witnessd is the background daemon that silently witnesses document changes.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"witnessd/internal/config"
	"witnessd/internal/mmr"
	"witnessd/internal/signer"
	"witnessd/internal/store"
	"witnessd/internal/watcher"
	"witnessd/internal/witness"
)

var (
	configPath = flag.String("config", "", "path to config file")
	verbose    = flag.Bool("v", false, "verbose logging")
)

func main() {
	flag.Parse()

	// Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	if err := cfg.Validate(); err != nil {
		log.Fatalf("Invalid config: %v", err)
	}

	// Ensure directories exist
	if err := cfg.EnsureDirectories(); err != nil {
		log.Fatalf("Failed to create directories: %v", err)
	}

	// Set up logging
	logFile, err := os.OpenFile(cfg.LogPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}
	defer logFile.Close()

	logger := log.New(logFile, "", log.LstdFlags|log.Lshortfile)
	if *verbose {
		// Also log to stderr
		logger = log.New(os.Stderr, "[witnessd] ", log.LstdFlags|log.Lshortfile)
	}

	logger.Printf("Starting witnessd...")

	// Check signing key exists
	if _, err := os.Stat(cfg.SigningKeyPath); os.IsNotExist(err) {
		logger.Fatalf("Signing key not found: %s", cfg.SigningKeyPath)
	}

	// Initialize MMR store
	mmrStore, err := mmr.OpenFileStore(cfg.DatabasePath)
	if err != nil {
		logger.Fatalf("Failed to open MMR store: %v", err)
	}

	mmrTree, err := mmr.New(mmrStore)
	if err != nil {
		mmrStore.Close()
		logger.Fatalf("Failed to initialize MMR: %v", err)
	}

	logger.Printf("MMR initialized with %d nodes (%d leaves)", mmrTree.Size(), mmrTree.LeafCount())

	// Initialize SQLite event store
	eventStore, err := store.Open(cfg.EventStorePath)
	if err != nil {
		mmrStore.Close()
		logger.Fatalf("Failed to open event store: %v", err)
	}
	defer eventStore.Close()

	// Load signing key bytes for shadow cache key derivation
	signingKeyBytes, err := loadSigningKeyBytes(cfg.SigningKeyPath)
	if err != nil {
		mmrStore.Close()
		logger.Fatalf("Failed to load signing key bytes: %v", err)
	}

	// Initialize shadow cache
	shadowCache, err := witness.NewShadowCache(
		config.WitnessdDir(),
		signingKeyBytes,
	)
	if err != nil {
		mmrStore.Close()
		logger.Fatalf("Failed to initialize shadow cache: %v", err)
	}

	// Get or create device identity
	deviceID, err := getOrCreateDeviceID(cfg)
	if err != nil {
		mmrStore.Close()
		logger.Fatalf("Failed to get device ID: %v", err)
	}
	logger.Printf("Device ID: %s", hex.EncodeToString(deviceID[:]))

	// Initialize watcher
	if len(cfg.WatchPaths) == 0 {
		logger.Printf("Warning: no watch paths configured")
	}

	w, err := watcher.New(cfg.WatchPaths, cfg.Interval)
	if err != nil {
		mmrStore.Close()
		logger.Fatalf("Failed to create watcher: %v", err)
	}

	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start watching
	if err := w.Start(); err != nil {
		mmrStore.Close()
		logger.Fatalf("Failed to start watcher: %v", err)
	}

	logger.Printf("Watching %d paths with %d second debounce", len(cfg.WatchPaths), cfg.Interval)

	// Write PID file
	pidPath := filepath.Join(config.WitnessdDir(), "witnessd.pid")
	if err := os.WriteFile(pidPath, []byte(fmt.Sprintf("%d", os.Getpid())), 0600); err != nil {
		logger.Printf("Warning: failed to write PID file: %v", err)
	}
	defer os.Remove(pidPath)

	// Main event loop
	eventCount := uint64(0)
	running := true

	for running {
		select {
		case event := <-w.Events():
			// Read current file content for topology extraction
			content, err := os.ReadFile(event.Path)
			if err != nil {
				logger.Printf("Error reading file %s: %v", event.Path, err)
				continue
			}

			now := time.Now().UnixNano()

			// Get previous shadow for topology extraction
			prevShadow, _ := shadowCache.Get(event.Path)

			// Extract edit topology and compute size delta
			var regions []witness.EditRegion
			var sizeDelta int32
			if prevShadow != nil {
				regions = witness.ExtractTopology(prevShadow.Content, content)
				sizeDelta = witness.ComputeSizeDelta(prevShadow.FileSize, int64(len(content)))
			} else {
				// New file - single insertion region covering the whole file
				sizeDelta = int32(len(content))
				if len(content) > 0 {
					regions = []witness.EditRegion{{
						StartPct:  0.0,
						EndPct:    1.0,
						DeltaSign: 1, // Insertion
						ByteCount: int32(len(content)),
					}}
				}
			}

			// Compute cryptographic commitment
			metadataHash := witness.ComputeMetadataHash(now, int64(len(content)), sizeDelta, event.Path)
			regionsRoot := witness.ComputeRegionsRoot(regions)
			leafHash := witness.ComputeMMRLeaf(event.Hash, metadataHash, regionsRoot)

			// Append to MMR using the full leaf hash (binds content + metadata + topology)
			idx, err := mmrTree.Append(leafHash[:])
			if err != nil {
				logger.Printf("Error appending to MMR: %v", err)
				continue
			}

			// Store full event in SQLite
			evt := &store.Event{
				DeviceID:    deviceID,
				MMRIndex:    idx,
				MMRLeafHash: leafHash,
				TimestampNs: now,
				FilePath:    event.Path,
				ContentHash: event.Hash,
				FileSize:    int64(len(content)),
				SizeDelta:   sizeDelta,
				ContextID:   getActiveContextID(eventStore),
			}

			eventID, err := eventStore.InsertEvent(evt)
			if err != nil {
				logger.Printf("Error storing event: %v", err)
				continue
			}

			// Store edit regions
			if len(regions) > 0 {
				storeRegions := make([]store.EditRegion, len(regions))
				for i, r := range regions {
					storeRegions[i] = store.EditRegion{
						EventID:   eventID,
						Ordinal:   int16(i),
						StartPct:  r.StartPct,
						EndPct:    r.EndPct,
						DeltaSign: int8(r.DeltaSign),
						ByteCount: r.ByteCount,
					}
				}
				if err := eventStore.InsertEditRegions(eventID, storeRegions); err != nil {
					logger.Printf("Error storing regions: %v", err)
				}
			}

			// Update shadow cache for next comparison
			if err := shadowCache.Put(event.Path, content); err != nil {
				logger.Printf("Warning: failed to update shadow: %v", err)
			}

			// Update verification index
			regionsRootPtr := &regionsRoot
			verifyEntry := &store.VerificationEntry{
				MMRIndex:     idx,
				LeafHash:     leafHash,
				MetadataHash: metadataHash,
				RegionsRoot:  regionsRootPtr,
			}
			if err := eventStore.InsertVerificationEntry(verifyEntry); err != nil {
				logger.Printf("Warning: failed to update verification index: %v", err)
			}

			eventCount++
			logger.Printf("Witnessed: %s (idx=%d, regions=%d, delta=%+d)",
				event.Path, idx, len(regions), sizeDelta)

			// Sign the root periodically (every 10 events)
			if eventCount%10 == 0 {
				if err := signAndLogRoot(cfg, mmrTree, logger); err != nil {
					logger.Printf("Warning: failed to sign root: %v", err)
				}
			}

		case err := <-w.Errors():
			logger.Printf("Watcher error: %v", err)

		case sig := <-sigChan:
			logger.Printf("Received signal %v, shutting down...", sig)
			running = false
		}
	}

	// Graceful shutdown
	logger.Printf("Stopping watcher...")
	if err := w.Stop(); err != nil {
		logger.Printf("Error stopping watcher: %v", err)
	}

	// Final root signing
	if eventCount > 0 {
		logger.Printf("Signing final root...")
		if err := signAndLogRoot(cfg, mmrTree, logger); err != nil {
			logger.Printf("Warning: failed to sign final root: %v", err)
		}
	}

	// Sync and close MMR store
	logger.Printf("Syncing MMR store...")
	if err := mmrStore.Sync(); err != nil {
		logger.Printf("Error syncing store: %v", err)
	}
	if err := mmrStore.Close(); err != nil {
		logger.Printf("Error closing store: %v", err)
	}

	logger.Printf("Shutdown complete. Witnessed %d events.", eventCount)
}

// signAndLogRoot signs the current MMR root and logs it.
func signAndLogRoot(cfg *config.Config, m *mmr.MMR, logger *log.Logger) error {
	root, err := m.GetRoot()
	if err != nil {
		return fmt.Errorf("get root: %w", err)
	}

	// Load signing key
	privKey, err := signer.LoadPrivateKey(cfg.SigningKeyPath)
	if err != nil {
		return fmt.Errorf("load key: %w", err)
	}

	// Sign the root
	sig := signer.SignCommitment(privKey, root[:])

	// Log to signatures file
	f, err := os.OpenFile(cfg.SignaturesPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("open sigs file: %w", err)
	}
	defer f.Close()

	entry := fmt.Sprintf("%s %s %s %d\n",
		time.Now().UTC().Format(time.RFC3339),
		hex.EncodeToString(root[:]),
		hex.EncodeToString(sig),
		m.Size())

	if _, err := f.WriteString(entry); err != nil {
		return fmt.Errorf("write sig: %w", err)
	}

	logger.Printf("Signed root: %s (size=%d)", hex.EncodeToString(root[:8]), m.Size())
	return nil
}

// getOrCreateDeviceID retrieves or generates a persistent device identifier.
// The device ID is stored in ~/.witnessd/device_id.
func getOrCreateDeviceID(cfg *config.Config) ([16]byte, error) {
	deviceIDPath := filepath.Join(config.WitnessdDir(), "device_id")

	// Try to load existing device ID
	data, err := os.ReadFile(deviceIDPath)
	if err == nil && len(data) == 16 {
		var deviceID [16]byte
		copy(deviceID[:], data)
		return deviceID, nil
	}

	// Generate new UUID v4
	var deviceID [16]byte
	if _, err := rand.Read(deviceID[:]); err != nil {
		return [16]byte{}, fmt.Errorf("generate device ID: %w", err)
	}

	// Set UUID v4 version and variant bits
	deviceID[6] = (deviceID[6] & 0x0f) | 0x40 // Version 4
	deviceID[8] = (deviceID[8] & 0x3f) | 0x80 // Variant 1

	// Save device ID
	if err := os.WriteFile(deviceIDPath, deviceID[:], 0600); err != nil {
		return [16]byte{}, fmt.Errorf("save device ID: %w", err)
	}

	return deviceID, nil
}

// getActiveContextID returns the ID of the currently active context, or nil if none.
func getActiveContextID(s *store.Store) *int64 {
	ctx, err := s.GetActiveContext()
	if err != nil || ctx == nil {
		return nil
	}
	return &ctx.ID
}

// loadSigningKeyBytes reads the raw signing key bytes for shadow cache key derivation.
func loadSigningKeyBytes(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read signing key: %w", err)
	}

	// The key file may contain just the seed (32 bytes) or full private key (64 bytes)
	// Use the first 32 bytes as the derivation source
	if len(data) < 32 {
		return nil, fmt.Errorf("signing key too short: expected at least 32 bytes, got %d", len(data))
	}

	return data[:32], nil
}
