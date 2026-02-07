// witnessd - Cryptographic authorship witnessing with commit-based workflow
//
// Unlike the old daemon-based approach, witnessd now uses explicit commits:
//
//	witnessd init           Initialize witnessing for current directory
//	witnessd commit <file>  Commit a checkpoint
//	witnessd log <file>     Show checkpoint history
//	witnessd export <file>  Export evidence packet
//	witnessd verify <file>  Verify checkpoint chain
//	witnessd presence       Start/stop presence verification session
//	witnessd calibrate      Calibrate VDF for this machine
//	witnessd daemon         (Legacy) Run background monitoring daemon
package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"witnessd/internal/checkpoint"
	"witnessd/internal/config"
	"witnessd/internal/declaration"
	"witnessd/internal/evidence"
	"witnessd/internal/jitter"
	"witnessd/internal/keyhierarchy"
	"witnessd/internal/presence"
	"witnessd/internal/sentinel"
	"witnessd/internal/store"
	"witnessd/internal/tpm"
	"witnessd/internal/tracking"
	"witnessd/internal/vdf"
	"witnessd/internal/wal"
	"witnessd/internal/witness"
)

// Version information (set via ldflags during build)
var (
	Version   = "dev"
	BuildTime = "unknown"
	Commit    = "unknown"
)

func main() {
	// If no arguments, launch interactive menu
	if len(os.Args) < 2 {
		menu := NewMenu()
		menu.Run()
		return
	}

	cmd := os.Args[1]

	switch cmd {
	case "init":
		cmdInit()
	case "commit":
		cmdCommit()
	case "log":
		cmdLog()
	case "export":
		cmdExport()
	case "verify":
		cmdVerify()
	case "presence":
		cmdPresence()
	case "track":
		cmdTrack()
	case "sentinel":
		cmdSentinel()
	case "calibrate":
		cmdCalibrate()
	case "status":
		cmdStatus()
	case "daemon":
		cmdDaemon()
	case "serve":
		cmdIPCDaemon()
	case "help", "-h", "--help":
		usage()
	case "version", "-v", "--version":
		printVersion()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", cmd)
		usage()
		os.Exit(1)
	}
}

const banner = `
░█░░░█░░▀░░▀█▀░█▀▀▄░█▀▀░█▀▀░█▀▀░░░░█▀▄
░▀▄█▄▀░░█▀░░█░░█░▒█░█▀▀░▀▀▄░▀▀▄░▀▀░█░█
░░▀░▀░░▀▀▀░░▀░░▀░░▀░▀▀▀░▀▀▀░▀▀▀░░░░▀▀░
`

func usage() {
	fmt.Print(banner)
	fmt.Println(`witnessd - Cryptographic Authorship Witnessing

USAGE:
    witnessd <command> [options]

COMMANDS:
    init                Initialize witnessd in current directory
    commit <file>       Create a checkpoint for a file
    log <file>          Show checkpoint history for a file
    export <file>       Export evidence packet with declaration
    verify <file>       Verify checkpoint chain or evidence packet
    presence <action>   Manage presence verification sessions
    track <action>      Track keyboard activity (count only, no capture)
    sentinel <action>   Manage background sentinel daemon
    calibrate           Calibrate VDF performance for this machine
    status              Show witnessd status and configuration
    serve               Start IPC daemon for client communication
    daemon              (Legacy) Run background monitoring daemon
    help                Show this help message
    version             Show version information

BASIC WORKFLOW:
    1. witnessd init                    # One-time setup (creates master identity)
    2. (write your document)
    3. witnessd commit doc.md -m "..."  # Checkpoint with ratcheting key signature
    4. (continue writing)
    5. witnessd commit doc.md -m "..."  # More checkpoints
    6. witnessd export doc.md           # Export evidence with key hierarchy
    7. witnessd verify evidence.json    # Verify including key hierarchy

ENHANCED WORKFLOW (with keystroke + jitter tracking):
    1. witnessd track start doc.md      # Start tracking daemon (creates WAL)
    2. (write your document)
    3. witnessd track status            # Check keystroke count, jitter samples
    4. witnessd commit doc.md -m "..."  # Creates checkpoint with jitter chain
    5. witnessd track stop              # Stop tracking, save jitter evidence
    6. witnessd export doc.md           # Export with jitter + key hierarchy
    7. witnessd verify evidence.wpkt    # Verify including all evidence layers

SENTINEL DAEMON (automatic tracking):
    witnessd sentinel start             # Start background sentinel daemon
    witnessd sentinel stop              # Stop sentinel daemon
    witnessd sentinel status            # Show tracked documents

PRIVACY NOTE:
    Tracking counts keystrokes - it does NOT capture which keys are pressed.
    This is NOT a keylogger. Only event counts and timing are recorded.

KEY HIERARCHY:
    The system uses a three-tier ratcheting key hierarchy:
    - Tier 0 (Identity): Master key derived from device PUF
    - Tier 1 (Session): Per-session keys certified by master
    - Tier 2 (Ratchet): Forward-secrecy keys per checkpoint

The system proves:
    - Content states form an unbroken chain
    - Minimum time elapsed between commits (VDF)
    - Real keystrokes occurred over time (jitter evidence)
    - Your signed declaration of creative process
    - Persistent author identity with forward secrecy

Patent Pending: USPTO Application No. 19/460,364

See https://github.com/writerslogic/witnessd for documentation.`)
}

func printVersion() {
	fmt.Print(banner)
	fmt.Printf("witnessd %s\n", Version)
	fmt.Printf("  Build:    %s\n", BuildTime)
	fmt.Printf("  Commit:   %s\n", Commit)
	fmt.Printf("  Platform: %s/%s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Printf("  Go:       %s\n", runtime.Version())
}

func witnessdDir() string {
	return config.WitnessdDir()
}

func cmdInit() {
	dir := witnessdDir()

	// Create directory structure
	dirs := []string{
		dir,
		filepath.Join(dir, "chains"),
		filepath.Join(dir, "sessions"),
		filepath.Join(dir, "tracking"),
		filepath.Join(dir, "sentinel"),
		filepath.Join(dir, "sentinel", "wal"),
	}

	for _, d := range dirs {
		if err := os.MkdirAll(d, 0700); err != nil {
			fmt.Fprintf(os.Stderr, "Error creating directory %s: %v\n", d, err)
			os.Exit(1)
		}
	}

	// Generate signing key if not exists
	keyPath := filepath.Join(dir, "signing_key")
	var privKey ed25519.PrivateKey
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		fmt.Println("Generating Ed25519 signing key...")
		pub, priv, err := ed25519.GenerateKey(nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error generating key: %v\n", err)
			os.Exit(1)
		}
		privKey = priv

		if err := os.WriteFile(keyPath, priv, 0600); err != nil {
			fmt.Fprintf(os.Stderr, "Error saving private key: %v\n", err)
			os.Exit(1)
		}

		if err := os.WriteFile(keyPath+".pub", pub, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Error saving public key: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("  Public key: %s\n", hex.EncodeToString(pub[:8])+"...")
	} else {
		// Load existing key
		keyData, err := os.ReadFile(keyPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading signing key: %v\n", err)
			os.Exit(1)
		}
		privKey = ed25519.PrivateKey(keyData)
	}

	// Initialize master identity from PUF (key hierarchy)
	pufSeedPath := filepath.Join(dir, "puf_seed")
	if _, err := os.Stat(pufSeedPath); os.IsNotExist(err) {
		fmt.Println("Initializing master identity from PUF...")
		puf, err := keyhierarchy.LoadOrCreateSoftwarePUF(pufSeedPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating PUF seed: %v\n", err)
			os.Exit(1)
		}

		identity, err := keyhierarchy.DeriveMasterIdentity(puf)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error deriving master identity: %v\n", err)
			os.Exit(1)
		}

		// Save identity public key
		identityPath := filepath.Join(dir, "identity.json")
		identityData, _ := json.MarshalIndent(map[string]interface{}{
			"version":     keyhierarchy.Version,
			"fingerprint": identity.Fingerprint,
			"public_key":  hex.EncodeToString(identity.PublicKey),
			"device_id":   identity.DeviceID,
			"created_at":  identity.CreatedAt,
		}, "", "  ")
		if err := os.WriteFile(identityPath, identityData, 0600); err != nil {
			fmt.Fprintf(os.Stderr, "Error saving identity: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("  Master Identity: %s\n", identity.Fingerprint)
		fmt.Printf("  Device ID: %s\n", identity.DeviceID)
	} else {
		// Load existing identity
		puf, err := keyhierarchy.LoadOrCreateSoftwarePUF(pufSeedPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading PUF: %v\n", err)
			os.Exit(1)
		}
		identity, err := keyhierarchy.DeriveMasterIdentity(puf)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error deriving identity: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("  Existing Master Identity: %s\n", identity.Fingerprint)
	}

	// Create secure SQLite database
	dbPath := filepath.Join(dir, "events.db")
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		fmt.Println("Creating secure event database...")

		// Derive HMAC key from signing key for database integrity
		hmacKey := deriveHMACKey(privKey)

		db, err := store.OpenSecure(dbPath, hmacKey)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating database: %v\n", err)
			os.Exit(1)
		}
		db.Close()
		fmt.Println("  Database: events.db (tamper-evident)")
	}

	// Create default config if not exists
	configPath := filepath.Join(dir, "config.json")
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		cfg := map[string]interface{}{
			"version": 4,
			"storage": map[string]interface{}{
				"type":   "sqlite",
				"path":   "events.db",
				"secure": true,
			},
			"vdf": map[string]interface{}{
				"iterations_per_second": 1000000,
				"min_iterations":        100000,
				"max_iterations":        3600000000,
				"calibrated":            false,
			},
			"presence": map[string]interface{}{
				"challenge_interval_seconds": 600,
				"response_window_seconds":    60,
			},
			"key_hierarchy": map[string]interface{}{
				"enabled": true,
				"version": keyhierarchy.Version,
			},
			"sentinel": map[string]interface{}{
				"auto_start":          false,
				"heartbeat_seconds":   60,
				"checkpoint_seconds":  60,
				"wal_enabled":         true,
			},
		}

		data, _ := json.MarshalIndent(cfg, "", "  ")
		if err := os.WriteFile(configPath, data, 0600); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing config: %v\n", err)
			os.Exit(1)
		}
	}

	fmt.Println()
	fmt.Println("witnessd initialized!")
	fmt.Println()
	fmt.Println("Next steps:")
	fmt.Println("  1. Run 'witnessd calibrate' to calibrate VDF for your machine")
	fmt.Println("  2. Create checkpoints with 'witnessd commit <file> -m \"message\"'")
	fmt.Println("  3. Export evidence with 'witnessd export <file>'")
	fmt.Println()
	fmt.Println("Optional: Run 'witnessd sentinel start' for automatic document tracking")
}

// deriveHMACKey derives an HMAC key from the signing key for database integrity.
func deriveHMACKey(privKey ed25519.PrivateKey) []byte {
	h := sha256.New()
	h.Write([]byte("witnessd-hmac-key-v1"))
	h.Write(privKey.Seed())
	return h.Sum(nil)
}

// openSecureStore opens the secure SQLite database.
func openSecureStore() (*store.SecureStore, error) {
	dir := witnessdDir()
	dbPath := filepath.Join(dir, "events.db")
	keyPath := filepath.Join(dir, "signing_key")

	// Load signing key
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read signing key: %w", err)
	}

	privKey := ed25519.PrivateKey(keyData)
	hmacKey := deriveHMACKey(privKey)

	return store.OpenSecure(dbPath, hmacKey)
}

// getDeviceID returns a stable device identifier derived from the signing key.
func getDeviceID() [16]byte {
	dir := witnessdDir()
	keyPath := filepath.Join(dir, "signing_key.pub")

	pubKey, err := os.ReadFile(keyPath)
	if err != nil {
		var zero [16]byte
		return zero
	}

	// Device ID is first 16 bytes of SHA256(public key)
	h := sha256.Sum256(pubKey)
	var id [16]byte
	copy(id[:], h[:16])
	return id
}

func cmdCommit() {
	fs := flag.NewFlagSet("commit", flag.ExitOnError)
	message := fs.String("m", "", "Commit message")
	fs.Parse(os.Args[2:])

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "Usage: witnessd commit <file> [-m message]")
		os.Exit(1)
	}

	filePath := fs.Arg(0)

	// Check file exists
	fileInfo, err := os.Stat(filePath)
	if os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "File not found: %s\n", filePath)
		os.Exit(1)
	}

	// Get absolute path
	absPath, err := filepath.Abs(filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error resolving path: %v\n", err)
		os.Exit(1)
	}

	// Open secure database
	db, err := openSecureStore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening database: %v\n", err)
		fmt.Fprintln(os.Stderr, "Run 'witnessd init' first.")
		os.Exit(1)
	}
	defer db.Close()

	// Read file content and compute hash
	content, err := os.ReadFile(absPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
		os.Exit(1)
	}
	contentHash := sha256.Sum256(content)

	// Get previous event for this file (for VDF input and size delta)
	lastEvent, _ := db.GetLastSecureEventForFile(absPath)

	var vdfInput [32]byte
	var sizeDelta int32
	if lastEvent != nil {
		vdfInput = lastEvent.EventHash // VDF input is previous event hash
		sizeDelta = int32(fileInfo.Size() - lastEvent.FileSize)
	} else {
		// Genesis: VDF input is content hash
		vdfInput = contentHash
		sizeDelta = int32(fileInfo.Size())
	}

	// Load VDF parameters and compute VDF proof
	vdfParams := loadVDFParams()

	fmt.Printf("Computing checkpoint...")
	start := time.Now()

	// Use 1 second as default VDF target duration
	vdfProof, err := vdf.Compute(vdfInput, time.Second, vdfParams)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\nError computing VDF: %v\n", err)
		os.Exit(1)
	}
	elapsed := time.Since(start)

	// Load signing key for ShadowCache
	keyPath := filepath.Join(witnessdDir(), "signing_key")
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\nError loading signing key: %v\n", err)
		os.Exit(1)
	}

	// Initialize ShadowCache
	shadowCache, err := witness.NewShadowCache(witnessdDir(), keyData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\nError initializing shadow cache: %v\n", err)
		os.Exit(1)
	}

	// Calculate Edit Topology
	var regions []witness.EditRegion
	prevShadow, _ := shadowCache.Get(absPath)

	if prevShadow != nil {
		if prevShadow.Strategy == witness.ShadowFull {
			regions = witness.ExtractTopology(prevShadow.Content, content)
		} else if prevShadow.Strategy == witness.ShadowChunked {
			currChunks := witness.ComputeChunks(content)
			regions = witness.DiffChunked(prevShadow.FileSize, content, prevShadow.Chunks, currChunks)
		}
	} else {
		// New file
		regions = witness.ExtractTopology(nil, content)
	}

	regionsRoot := witness.ComputeRegionsRoot(regions)

	// Update ShadowCache
	if err := shadowCache.Put(absPath, content); err != nil {
		fmt.Fprintf(os.Stderr, "\nWarning: failed to update shadow cache: %v\n", err)
	}

	// Check for active tracking session
	var trackingInfo string
	if jitterEv := loadTrackingEvidence(filePath); jitterEv != nil {
		trackingInfo = fmt.Sprintf(" (tracking: %d keystrokes, %d samples)",
			jitterEv.Statistics.TotalKeystrokes,
			jitterEv.Statistics.TotalSamples)
	}

	// Create event
	event := &store.SecureEvent{
		DeviceID:      getDeviceID(),
		TimestampNs:   time.Now().UnixNano(),
		FilePath:      absPath,
		ContentHash:   contentHash,
		FileSize:      fileInfo.Size(),
		SizeDelta:     sizeDelta,
		ContextType:   *message,
		VDFInput:      vdfInput,
		VDFOutput:     vdfProof.Output,
		VDFIterations: vdfProof.Iterations,
		RegionsRoot:   regionsRoot,
		EditRegions:   regions,
	}

	if err := db.InsertSecureEvent(event); err != nil {
		fmt.Fprintf(os.Stderr, "\nError saving checkpoint: %v\n", err)
		os.Exit(1)
	}

	// Get checkpoint number
	count, _ := db.CountEventsForFile(absPath)

	fmt.Printf(" done (%s)\n", elapsed.Round(time.Millisecond))
	fmt.Println()
	fmt.Printf("Checkpoint #%d created%s\n", count, trackingInfo)
	fmt.Printf("  Content hash: %s...\n", hex.EncodeToString(contentHash[:8]))
	fmt.Printf("  Event hash:   %s...\n", hex.EncodeToString(event.EventHash[:8]))
	fmt.Printf("  VDF proves:   >= %s elapsed\n", vdfProof.MinElapsedTime(vdfParams).Round(time.Second))
	if *message != "" {
		fmt.Printf("  Message:      %s\n", *message)
	}
}

func cmdLog() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "Usage: witnessd log <file>")
		os.Exit(1)
	}

	filePath := os.Args[2]

	// Get absolute path
	absPath, err := filepath.Abs(filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error resolving path: %v\n", err)
		os.Exit(1)
	}

	// Open database
	db, err := openSecureStore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening database: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	// Get events for file
	events, err := db.GetEventsForFile(absPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading events: %v\n", err)
		os.Exit(1)
	}

	if len(events) == 0 {
		fmt.Printf("No checkpoint history found for: %s\n", filePath)
		return
	}

	// Calculate total VDF time
	vdfParams := loadVDFParams()
	totalVDFTime, _ := db.GetTotalVDFTime(absPath, vdfParams.IterationsPerSecond)

	fmt.Printf("=== Checkpoint History: %s ===\n", filepath.Base(filePath))
	fmt.Printf("Document: %s\n", absPath)
	fmt.Printf("Checkpoints: %d\n", len(events))
	fmt.Printf("Total VDF time: %s\n", totalVDFTime.Round(time.Second))
	fmt.Println()

	for i, ev := range events {
		ts := time.Unix(0, ev.TimestampNs)
		fmt.Printf("[%d] %s\n", i+1, ts.Format("2006-01-02 15:04:05"))
		fmt.Printf("    Hash: %s\n", hex.EncodeToString(ev.ContentHash[:]))
		fmt.Printf("    Size: %d bytes", ev.FileSize)
		if ev.SizeDelta != 0 {
			if ev.SizeDelta > 0 {
				fmt.Printf(" (+%d)", ev.SizeDelta)
			} else {
				fmt.Printf(" (%d)", ev.SizeDelta)
			}
		}
		fmt.Println()
		if ev.VDFIterations > 0 {
			elapsed := time.Duration(float64(ev.VDFIterations) / float64(vdfParams.IterationsPerSecond) * float64(time.Second))
			fmt.Printf("    VDF:  >= %s\n", elapsed.Round(time.Second))
		}
		if ev.ContextType != "" {
			fmt.Printf("    Msg:  %s\n", ev.ContextType)
		}
		fmt.Println()
	}
}

func cmdExport() {
	fs := flag.NewFlagSet("export", flag.ExitOnError)
	tier := fs.String("tier", "basic", "Evidence tier: basic, standard, enhanced, maximum")
	output := fs.String("o", "", "Output file (default: <file>.evidence.json)")
	fs.Parse(os.Args[2:])

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "Usage: witnessd export <file> [-tier basic|standard|enhanced|maximum] [-o output.json]")
		os.Exit(1)
	}

	filePath := fs.Arg(0)

	// Get absolute path
	absPath, err := filepath.Abs(filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error resolving path: %v\n", err)
		os.Exit(1)
	}

	// Try SQLite first
	db, err := openSecureStore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening database: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	events, err := db.GetEventsForFile(absPath)
	if err != nil || len(events) == 0 {
		// Fall back to legacy chain
		cmdExportLegacy(filePath, *tier, *output)
		return
	}

	// SQLite-based export
	cmdExportFromSQLite(absPath, events, *tier, *output)
}

func cmdExportFromSQLite(absPath string, events []store.SecureEvent, tier, output string) {
	vdfParams := loadVDFParams()

	// Load signing key
	keyPath := filepath.Join(witnessdDir(), "signing_key")
	privKeyData, err := os.ReadFile(keyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading signing key: %v\n", err)
		os.Exit(1)
	}
	privKey := ed25519.PrivateKey(privKeyData)

	// Get latest event
	latest := events[len(events)-1]

	// Collect declaration
	fmt.Println("=== Process Declaration ===")
	fmt.Println("You must declare how this document was created.")
	fmt.Println()

	decl, err := collectDeclarationSimple(latest.ContentHash, latest.EventHash, filepath.Base(absPath), privKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating declaration: %v\n", err)
		os.Exit(1)
	}

	// Calculate totals
	var totalIterations uint64
	for _, ev := range events {
		totalIterations += ev.VDFIterations
	}
	totalVDFTime := time.Duration(float64(totalIterations) / float64(vdfParams.IterationsPerSecond) * float64(time.Second))

	// Build evidence packet
	packet := map[string]interface{}{
		"version":     3,
		"format":      "witnessd-sqlite",
		"exported_at": time.Now().Format(time.RFC3339),
		"tier":        tier,
		"document": map[string]interface{}{
			"path":         absPath,
			"name":         filepath.Base(absPath),
			"final_hash":   hex.EncodeToString(latest.ContentHash[:]),
			"final_size":   latest.FileSize,
			"checkpoints":  len(events),
			"total_vdf_time": totalVDFTime.String(),
		},
		"vdf_params": map[string]interface{}{
			"iterations_per_second": vdfParams.IterationsPerSecond,
		},
		"chain_hash":  hex.EncodeToString(latest.EventHash[:]),
		"declaration": decl,
		"checkpoints": formatEventsForExport(events, vdfParams),
		"claims": []map[string]interface{}{
			{"type": "cryptographic", "description": "Content states form unbroken cryptographic chain", "confidence": "certain"},
			{"type": "cryptographic", "description": fmt.Sprintf("At least %s elapsed during documented composition", totalVDFTime.Round(time.Second)), "confidence": "certain"},
		},
		"limitations": []string{
			"Cannot prove cognitive origin of ideas",
			"Cannot prove absence of AI involvement in ideation",
		},
	}

	// Add key hierarchy evidence
	khEv := loadKeyHierarchyEvidence(absPath)
	if khEv != nil {
		packet["key_hierarchy"] = map[string]interface{}{
			"version":             khEv.Version,
			"master_fingerprint":  khEv.MasterFingerprint,
			"master_public_key":   hex.EncodeToString(khEv.MasterPublicKey),
			"device_id":           khEv.DeviceID,
			"session_id":          khEv.SessionID,
			"session_public_key":  hex.EncodeToString(khEv.SessionPublicKey),
			"session_started":     khEv.SessionStarted.Format(time.RFC3339),
			"session_certificate": hex.EncodeToString(khEv.SessionCertificateRaw),
			"ratchet_count":       khEv.RatchetCount,
		}
		packet["claims"] = append(packet["claims"].([]map[string]interface{}),
			map[string]interface{}{
				"type":        "identity",
				"description": fmt.Sprintf("Identity verified: %s", khEv.MasterFingerprint),
				"confidence":  "certain",
			})
		fmt.Printf("Including key hierarchy evidence: %s\n", khEv.MasterFingerprint)
	}

	// Add keystroke evidence if available
	keystrokeEvidence := loadTrackingEvidence(absPath)
	if keystrokeEvidence != nil && (tier == "standard" || tier == "enhanced" || tier == "maximum") {
		packet["keystroke"] = map[string]interface{}{
			"session_id":       keystrokeEvidence.SessionID,
			"total_keystrokes": keystrokeEvidence.Statistics.TotalKeystrokes,
			"total_samples":    keystrokeEvidence.Statistics.TotalSamples,
			"duration":         keystrokeEvidence.Statistics.Duration.String(),
			"keystrokes_per_min": keystrokeEvidence.Statistics.KeystrokesPerMin,
			"chain_valid":      keystrokeEvidence.Statistics.ChainValid,
		}
		packet["claims"] = append(packet["claims"].([]map[string]interface{}),
			map[string]interface{}{
				"type":        "behavioral",
				"description": fmt.Sprintf("Real keystrokes recorded: %d events", keystrokeEvidence.Statistics.TotalKeystrokes),
				"confidence":  "high",
			})
		fmt.Printf("Including keystroke evidence: %d keystrokes, %d samples\n",
			keystrokeEvidence.Statistics.TotalKeystrokes,
			keystrokeEvidence.Statistics.TotalSamples)
	}

	// Determine output path
	outPath := output
	if outPath == "" {
		outPath = filepath.Base(absPath) + ".evidence.json"
	}

	// Save
	data, _ := json.MarshalIndent(packet, "", "  ")
	if err := os.WriteFile(outPath, data, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error saving evidence: %v\n", err)
		os.Exit(1)
	}

	fmt.Println()
	fmt.Printf("Evidence exported to: %s\n", outPath)
	fmt.Printf("  Checkpoints: %d\n", len(events))
	fmt.Printf("  Total VDF time: %s\n", totalVDFTime.Round(time.Second))
	fmt.Printf("  Tier: %s\n", tier)
}

func formatEventsForExport(events []store.SecureEvent, vdfParams vdf.Parameters) []map[string]interface{} {
	result := make([]map[string]interface{}, len(events))
	for i, ev := range events {
		elapsed := time.Duration(float64(ev.VDFIterations) / float64(vdfParams.IterationsPerSecond) * float64(time.Second))
		result[i] = map[string]interface{}{
			"ordinal":        i + 1,
			"timestamp":      time.Unix(0, ev.TimestampNs).Format(time.RFC3339),
			"content_hash":   hex.EncodeToString(ev.ContentHash[:]),
			"event_hash":     hex.EncodeToString(ev.EventHash[:]),
			"file_size":      ev.FileSize,
			"size_delta":     ev.SizeDelta,
			"vdf_iterations": ev.VDFIterations,
			"vdf_elapsed":    elapsed.String(),
			"message":        ev.ContextType,
		}
	}
	return result
}

func collectDeclarationSimple(contentHash, chainHash [32]byte, docName string, privKey ed25519.PrivateKey) (map[string]interface{}, error) {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println("Input modality (how was this written?):")
	fmt.Println("  1. Keyboard (typing)")
	fmt.Println("  2. Dictation (voice)")
	fmt.Println("  3. Mixed")
	fmt.Print("Choice [1]: ")

	modalityChoice, _ := reader.ReadString('\n')
	modalityChoice = strings.TrimSpace(modalityChoice)

	modality := "keyboard"
	switch modalityChoice {
	case "2":
		modality = "dictation"
	case "3":
		modality = "mixed"
	}

	fmt.Println()
	fmt.Println("Did you use any AI tools? (y/n)")
	fmt.Print("Choice [n]: ")

	aiChoice, _ := reader.ReadString('\n')
	aiChoice = strings.TrimSpace(aiChoice)

	var aiInfo map[string]interface{}
	if strings.ToLower(aiChoice) == "y" {
		fmt.Print("Which AI tool? ")
		tool, _ := reader.ReadString('\n')
		tool = strings.TrimSpace(tool)

		fmt.Println("How was it used? (1=research, 2=feedback, 3=editing, 4=drafting)")
		fmt.Print("Choice [1]: ")
		purposeChoice, _ := reader.ReadString('\n')
		purposeChoice = strings.TrimSpace(purposeChoice)

		purpose := "research"
		switch purposeChoice {
		case "2":
			purpose = "feedback"
		case "3":
			purpose = "editing"
		case "4":
			purpose = "drafting"
		}

		fmt.Println("Extent? (1=minimal, 2=moderate, 3=substantial)")
		fmt.Print("Choice [1]: ")
		extentChoice, _ := reader.ReadString('\n')
		extentChoice = strings.TrimSpace(extentChoice)

		extent := "minimal"
		switch extentChoice {
		case "2":
			extent = "moderate"
		case "3":
			extent = "substantial"
		}

		aiInfo = map[string]interface{}{
			"tool":    tool,
			"purpose": purpose,
			"extent":  extent,
		}
	}

	fmt.Println()
	fmt.Print("Brief statement about your process: ")
	statement, _ := reader.ReadString('\n')
	statement = strings.TrimSpace(statement)
	if statement == "" {
		statement = "I authored this document as declared."
	}

	decl := map[string]interface{}{
		"document":     docName,
		"content_hash": hex.EncodeToString(contentHash[:]),
		"chain_hash":   hex.EncodeToString(chainHash[:]),
		"modality":     modality,
		"statement":    statement,
		"timestamp":    time.Now().Format(time.RFC3339),
	}

	if aiInfo != nil {
		decl["ai_tools"] = []interface{}{aiInfo}
	}

	// Sign the declaration
	declBytes, _ := json.Marshal(decl)
	signature := ed25519.Sign(privKey, declBytes)
	decl["signature"] = hex.EncodeToString(signature)
	decl["public_key"] = hex.EncodeToString(privKey.Public().(ed25519.PublicKey))

	return decl, nil
}

func cmdExportLegacy(filePath, tier, output string) {
	// Find and load chain
	chainPath, err := checkpoint.FindChain(filePath, witnessdDir())
	if err != nil {
		fmt.Fprintf(os.Stderr, "No checkpoint history found for: %s\n", filePath)
		os.Exit(1)
	}

	chain, err := checkpoint.Load(chainPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading chain: %v\n", err)
		os.Exit(1)
	}

	if len(chain.Checkpoints) == 0 {
		fmt.Fprintln(os.Stderr, "No checkpoints found. Run 'witnessd commit' first.")
		os.Exit(1)
	}

	// Load signing key
	keyPath := filepath.Join(witnessdDir(), "signing_key")
	privKey, err := os.ReadFile(keyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading signing key: %v\n", err)
		os.Exit(1)
	}

	// Collect declaration interactively
	fmt.Println("=== Process Declaration ===")
	fmt.Println("You must declare how this document was created.")
	fmt.Println()

	decl, err := collectDeclaration(chain, filePath, ed25519.PrivateKey(privKey))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating declaration: %v\n", err)
		os.Exit(1)
	}

	// Build evidence packet
	builder := evidence.NewBuilder(filepath.Base(filePath), chain).
		WithDeclaration(decl)

	// Add key hierarchy evidence
	khEv := loadKeyHierarchyEvidence(filePath)
	if khEv != nil {
		builder.WithKeyHierarchy(khEv)
		fmt.Printf("Including key hierarchy evidence: %s\n", khEv.MasterFingerprint)
	}

	// Load tracking evidence if available
	keystrokeEvidence := loadTrackingEvidence(filePath)
	if keystrokeEvidence != nil {
		fmt.Printf("Including keystroke evidence: %d keystrokes, %d samples\n",
			keystrokeEvidence.Statistics.TotalKeystrokes,
			keystrokeEvidence.Statistics.TotalSamples)
	}

	// Add tier-specific evidence
	switch strings.ToLower(tier) {
	case "standard":
		sessions := loadPresenceSessions(filePath)
		if len(sessions) > 0 {
			builder.WithPresence(sessions)
		}
		// Include keystroke evidence at standard tier and above
		if keystrokeEvidence != nil {
			builder.WithKeystroke(keystrokeEvidence)
		}
	case "enhanced":
		sessions := loadPresenceSessions(filePath)
		if len(sessions) > 0 {
			builder.WithPresence(sessions)
		}
		// Include keystroke evidence
		if keystrokeEvidence != nil {
			builder.WithKeystroke(keystrokeEvidence)
		}
		// Add TPM hardware attestation
		tpmBindings, tpmDeviceID := collectTPMBindings(chain)
		if len(tpmBindings) > 0 {
			builder.WithHardware(tpmBindings, tpmDeviceID)
			fmt.Printf("Including TPM attestation: %d bindings\n", len(tpmBindings))
		}
	case "maximum":
		sessions := loadPresenceSessions(filePath)
		if len(sessions) > 0 {
			builder.WithPresence(sessions)
		}
		// Include keystroke evidence
		if keystrokeEvidence != nil {
			builder.WithKeystroke(keystrokeEvidence)
		}
		// Add TPM hardware attestation
		tpmBindings, tpmDeviceID := collectTPMBindings(chain)
		if len(tpmBindings) > 0 {
			builder.WithHardware(tpmBindings, tpmDeviceID)
			fmt.Printf("Including TPM attestation: %d bindings\n", len(tpmBindings))
		}
		// All layers would be added here (behavioral data, external anchors)
	}

	packet, err := builder.Build()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error building evidence: %v\n", err)
		os.Exit(1)
	}

	// Determine output path
	outPath := output
	if outPath == "" {
		outPath = filepath.Base(filePath) + ".evidence.json"
	}

	// Save
	data, _ := packet.Encode()
	if err := os.WriteFile(outPath, data, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error saving evidence: %v\n", err)
		os.Exit(1)
	}

	fmt.Println()
	fmt.Printf("Evidence exported to: %s\n", outPath)
	fmt.Println()
	fmt.Printf("Strength: %s\n", packet.Strength)
	fmt.Printf("Checkpoints: %d\n", len(packet.Checkpoints))
	fmt.Printf("Total elapsed: %s\n", packet.TotalElapsedTime().Round(time.Second))
	fmt.Println()
	fmt.Println("Claims:")
	for _, claim := range packet.Claims {
		fmt.Printf("  - [%s] %s\n", claim.Confidence, claim.Description)
	}
}

func cmdVerify() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "Usage: witnessd verify <file|evidence.json|evidence.wpkt>")
		os.Exit(1)
	}

	path := os.Args[2]

	// Check if it's a .wpkt file (witnessd packet - binary or JSON)
	if strings.HasSuffix(path, ".wpkt") {
		verifyEvidencePacket(path)
		return
	}

	// Check if it's an evidence JSON file
	if strings.HasSuffix(path, ".json") || strings.HasSuffix(path, ".evidence.json") {
		data, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
			os.Exit(1)
		}

		packet, err := evidence.Decode(data)
		if err != nil {
			// Try as chain verification
			verifyChain(path)
			return
		}

		verifyPacket(packet)
		return
	}

	// Verify chain for file
	verifyChain(path)
}

// verifyEvidencePacket verifies a .wpkt evidence packet file.
func verifyEvidencePacket(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
		os.Exit(1)
	}

	// Try JSON first
	packet, err := evidence.Decode(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error decoding evidence packet: %v\n", err)
		os.Exit(1)
	}

	verifyPacket(packet)
}

// verifyPacket verifies an evidence packet and prints results.
func verifyPacket(packet *evidence.Packet) {
	fmt.Println("=== Evidence Verification ===")
	fmt.Println()

	// Verify evidence packet
	vdfParams := loadVDFParams()
	if err := packet.Verify(vdfParams); err != nil {
		fmt.Fprintf(os.Stderr, "Verification FAILED: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Document: %s\n", packet.Document.Title)
	fmt.Printf("Strength: %s\n", packet.Strength)
	fmt.Printf("Checkpoints: %d\n", len(packet.Checkpoints))
	fmt.Printf("Total elapsed: %s\n", packet.TotalElapsedTime().Round(time.Second))

	// Verify keystroke/jitter evidence if present
	if packet.Keystroke != nil {
		fmt.Println()
		fmt.Println("Keystroke Evidence:")
		fmt.Printf("  Keystrokes: %d\n", packet.Keystroke.TotalKeystrokes)
		fmt.Printf("  Jitter samples: %d\n", packet.Keystroke.TotalSamples)
		fmt.Printf("  Duration: %s\n", packet.Keystroke.Duration.Round(time.Second))
		fmt.Printf("  Typing rate: %.0f keystrokes/min\n", packet.Keystroke.KeystrokesPerMin)

		// Verify jitter chain if samples are present
		if len(packet.Keystroke.Samples) > 0 {
			jitterEv := &jitter.Evidence{
				SessionID:    packet.Keystroke.SessionID,
				StartedAt:    packet.Keystroke.StartedAt,
				EndedAt:      packet.Keystroke.EndedAt,
				Samples:      packet.Keystroke.Samples,
				Statistics: jitter.Statistics{
					TotalKeystrokes:  packet.Keystroke.TotalKeystrokes,
					TotalSamples:     packet.Keystroke.TotalSamples,
					Duration:         packet.Keystroke.Duration,
					KeystrokesPerMin: packet.Keystroke.KeystrokesPerMin,
					UniqueDocHashes:  packet.Keystroke.UniqueDocStates,
					ChainValid:       packet.Keystroke.ChainValid,
				},
			}
			if err := jitterEv.Verify(); err != nil {
				fmt.Printf("  Jitter chain: INVALID (%v)\n", err)
			} else {
				fmt.Println("  Jitter chain: VALID")
			}
		}

		if packet.Keystroke.PlausibleHumanRate {
			fmt.Println("  Human plausibility: consistent with human typing")
		} else {
			fmt.Println("  Human plausibility: unusual patterns detected")
		}
	}

	fmt.Println()
	fmt.Println("Claims verified:")
	for _, claim := range packet.Claims {
		fmt.Printf("  [OK] %s\n", claim.Description)
	}
	fmt.Println()
	fmt.Println("Verification PASSED")
}

func verifyChain(filePath string) {
	chainPath, err := checkpoint.FindChain(filePath, witnessdDir())
	if err != nil {
		fmt.Fprintf(os.Stderr, "No checkpoint history found for: %s\n", filePath)
		os.Exit(1)
	}

	chain, err := checkpoint.Load(chainPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading chain: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Verifying checkpoint chain...")

	if err := chain.Verify(); err != nil {
		fmt.Fprintf(os.Stderr, "Verification FAILED: %v\n", err)
		os.Exit(1)
	}

	fmt.Println()
	fmt.Printf("Chain: %d checkpoints\n", len(chain.Checkpoints))
	fmt.Printf("Total VDF-proven time: %s\n", chain.TotalElapsedTime().Round(time.Second))
	fmt.Println()
	fmt.Println("✓ All hash links valid")
	fmt.Println("✓ All VDF proofs verified")
	fmt.Println()
	fmt.Println("Verification PASSED")
}

func cmdPresence() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "Usage: witnessd presence <start|stop|status|challenge>")
		os.Exit(1)
	}

	action := os.Args[2]
	sessionFile := filepath.Join(witnessdDir(), "sessions", "current.json")

	switch action {
	case "start":
		// Check for existing session
		if _, err := os.Stat(sessionFile); err == nil {
			fmt.Fprintln(os.Stderr, "Session already active. Run 'witnessd presence stop' first.")
			os.Exit(1)
		}

		verifier := presence.NewVerifier(presence.DefaultConfig())
		session, err := verifier.StartSession()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error starting session: %v\n", err)
			os.Exit(1)
		}

		data, _ := session.Encode()
		if err := os.WriteFile(sessionFile, data, 0600); err != nil {
			fmt.Fprintf(os.Stderr, "Error saving session: %v\n", err)
			os.Exit(1)
		}

		fmt.Println("Presence verification session started.")
		fmt.Printf("Session ID: %s\n", session.ID)
		fmt.Println()
		fmt.Println("Run 'witnessd presence challenge' periodically to verify presence.")

	case "stop":
		data, err := os.ReadFile(sessionFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "No active session.")
			os.Exit(1)
		}

		session, err := presence.DecodeSession(data)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading session: %v\n", err)
			os.Exit(1)
		}

		session.Active = false
		session.EndTime = time.Now()

		// Calculate stats
		for _, c := range session.Challenges {
			session.ChallengesIssued++
			switch c.Status {
			case presence.StatusPassed:
				session.ChallengesPassed++
			case presence.StatusFailed:
				session.ChallengesFailed++
			default:
				session.ChallengesMissed++
			}
		}
		if session.ChallengesIssued > 0 {
			session.VerificationRate = float64(session.ChallengesPassed) / float64(session.ChallengesIssued)
		}

		// Archive session
		archivePath := filepath.Join(witnessdDir(), "sessions", session.ID+".json")
		archiveData, _ := session.Encode()
		os.WriteFile(archivePath, archiveData, 0600)
		os.Remove(sessionFile)

		fmt.Println("Session ended.")
		fmt.Printf("Duration: %s\n", session.EndTime.Sub(session.StartTime).Round(time.Second))
		fmt.Printf("Challenges: %d issued, %d passed (%.0f%%)\n",
			session.ChallengesIssued, session.ChallengesPassed, session.VerificationRate*100)

	case "status":
		data, err := os.ReadFile(sessionFile)
		if err != nil {
			fmt.Println("No active session.")
			return
		}

		session, _ := presence.DecodeSession(data)
		fmt.Println("Active session:")
		fmt.Printf("  ID: %s\n", session.ID)
		fmt.Printf("  Started: %s\n", session.StartTime.Format(time.RFC3339))
		fmt.Printf("  Duration: %s\n", time.Since(session.StartTime).Round(time.Second))
		fmt.Printf("  Challenges: %d\n", len(session.Challenges))

	case "challenge":
		data, err := os.ReadFile(sessionFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "No active session. Run 'witnessd presence start' first.")
			os.Exit(1)
		}

		session, _ := presence.DecodeSession(data)

		verifier := presence.NewVerifier(presence.DefaultConfig())
		// Reconstruct verifier state
		verifier.StartSession()

		challenge, err := verifier.IssueChallenge()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error issuing challenge: %v\n", err)
			os.Exit(1)
		}

		fmt.Println("=== Presence Challenge ===")
		fmt.Println()
		fmt.Println(challenge.Prompt)
		fmt.Println()
		fmt.Printf("You have %s to respond.\n", challenge.Window)
		fmt.Print("Your answer: ")

		reader := bufio.NewReader(os.Stdin)
		response, _ := reader.ReadString('\n')
		response = strings.TrimSpace(response)

		passed, err := verifier.RespondToChallenge(challenge.ID, response)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		}

		// Update session
		activeSession := verifier.ActiveSession()
		session.Challenges = append(session.Challenges, activeSession.Challenges[len(activeSession.Challenges)-1])

		newData, _ := session.Encode()
		os.WriteFile(sessionFile, newData, 0600)

		if passed {
			fmt.Println("✓ Challenge PASSED")
		} else {
			fmt.Println("✗ Challenge FAILED")
		}

	default:
		fmt.Fprintf(os.Stderr, "Unknown action: %s\n", action)
		os.Exit(1)
	}
}

func cmdTrack() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, `Usage: witnessd track <action> [options]

ACTIONS:
    start <file>    Start tracking keyboard activity for a file (runs in background)
    stop            Stop tracking and save evidence
    status          Show current tracking status
    list            List saved tracking sessions
    export <id>     Export jitter evidence from a session

PRIVACY NOTE:
    Tracking counts keystrokes - it does NOT capture which keys are pressed.
    This is NOT a keylogger. Only event counts and timing are recorded.`)
		os.Exit(1)
	}

	action := os.Args[2]
	trackingDir := filepath.Join(witnessdDir(), "tracking")
	os.MkdirAll(trackingDir, 0700)

	// Session state file
	currentFile := filepath.Join(trackingDir, "current_session.json")
	// PID file for background daemon
	pidFile := filepath.Join(trackingDir, "daemon.pid")

	switch action {
	case "start":
		if len(os.Args) < 4 {
			fmt.Fprintln(os.Stderr, "Usage: witnessd track start <file>")
			os.Exit(1)
		}

		filePath := os.Args[3]

		// Get absolute path for the file
		absPath, err := filepath.Abs(filePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error resolving path: %v\n", err)
			os.Exit(1)
		}

		// Check file exists
		if _, err := os.Stat(absPath); os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "File not found: %s\n", filePath)
			os.Exit(1)
		}

		// Check for existing session
		if _, err := os.Stat(currentFile); err == nil {
			// Check if daemon is still running
			if isTrackingDaemonRunning(pidFile) {
				fmt.Fprintln(os.Stderr, "Tracking session already active. Run 'witnessd track stop' first.")
				os.Exit(1)
			}
			// Daemon not running, clean up stale session
			os.Remove(currentFile)
			os.Remove(pidFile)
		}

		// Check if this is the daemon subprocess
		if os.Getenv("WITNESSD_TRACKING_DAEMON") == "1" {
			runTrackingDaemon(absPath, currentFile, pidFile)
			return
		}

		// Fork a daemon subprocess
		fmt.Println("Starting keystroke tracking daemon...")

		exe, err := os.Executable()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error finding executable: %v\n", err)
			os.Exit(1)
		}

		// Start daemon subprocess
		cmd := exec.Command(exe, "track", "start", absPath)
		cmd.Env = append(os.Environ(), "WITNESSD_TRACKING_DAEMON=1")
		cmd.Stdout = nil
		cmd.Stderr = nil
		cmd.Stdin = nil

		// Detach from parent process (platform-specific)
		cmd.SysProcAttr = getDaemonSysProcAttr()

		if err := cmd.Start(); err != nil {
			fmt.Fprintf(os.Stderr, "Error starting tracking daemon: %v\n", err)
			os.Exit(1)
		}

		// Wait a moment for daemon to initialize
		time.Sleep(500 * time.Millisecond)

		// Check if daemon started successfully
		if _, err := os.Stat(currentFile); os.IsNotExist(err) {
			fmt.Fprintln(os.Stderr, "Error: Tracking daemon failed to start.")
			fmt.Fprintln(os.Stderr)
			fmt.Fprintln(os.Stderr, "On macOS: Grant Accessibility permission in System Preferences")
			fmt.Fprintln(os.Stderr, "On Linux: Add yourself to the 'input' group or run as root")
			os.Exit(1)
		}

		// Read session info
		data, _ := os.ReadFile(currentFile)
		var sessionInfo map[string]interface{}
		json.Unmarshal(data, &sessionInfo)

		fmt.Println("Keystroke tracking started.")
		fmt.Printf("Session ID: %s\n", sessionInfo["id"])
		fmt.Printf("Document: %s\n", absPath)
		fmt.Println()
		fmt.Println("PRIVACY NOTE: Only keystroke counts are recorded, NOT key values.")
		fmt.Println()
		fmt.Println("Run 'witnessd track status' to check progress.")
		fmt.Println("Run 'witnessd track stop' when done.")
		return

	case "stop":
		data, err := os.ReadFile(currentFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "No active tracking session.")
			os.Exit(1)
		}

		var sessionInfo map[string]interface{}
		json.Unmarshal(data, &sessionInfo)
		sessionID := sessionInfo["id"].(string)

		// Signal the daemon to stop gracefully
		if isTrackingDaemonRunning(pidFile) {
			stopTrackingDaemon(pidFile)
			// Wait for daemon to save session
			for i := 0; i < 30; i++ {
				time.Sleep(100 * time.Millisecond)
				if !isTrackingDaemonRunning(pidFile) {
					break
				}
			}
		}

		// Load session to get final stats
		session, err := tracking.Load(witnessdDir(), sessionID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading session: %v\n", err)
			os.Exit(1)
		}

		status := session.Status()

		// Remove current session marker and PID file
		os.Remove(currentFile)
		os.Remove(pidFile)

		fmt.Println("Tracking session stopped.")
		fmt.Printf("Duration: %s\n", status.Duration.Round(time.Second))
		fmt.Printf("Keystrokes: %d\n", status.KeystrokeCount)
		fmt.Printf("Samples: %d\n", status.SampleCount)
		fmt.Printf("Checkpoints: %d\n", status.Checkpoints)
		if status.KeystrokesPerMin > 0 {
			fmt.Printf("Typing rate: %.0f keystrokes/min\n", status.KeystrokesPerMin)
		}

		// Show security summary
		fmt.Println()
		fmt.Println("Security Summary:")
		if status.TPMAvailable {
			fmt.Println("  TPM: hardware-backed")
		} else {
			fmt.Println("  TPM: software integrity only")
		}
		if status.Compromised {
			fmt.Printf("  INTEGRITY: COMPROMISED (%s)\n", status.CompromiseReason)
		} else {
			fmt.Println("  Integrity: VERIFIED")
		}
		if status.SyntheticRejected > 0 {
			fmt.Printf("  Synthetic rejected: %d events\n", status.SyntheticRejected)
		}
		if status.AnomalyPercentage > 5 {
			fmt.Printf("  Anomaly rate: %.1f%% (elevated)\n", status.AnomalyPercentage)
		} else if status.AnomalyPercentage > 0 {
			fmt.Printf("  Anomaly rate: %.1f%% (normal)\n", status.AnomalyPercentage)
		}
		if status.SuspectedScripted || status.SuspectedUSBHID {
			fmt.Println("  WARNING: Suspicious patterns detected!")
		}

		fmt.Println()
		fmt.Printf("Session saved: %s\n", sessionID)
		fmt.Println()
		fmt.Println("Include this tracking evidence when exporting:")
		fmt.Println("  witnessd export <document> -tier standard")

	case "status":
		data, err := os.ReadFile(currentFile)
		if err != nil {
			fmt.Println("No active tracking session.")
			return
		}

		var sessionInfo map[string]interface{}
		json.Unmarshal(data, &sessionInfo)
		sessionID := sessionInfo["id"].(string)

		// Check if daemon is running
		daemonRunning := isTrackingDaemonRunning(pidFile)

		// Load session to get current stats
		session, err := tracking.Load(witnessdDir(), sessionID)
		if err != nil {
			fmt.Printf("Session ID: %s\n", sessionID)
			fmt.Println("(unable to load session details)")
			return
		}

		status := session.Status()

		fmt.Println("=== Active Tracking Session ===")
		fmt.Printf("Session ID: %s\n", status.ID)
		fmt.Printf("Document: %s\n", status.DocumentPath)
		fmt.Printf("Started: %s\n", status.StartedAt.Format(time.RFC3339))
		fmt.Printf("Duration: %s\n", status.Duration.Round(time.Second))
		fmt.Printf("Keystrokes: %d\n", status.KeystrokeCount)
		fmt.Printf("Jitter samples: %d\n", status.SampleCount)
		fmt.Printf("Checkpoints: %d\n", status.Checkpoints)
		if status.PasteEvents > 0 {
			fmt.Printf("Paste events: %d (legitimate copy/paste detected)\n", status.PasteEvents)
		}
		if status.KeystrokesPerMin > 0 {
			fmt.Printf("Typing rate: %.0f keystrokes/min\n", status.KeystrokesPerMin)
		}
		if daemonRunning {
			fmt.Println("Daemon: RUNNING")
		} else {
			fmt.Println("Daemon: STOPPED (session data preserved)")
		}

		// Security status
		fmt.Println()
		fmt.Println("=== Security Status ===")
		if status.TPMAvailable {
			fmt.Println("TPM: BOUND (hardware-backed)")
		} else {
			fmt.Println("TPM: not available (software integrity only)")
		}

		if status.Compromised {
			fmt.Printf("INTEGRITY: COMPROMISED (%s)\n", status.CompromiseReason)
		} else {
			fmt.Println("Integrity: VERIFIED")
		}

		if status.SyntheticRejected > 0 {
			fmt.Printf("Synthetic events rejected: %d\n", status.SyntheticRejected)
		}

		if status.ValidationMismatch > 0 {
			fmt.Printf("Validation mismatches: %d\n", status.ValidationMismatch)
		}

		if status.AnomalyPercentage > 0 {
			fmt.Printf("Anomaly rate: %.1f%%\n", status.AnomalyPercentage)
		}

		if status.SuspectedScripted {
			fmt.Println("WARNING: Scripted input patterns detected!")
		}
		if status.SuspectedUSBHID {
			fmt.Println("WARNING: USB-HID spoofing patterns detected!")
		}

	case "list":
		manager := tracking.NewManager(witnessdDir())
		sessions, err := manager.ListSavedSessions()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error listing sessions: %v\n", err)
			os.Exit(1)
		}

		if len(sessions) == 0 {
			fmt.Println("No saved tracking sessions.")
			return
		}

		fmt.Println("Saved tracking sessions:")
		for _, id := range sessions {
			evidence, err := manager.LoadEvidence(id)
			if err != nil {
				fmt.Printf("  %s (error loading)\n", id)
				continue
			}
			fmt.Printf("  %s: %d keystrokes, %d samples, %s\n",
				id,
				evidence.Statistics.TotalKeystrokes,
				evidence.Statistics.TotalSamples,
				evidence.Statistics.Duration.Round(time.Second))
		}

	case "export":
		if len(os.Args) < 4 {
			fmt.Fprintln(os.Stderr, "Usage: witnessd track export <session-id>")
			os.Exit(1)
		}

		sessionID := os.Args[3]
		manager := tracking.NewManager(witnessdDir())
		evidence, err := manager.LoadEvidence(sessionID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading session: %v\n", err)
			os.Exit(1)
		}

		// Verify the evidence
		if err := evidence.Verify(); err != nil {
			fmt.Fprintf(os.Stderr, "Evidence verification failed: %v\n", err)
			os.Exit(1)
		}

		// Export to JSON
		outPath := sessionID + ".jitter.json"
		data, _ := evidence.Encode()
		if err := os.WriteFile(outPath, data, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing evidence: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("Jitter evidence exported to: %s\n", outPath)
		fmt.Println()
		fmt.Println("Evidence summary:")
		fmt.Printf("  Duration: %s\n", evidence.Statistics.Duration.Round(time.Second))
		fmt.Printf("  Keystrokes: %d\n", evidence.Statistics.TotalKeystrokes)
		fmt.Printf("  Samples: %d\n", evidence.Statistics.TotalSamples)
		fmt.Printf("  Document states: %d\n", evidence.Statistics.UniqueDocHashes)
		fmt.Printf("  Chain valid: %v\n", evidence.Statistics.ChainValid)

		if evidence.IsPlausibleHumanTyping() {
			fmt.Println("  Plausibility: consistent with human typing")
		} else {
			fmt.Println("  Plausibility: unusual patterns detected")
		}

	default:
		fmt.Fprintf(os.Stderr, "Unknown action: %s\n", action)
		os.Exit(1)
	}
}

func cmdCalibrate() {
	fmt.Println("Calibrating VDF performance...")
	fmt.Println("This measures your CPU's SHA-256 hashing speed.")
	fmt.Println()

	params, err := vdf.Calibrate(2 * time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Calibration failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Iterations per second: %d\n", params.IterationsPerSecond)
	fmt.Printf("Min iterations (0.1s): %d\n", params.MinIterations)
	fmt.Printf("Max iterations (1hr):  %d\n", params.MaxIterations)
	fmt.Println()

	// Save to config
	configPath := filepath.Join(witnessdDir(), "config.json")
	cfg := map[string]interface{}{
		"version": 2,
		"vdf": map[string]interface{}{
			"iterations_per_second": params.IterationsPerSecond,
			"min_iterations":        params.MinIterations,
			"max_iterations":        params.MaxIterations,
			"calibrated":            true,
			"calibrated_at":         time.Now().Format(time.RFC3339),
		},
		"presence": map[string]interface{}{
			"challenge_interval_seconds": 600,
			"response_window_seconds":    60,
		},
	}

	data, _ := json.MarshalIndent(cfg, "", "  ")
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "Error saving config: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Calibration saved.")
}

func cmdStatus() {
	dir := witnessdDir()

	fmt.Println("=== witnessd Status ===")
	fmt.Println()

	// Check initialization
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		fmt.Println("Not initialized. Run 'witnessd init' first.")
		return
	}
	fmt.Printf("Data directory: %s\n", dir)

	// Check signing key
	keyPath := filepath.Join(dir, "signing_key.pub")
	if pubKey, err := os.ReadFile(keyPath); err == nil {
		fmt.Printf("Public key: %s\n", hex.EncodeToString(pubKey[:8])+"...")
	}

	// Check VDF calibration
	vdfParams := loadVDFParams()
	fmt.Printf("VDF iterations/sec: %d\n", vdfParams.IterationsPerSecond)

	fmt.Println()
	fmt.Println("=== Secure Database ===")

	// Check SQLite database
	db, err := openSecureStore()
	if err != nil {
		fmt.Printf("Database: ERROR (%v)\n", err)
	} else {
		defer db.Close()

		stats, err := db.GetStats()
		if err != nil {
			fmt.Printf("Database: ERROR reading stats (%v)\n", err)
		} else {
			if stats.IntegrityOK {
				fmt.Println("Integrity: VERIFIED (tamper-evident)")
			} else {
				fmt.Println("Integrity: FAILED - database may be tampered!")
			}
			fmt.Printf("Events: %d\n", stats.EventCount)
			fmt.Printf("Files tracked: %d\n", stats.FileCount)
			if stats.EventCount > 0 {
				fmt.Printf("Oldest event: %s\n", stats.OldestEvent.Format(time.RFC3339))
				fmt.Printf("Newest event: %s\n", stats.NewestEvent.Format(time.RFC3339))
			}
			fmt.Printf("Chain hash: %s...\n", stats.ChainHash[:16])
		}
	}

	fmt.Println()
	fmt.Println("=== Legacy Chains ===")

	// Count chains (legacy JSON format)
	chainsDir := filepath.Join(dir, "chains")
	chains, _ := filepath.Glob(filepath.Join(chainsDir, "*.json"))
	fmt.Printf("JSON chains: %d\n", len(chains))

	// Check for active presence session
	sessionFile := filepath.Join(dir, "sessions", "current.json")
	if _, err := os.Stat(sessionFile); err == nil {
		fmt.Println("Presence session: ACTIVE")
	} else {
		fmt.Println("Presence session: none")
	}

	fmt.Println()
	fmt.Println("=== Hardware ===")

	tpmProvider := tpm.DetectTPM()
	if tpmProvider.Available() {
		if err := tpmProvider.Open(); err == nil {
			fmt.Printf("TPM: available (%s, firmware %s)\n",
				tpmProvider.Manufacturer(), tpmProvider.FirmwareVersion())
			tpmProvider.Close()
		} else {
			fmt.Println("TPM: available (unable to open)")
		}
	} else {
		fmt.Println("TPM: not available")
	}
}

// cmdDaemon runs the legacy background monitoring daemon.
// This is kept for backwards compatibility but the new recommended
// workflow is explicit commits with 'witnessd commit'.
func cmdDaemon() {
	fmt.Println("Legacy daemon mode.")
	fmt.Println("Note: The recommended workflow is now explicit commits:")
	fmt.Println("  witnessd commit <file> -m \"message\"")
	fmt.Println()
	fmt.Println("To run the legacy daemon, use the old configuration:")
	fmt.Println("  witnessd daemon --config ~/.witnessd/config.toml")
	fmt.Println()
	fmt.Println("See 'witnessd help' for the new workflow.")
}

// Helper functions

func loadVDFParams() vdf.Parameters {
	configPath := filepath.Join(witnessdDir(), "config.json")
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

func collectDeclaration(chain *checkpoint.Chain, filePath string, privKey ed25519.PrivateKey) (*declaration.Declaration, error) {
	// Get document hash
	latest := chain.Latest()
	if latest == nil {
		return nil, fmt.Errorf("no checkpoints")
	}

	// Get chain hash
	var chainHash [32]byte
	chainHash = latest.Hash

	reader := bufio.NewReader(os.Stdin)

	// Interactive declaration collection
	fmt.Println("Input modality (how was this written?):")
	fmt.Println("  1. Keyboard (typing)")
	fmt.Println("  2. Dictation (voice)")
	fmt.Println("  3. Mixed")
	fmt.Print("Choice [1]: ")

	modalityChoice, _ := reader.ReadString('\n')
	modalityChoice = strings.TrimSpace(modalityChoice)

	modality := declaration.ModalityKeyboard
	switch modalityChoice {
	case "2":
		modality = declaration.ModalityDictation
	case "3":
		modality = declaration.ModalityMixed
	}

	fmt.Println()
	fmt.Println("Did you use any AI tools? (y/n)")
	fmt.Print("Choice [n]: ")

	aiChoice, _ := reader.ReadString('\n')
	aiChoice = strings.TrimSpace(aiChoice)

	builder := declaration.NewDeclaration(latest.ContentHash, chainHash, filepath.Base(filePath)).
		AddModality(modality, 100, "")

	if strings.ToLower(aiChoice) == "y" {
		fmt.Println()
		fmt.Print("Which AI tool? (e.g., Claude, ChatGPT, Copilot): ")
		tool, _ := reader.ReadString('\n')
		tool = strings.TrimSpace(tool)

		fmt.Println("How was it used?")
		fmt.Println("  1. Research/ideation only")
		fmt.Println("  2. Feedback on drafts")
		fmt.Println("  3. Editing assistance")
		fmt.Println("  4. Drafting assistance")
		fmt.Print("Choice [1]: ")

		purposeChoice, _ := reader.ReadString('\n')
		purposeChoice = strings.TrimSpace(purposeChoice)

		purpose := declaration.PurposeResearch
		switch purposeChoice {
		case "2":
			purpose = declaration.PurposeFeedback
		case "3":
			purpose = declaration.PurposeEditing
		case "4":
			purpose = declaration.PurposeDrafting
		}

		fmt.Println("Extent of AI involvement?")
		fmt.Println("  1. Minimal (minor suggestions)")
		fmt.Println("  2. Moderate (significant assistance)")
		fmt.Println("  3. Substantial (major portions influenced)")
		fmt.Print("Choice [1]: ")

		extentChoice, _ := reader.ReadString('\n')
		extentChoice = strings.TrimSpace(extentChoice)

		extent := declaration.ExtentMinimal
		switch extentChoice {
		case "2":
			extent = declaration.ExtentModerate
		case "3":
			extent = declaration.ExtentSubstantial
		}

		builder.AddAITool(tool, "", purpose, "", extent)
	}

	fmt.Println()
	fmt.Println("Provide a brief statement about your process:")
	fmt.Print("> ")
	statement, _ := reader.ReadString('\n')
	statement = strings.TrimSpace(statement)
	if statement == "" {
		statement = "I authored this document as declared."
	}

	builder.WithStatement(statement)

	return builder.Sign(privKey)
}

func loadPresenceSessions(filePath string) []presence.Session {
	sessionsDir := filepath.Join(witnessdDir(), "sessions")
	files, _ := filepath.Glob(filepath.Join(sessionsDir, "*.json"))

	var sessions []presence.Session
	for _, f := range files {
		if filepath.Base(f) == "current.json" {
			continue
		}
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		session, err := presence.DecodeSession(data)
		if err != nil {
			continue
		}
		sessions = append(sessions, *session)
	}

	return sessions
}

// loadTrackingEvidence loads jitter evidence for a document from tracking sessions.
func loadTrackingEvidence(documentPath string) *jitter.Evidence {
	absPath, err := filepath.Abs(documentPath)
	if err != nil {
		return nil
	}

	manager := tracking.NewManager(witnessdDir())
	sessions, err := manager.ListSavedSessions()
	if err != nil {
		return nil
	}

	// Find sessions that match this document
	for _, sessionID := range sessions {
		ev, err := manager.LoadEvidence(sessionID)
		if err != nil {
			continue
		}
		if ev.DocumentPath == absPath {
			return ev
		}
	}

	// Also check current session
	trackingDir := filepath.Join(witnessdDir(), "tracking")
	currentFile := filepath.Join(trackingDir, "current_session.json")
	data, err := os.ReadFile(currentFile)
	if err == nil {
		var sessionInfo map[string]interface{}
		json.Unmarshal(data, &sessionInfo)
		if doc, ok := sessionInfo["document"].(string); ok && doc == absPath {
			if id, ok := sessionInfo["id"].(string); ok {
				ev, err := manager.LoadEvidence(id)
				if err == nil {
					return ev
				}
			}
		}
	}

	return nil
}

// isTrackingDaemonRunning checks if the tracking daemon process is running.
func isTrackingDaemonRunning(pidFile string) bool {
	data, err := os.ReadFile(pidFile)
	if err != nil {
		return false
	}

	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return false
	}

	// Check if process exists
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}

	// On Unix, FindProcess always succeeds. Send signal 0 to check if process exists.
	err = process.Signal(syscall.Signal(0))
	return err == nil
}

// stopTrackingDaemon sends SIGTERM to the tracking daemon.
func stopTrackingDaemon(pidFile string) error {
	data, err := os.ReadFile(pidFile)
	if err != nil {
		return err
	}

	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return err
	}

	process, err := os.FindProcess(pid)
	if err != nil {
		return err
	}

	return process.Signal(syscall.SIGTERM)
}

// runTrackingDaemon runs the tracking daemon in the foreground (called by subprocess).
func runTrackingDaemon(documentPath, currentFile, pidFile string) {
	// Write PID file
	if err := os.WriteFile(pidFile, []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
		os.Exit(1)
	}

	// Create tracking session
	cfg := tracking.DefaultConfig(documentPath)
	session, err := tracking.NewSession(cfg)
	if err != nil {
		os.Remove(pidFile)
		os.Exit(1)
	}

	// Start tracking
	if err := session.Start(); err != nil {
		os.Remove(pidFile)
		os.Exit(1)
	}

	// Save session info
	sessionInfo := map[string]interface{}{
		"id":         session.ID,
		"started_at": session.StartedAt,
		"document":   documentPath,
		"pid":        os.Getpid(),
	}
	data, _ := json.MarshalIndent(sessionInfo, "", "  ")
	if err := os.WriteFile(currentFile, data, 0600); err != nil {
		session.Stop()
		os.Remove(pidFile)
		os.Exit(1)
	}

	// Save initial session state
	session.Save(witnessdDir())

	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT)

	// Periodic save ticker
	saveTicker := time.NewTicker(10 * time.Second)
	defer saveTicker.Stop()

	// Run until signaled
	for {
		select {
		case <-sigChan:
			// Graceful shutdown
			session.Stop()
			session.Save(witnessdDir())
			os.Remove(pidFile)
			return
		case <-saveTicker.C:
			// Periodic save to preserve progress
			session.Save(witnessdDir())
		}
	}
}

// collectTPMBindings creates TPM attestations for checkpoint chain.
func collectTPMBindings(chain *checkpoint.Chain) ([]tpm.Binding, string) {
	provider := tpm.DetectTPM()
	if !provider.Available() {
		return nil, ""
	}

	if err := provider.Open(); err != nil {
		return nil, ""
	}
	defer provider.Close()

	deviceID, err := provider.DeviceID()
	if err != nil {
		return nil, ""
	}

	binder := tpm.NewBinder(provider)
	var bindings []tpm.Binding

	for _, cp := range chain.Checkpoints {
		binding, err := binder.Bind(cp.Hash)
		if err != nil {
			// Non-fatal - continue without this binding
			continue
		}
		bindings = append(bindings, *binding)
	}

	return bindings, hex.EncodeToString(deviceID)
}

// cmdSentinel handles sentinel daemon commands.
//
// Patent Pending: USPTO Application No. 19/460,364
func cmdSentinel() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, `Usage: witnessd sentinel <action> [options]

ACTIONS:
    start               Start background sentinel daemon
    stop                Stop sentinel daemon
    status              Show sentinel status and tracked documents
    track <file>        Add a document to sentinel tracking
    untrack <file>      Remove a document from sentinel tracking

The sentinel daemon automatically tracks documents and manages WAL-based
crash recovery for continuous authorship witnessing.`)
		os.Exit(1)
	}

	action := os.Args[2]
	dir := witnessdDir()
	daemonMgr := sentinel.NewDaemonManager(dir)

	switch action {
	case "start":
		if daemonMgr.IsRunning() {
			fmt.Fprintln(os.Stderr, "Sentinel daemon is already running.")
			status, _ := daemonMgr.Status()
			if status != nil {
				fmt.Printf("  PID: %d\n", status.PID)
				fmt.Printf("  Uptime: %s\n", status.Uptime.Round(time.Second))
			}
			os.Exit(1)
		}

		// Check if running as daemon subprocess
		if os.Getenv("WITNESSD_SENTINEL_DAEMON") == "1" {
			runSentinelDaemon(dir)
			return
		}

		// Fork daemon subprocess
		fmt.Println("Starting sentinel daemon...")

		exe, err := os.Executable()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error finding executable: %v\n", err)
			os.Exit(1)
		}

		cmd := exec.Command(exe, "sentinel", "start")
		cmd.Env = append(os.Environ(), "WITNESSD_SENTINEL_DAEMON=1")
		cmd.Stdout = nil
		cmd.Stderr = nil
		cmd.Stdin = nil
		cmd.SysProcAttr = getDaemonSysProcAttr()

		if err := cmd.Start(); err != nil {
			fmt.Fprintf(os.Stderr, "Error starting sentinel: %v\n", err)
			os.Exit(1)
		}

		// Wait for daemon to initialize
		time.Sleep(500 * time.Millisecond)

		if daemonMgr.IsRunning() {
			status, _ := daemonMgr.Status()
			fmt.Println("Sentinel daemon started.")
			if status != nil {
				fmt.Printf("  PID: %d\n", status.PID)
				if status.Identity != "" {
					fmt.Printf("  Identity: %s\n", status.Identity)
				}
			}
		} else {
			fmt.Fprintln(os.Stderr, "Error: Sentinel daemon failed to start.")
			os.Exit(1)
		}

	case "stop":
		if !daemonMgr.IsRunning() {
			fmt.Fprintln(os.Stderr, "Sentinel daemon is not running.")
			os.Exit(1)
		}

		fmt.Println("Stopping sentinel daemon...")

		if err := daemonMgr.SignalStop(); err != nil {
			fmt.Fprintf(os.Stderr, "Error signaling daemon: %v\n", err)
			os.Exit(1)
		}

		if err := daemonMgr.WaitForStop(10 * time.Second); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: %v\n", err)
		}

		fmt.Println("Sentinel daemon stopped.")

	case "status":
		status, err := daemonMgr.Status()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading status: %v\n", err)
			os.Exit(1)
		}

		fmt.Println("=== Sentinel Status ===")
		fmt.Println()

		if status.Running {
			fmt.Printf("Status: RUNNING (PID %d)\n", status.PID)
			fmt.Printf("Started: %s\n", status.StartedAt.Format(time.RFC3339))
			fmt.Printf("Uptime: %s\n", status.Uptime.Round(time.Second))
			if status.Identity != "" {
				fmt.Printf("Identity: %s\n", status.Identity)
			}
		} else {
			fmt.Println("Status: STOPPED")
		}

		// List WAL files for crash recovery info
		walDir := sentinel.WALDir(dir)
		if files, err := filepath.Glob(filepath.Join(walDir, "*.wal")); err == nil && len(files) > 0 {
			fmt.Println()
			fmt.Printf("Active WAL files: %d\n", len(files))
			for _, f := range files {
				info, _ := os.Stat(f)
				if info != nil {
					fmt.Printf("  %s (%d bytes)\n", filepath.Base(f), info.Size())
				}
			}
		}

	case "track":
		if len(os.Args) < 4 {
			fmt.Fprintln(os.Stderr, "Usage: witnessd sentinel track <file>")
			os.Exit(1)
		}

		filePath := os.Args[3]
		absPath, err := filepath.Abs(filePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error resolving path: %v\n", err)
			os.Exit(1)
		}

		if _, err := os.Stat(absPath); os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "File not found: %s\n", filePath)
			os.Exit(1)
		}

		// TODO: Send track command to running daemon via IPC
		fmt.Printf("Would track: %s\n", absPath)
		fmt.Println("Note: IPC to running daemon not yet implemented.")
		fmt.Println("For now, restart sentinel with file in auto-start list.")

	case "untrack":
		if len(os.Args) < 4 {
			fmt.Fprintln(os.Stderr, "Usage: witnessd sentinel untrack <file>")
			os.Exit(1)
		}

		filePath := os.Args[3]
		absPath, err := filepath.Abs(filePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error resolving path: %v\n", err)
			os.Exit(1)
		}

		// TODO: Send untrack command to running daemon via IPC
		fmt.Printf("Would untrack: %s\n", absPath)
		fmt.Println("Note: IPC to running daemon not yet implemented.")

	default:
		fmt.Fprintf(os.Stderr, "Unknown sentinel action: %s\n", action)
		os.Exit(1)
	}
}

// runSentinelDaemon runs the sentinel daemon in the foreground (called by subprocess).
func runSentinelDaemon(witnessdDir string) {
	daemonMgr := sentinel.NewDaemonManager(witnessdDir)

	// Write PID file
	if err := daemonMgr.WritePID(); err != nil {
		os.Exit(1)
	}

	// Load configuration
	cfg := sentinel.DefaultConfig().WithWitnessdDir(witnessdDir)

	// Create sentinel
	sent, err := sentinel.New(cfg)
	if err != nil {
		daemonMgr.Cleanup()
		os.Exit(1)
	}

	// Write daemon state
	state := &sentinel.DaemonState{
		PID:       os.Getpid(),
		StartedAt: time.Now(),
		Version:   Version,
	}
	daemonMgr.WriteState(state)

	// Start sentinel
	if err := sent.Start(context.Background()); err != nil {
		daemonMgr.Cleanup()
		os.Exit(1)
	}

	// Set up signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)

	// Run until signaled
	for {
		sig := <-sigChan
		switch sig {
		case syscall.SIGHUP:
			// Reload configuration
			// TODO: Implement config reload
			continue
		default:
			// Graceful shutdown
			sent.Stop()
			daemonMgr.Cleanup()
			return
		}
	}
}

// loadMasterIdentity loads the master identity for key hierarchy operations.
func loadMasterIdentity() (*keyhierarchy.MasterIdentity, *keyhierarchy.SoftwarePUF, error) {
	dir := witnessdDir()
	pufSeedPath := filepath.Join(dir, "puf_seed")

	puf, err := keyhierarchy.LoadOrCreateSoftwarePUF(pufSeedPath)
	if err != nil {
		return nil, nil, fmt.Errorf("load PUF: %w", err)
	}

	identity, err := keyhierarchy.DeriveMasterIdentity(puf)
	if err != nil {
		return nil, nil, fmt.Errorf("derive identity: %w", err)
	}

	return identity, puf, nil
}

// loadKeyHierarchyEvidence loads key hierarchy evidence for a document session.
func loadKeyHierarchyEvidence(documentPath string) *keyhierarchy.KeyHierarchyEvidence {
	dir := witnessdDir()
	absPath, err := filepath.Abs(documentPath)
	if err != nil {
		return nil
	}

	// Look for session-specific key hierarchy data
	sessionDir := filepath.Join(dir, "sessions")
	docHash := sha256.Sum256([]byte(absPath))
	sessionFile := filepath.Join(sessionDir, hex.EncodeToString(docHash[:8])+".keyhierarchy.json")

	data, err := os.ReadFile(sessionFile)
	if err != nil {
		return nil
	}

	var evidence keyhierarchy.KeyHierarchyEvidence
	if err := json.Unmarshal(data, &evidence); err != nil {
		return nil
	}

	return &evidence
}

// saveKeyHierarchyEvidence saves key hierarchy evidence for a document session.
func saveKeyHierarchyEvidence(documentPath string, evidence *keyhierarchy.KeyHierarchyEvidence) error {
	dir := witnessdDir()
	absPath, err := filepath.Abs(documentPath)
	if err != nil {
		return err
	}

	sessionDir := filepath.Join(dir, "sessions")
	if err := os.MkdirAll(sessionDir, 0700); err != nil {
		return err
	}

	docHash := sha256.Sum256([]byte(absPath))
	sessionFile := filepath.Join(sessionDir, hex.EncodeToString(docHash[:8])+".keyhierarchy.json")

	data, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(sessionFile, data, 0600)
}

// getOrCreateKeySession gets or creates a key hierarchy session for a document.
func getOrCreateKeySession(documentPath string) (*keyhierarchy.SessionManager, error) {
	_, puf, err := loadMasterIdentity()
	if err != nil {
		return nil, err
	}

	return keyhierarchy.NewSessionManager(puf, documentPath)
}

// openOrCreateWAL opens or creates a WAL for tracking a document.
func openOrCreateWAL(documentPath, sessionID string) (*wal.WAL, error) {
	dir := witnessdDir()
	walDir := filepath.Join(dir, "tracking", "wal")
	if err := os.MkdirAll(walDir, 0700); err != nil {
		return nil, fmt.Errorf("create WAL dir: %w", err)
	}

	// Generate session-specific HMAC key
	h := sha256.Sum256([]byte("witnessd-wal-hmac-" + sessionID))
	var sessionIDBytes [32]byte
	sessionIDHash := sha256.Sum256([]byte(sessionID))
	copy(sessionIDBytes[:], sessionIDHash[:])

	walPath := filepath.Join(walDir, sessionID+".wal")
	return wal.Open(walPath, sessionIDBytes, h[:])
}

// recoverFromWAL recovers tracking state from a WAL after crash.
func recoverFromWAL(walLog *wal.WAL) (*wal.RecoveryInfo, error) {
	entries, err := walLog.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("read WAL: %w", err)
	}

	recovery := &wal.RecoveryInfo{
		RecoveredAt:      time.Now(),
		EntriesRecovered: uint64(len(entries)),
	}

	// Replay entries to recover state
	for _, entry := range entries {
		switch entry.Type {
		case wal.EntryKeystrokeBatch:
			if payload, err := wal.DeserializeKeystrokeBatch(entry.Payload); err == nil {
				recovery.KeystrokesRecovered += uint64(payload.Count)
			}
		case wal.EntryJitterSample:
			recovery.SamplesRecovered++
		case wal.EntryCheckpoint:
			recovery.LastCheckpointSeq = entry.Sequence
		}

		// Verify entry integrity
		if !walLog.VerifyHMAC(&entry) {
			recovery.TamperedEntries++
		}
	}

	// Estimate data loss (max 100ms between WAL writes)
	recovery.DataLossEstimate = "< 100ms"

	return recovery, nil
}

// checkAndRecoverWAL checks for WAL files that need recovery and prompts user.
func checkAndRecoverWAL() {
	dir := witnessdDir()
	walDir := filepath.Join(dir, "tracking", "wal")

	files, err := filepath.Glob(filepath.Join(walDir, "*.wal"))
	if err != nil || len(files) == 0 {
		return
	}

	fmt.Println("=== WAL Recovery Check ===")
	fmt.Printf("Found %d WAL file(s) that may need recovery.\n", len(files))

	for _, walFile := range files {
		sessionID := strings.TrimSuffix(filepath.Base(walFile), ".wal")
		fmt.Printf("\nSession: %s\n", sessionID)

		// Open WAL and attempt recovery
		h := sha256.Sum256([]byte("witnessd-wal-hmac-" + sessionID))
		var sessionIDBytes [32]byte
		sessionIDHash := sha256.Sum256([]byte(sessionID))
	copy(sessionIDBytes[:], sessionIDHash[:])

		walLog, err := wal.Open(walFile, sessionIDBytes, h[:])
		if err != nil {
			fmt.Printf("  Error opening WAL: %v\n", err)
			continue
		}

		recovery, err := recoverFromWAL(walLog)
		walLog.Close()

		if err != nil {
			fmt.Printf("  Error recovering: %v\n", err)
			continue
		}

		fmt.Printf("  Entries: %d\n", recovery.EntriesRecovered)
		fmt.Printf("  Keystrokes: %d\n", recovery.KeystrokesRecovered)
		fmt.Printf("  Data loss estimate: %s\n", recovery.DataLossEstimate)
		if recovery.TamperedEntries > 0 {
			fmt.Printf("  WARNING: %d tampered entries detected!\n", recovery.TamperedEntries)
		}
	}
}

// Unused import guards - these ensure the imports are used
var (
	_ = context.Background
	_ = sentinel.DefaultConfig
	_ = keyhierarchy.Version
	_ = wal.Version
)
