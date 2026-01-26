// witnessctl is the control CLI for witnessd.
package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"witnessd/internal/config"
	"witnessd/internal/context"
	"witnessd/internal/forensics"
	"witnessd/internal/mmr"
	"witnessd/internal/signer"
	"witnessd/internal/store"
	"witnessd/internal/verify"
)

var (
	configPath = flag.String("config", "", "path to config file")
)

func main() {
	flag.Parse()

	if flag.NArg() < 1 {
		usage()
		os.Exit(1)
	}

	cmd := flag.Arg(0)

	switch cmd {
	case "status":
		cmdStatus()
	case "history":
		cmdHistory()
	case "verify":
		if flag.NArg() < 2 {
			fmt.Fprintln(os.Stderr, "Usage: witnessctl verify <file>")
			os.Exit(1)
		}
		cmdVerify(flag.Arg(1))
	case "export":
		if flag.NArg() < 2 {
			fmt.Fprintln(os.Stderr, "Usage: witnessctl export <file> [output.json]")
			os.Exit(1)
		}
		output := ""
		if flag.NArg() >= 3 {
			output = flag.Arg(2)
		}
		cmdExport(flag.Arg(1), output)
	case "forensics":
		if flag.NArg() < 2 {
			fmt.Fprintln(os.Stderr, "Usage: witnessctl forensics <file>")
			os.Exit(1)
		}
		cmdForensics(flag.Arg(1))
	case "context":
		if flag.NArg() < 2 {
			fmt.Fprintln(os.Stderr, "Usage: witnessctl context <begin|end|status> [type] [note]")
			os.Exit(1)
		}
		cmdContext(flag.Args()[1:])
	case "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", cmd)
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `witnessctl - Control utility for witnessd

Usage: witnessctl [options] <command> [args]

Commands:
  status              Show daemon status and statistics
  history             Print witness history
  verify <file>       Verify a file against the witness database
  export <file>       Export cryptographic evidence for a file
  forensics <file>    Analyze authorship patterns for a file
  context <action>    Manage editing context declarations
    begin <type> [note]  Start context (types: external, assisted, review)
    end                  End current context
    status               Show active context
  help                Show this help message

Options:
  -config <path>  Path to config file (default: ~/.witnessd/config.toml)`)
}

func loadConfig() *config.Config {
	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}
	return cfg
}

func cmdStatus() {
	cfg := loadConfig()

	fmt.Println("=== witnessd Status ===")
	fmt.Println()

	// Check if daemon is running
	pidPath := filepath.Join(config.WitnessdDir(), "witnessd.pid")
	pidData, err := os.ReadFile(pidPath)
	if err != nil {
		fmt.Println("Daemon Status: NOT RUNNING")
	} else {
		pid, _ := strconv.Atoi(strings.TrimSpace(string(pidData)))
		// Check if process exists
		if processExists(pid) {
			fmt.Printf("Daemon Status: RUNNING (PID %d)\n", pid)
		} else {
			fmt.Printf("Daemon Status: STALE PID FILE (PID %d not found)\n", pid)
		}
	}
	fmt.Println()

	// MMR statistics
	fmt.Println("Database:")
	if _, err := os.Stat(cfg.DatabasePath); os.IsNotExist(err) {
		fmt.Println("  No database found")
	} else {
		store, err := mmr.OpenFileStore(cfg.DatabasePath)
		if err != nil {
			fmt.Printf("  Error opening database: %v\n", err)
		} else {
			defer store.Close()
			m, err := mmr.New(store)
			if err != nil {
				fmt.Printf("  Error reading MMR: %v\n", err)
			} else {
				fmt.Printf("  Total nodes: %d\n", m.Size())
				fmt.Printf("  Total leaves (witnesses): %d\n", m.LeafCount())

				if m.Size() > 0 {
					root, err := m.GetRoot()
					if err == nil {
						fmt.Printf("  Current root: %s\n", hex.EncodeToString(root[:16])+"...")
					}
				}

				// File size
				info, _ := os.Stat(cfg.DatabasePath)
				if info != nil {
					fmt.Printf("  Database size: %s\n", formatBytes(info.Size()))
				}
			}
		}
	}
	fmt.Println()

	// Watch paths
	fmt.Println("Watch Paths:")
	if len(cfg.WatchPaths) == 0 {
		fmt.Println("  (none configured)")
	} else {
		for _, p := range cfg.WatchPaths {
			fmt.Printf("  - %s\n", p)
		}
	}
	fmt.Println()

	// Signing key
	fmt.Println("Signing Key:")
	if _, err := os.Stat(cfg.SigningKeyPath); os.IsNotExist(err) {
		fmt.Printf("  NOT FOUND: %s\n", cfg.SigningKeyPath)
	} else {
		pubKeyPath := cfg.SigningKeyPath + ".pub"
		if pubKey, err := signer.LoadPublicKey(pubKeyPath); err == nil {
			fmt.Printf("  Public key: %s...\n", hex.EncodeToString(pubKey[:8]))
		}
		fmt.Printf("  Path: %s\n", cfg.SigningKeyPath)
	}
}

func cmdHistory() {
	cfg := loadConfig()

	store, err := mmr.OpenFileStore(cfg.DatabasePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening database: %v\n", err)
		os.Exit(1)
	}
	defer store.Close()

	m, err := mmr.New(store)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading MMR: %v\n", err)
		os.Exit(1)
	}

	if m.Size() == 0 {
		fmt.Println("No witness events recorded.")
		return
	}

	// Load signature entries for timestamps
	sigEntries := loadSignatureEntries(cfg.SignaturesPath)

	fmt.Println("=== Witness History ===")
	fmt.Printf("%-8s %-16s %-20s\n", "Index", "Hash", "Root (if signed)")
	fmt.Println(strings.Repeat("-", 50))

	// Print leaves only (height 0)
	count := 0
	for i := uint64(0); i < m.Size() && count < 100; i++ {
		node, err := m.Get(i)
		if err != nil {
			continue
		}
		if node.Height != 0 {
			continue
		}

		hashStr := hex.EncodeToString(node.Hash[:8]) + "..."

		// Check if any signature covers this index
		var sigInfo string
		for _, entry := range sigEntries {
			if entry.Size > i {
				sigInfo = hex.EncodeToString(entry.Root[:8]) + "..."
				break
			}
		}

		fmt.Printf("%-8d %-16s %-20s\n", i, hashStr, sigInfo)
		count++
	}

	if count >= 100 {
		fmt.Printf("\n(showing first 100 of %d leaves)\n", m.LeafCount())
	}
}

func cmdVerify(filePath string) {
	cfg := loadConfig()

	pubKeyPath := cfg.SigningKeyPath + ".pub"

	v, err := verify.NewVerifier(cfg.DatabasePath, pubKeyPath, cfg.SignaturesPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing verifier: %v\n", err)
		os.Exit(1)
	}
	defer v.Close()

	result, err := v.VerifyFile(filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Verification FAILED: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("=== Verification Result ===")
	fmt.Printf("File:           %s\n", result.Path)
	fmt.Printf("Current Hash:   %s\n", result.CurrentHash)
	fmt.Printf("Witnessed Hash: %s\n", result.WitnessedHash)
	fmt.Printf("MMR Index:      %d\n", result.MMRIndex)
	fmt.Printf("MMR Root:       %s\n", result.MMRRoot)

	if result.Valid {
		fmt.Println("\n✓ Verification PASSED")
		fmt.Println("  This file has been cryptographically witnessed.")
	} else {
		fmt.Println("\n✗ Verification FAILED")
		fmt.Printf("  Error: %s\n", result.Error)
		os.Exit(1)
	}
}

func cmdExport(filePath, outputPath string) {
	cfg := loadConfig()

	pubKeyPath := cfg.SigningKeyPath + ".pub"

	v, err := verify.NewVerifier(cfg.DatabasePath, pubKeyPath, cfg.SignaturesPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing verifier: %v\n", err)
		os.Exit(1)
	}
	defer v.Close()

	packet, err := v.ExportEvidence(filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error exporting evidence: %v\n", err)
		os.Exit(1)
	}

	// Generate output path if not provided
	if outputPath == "" {
		base := filepath.Base(filePath)
		outputPath = base + ".evidence.json"
	}

	if err := verify.SaveEvidence(packet, outputPath); err != nil {
		fmt.Fprintf(os.Stderr, "Error saving evidence: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Evidence exported to: %s\n", outputPath)
	fmt.Println()
	fmt.Println("Evidence Summary:")
	fmt.Printf("  File: %s\n", packet.FilePath)
	fmt.Printf("  Hash: %s\n", packet.FileHash)
	fmt.Printf("  MMR Index: %d (of %d)\n", packet.MMRIndex, packet.MMRSize)
	fmt.Printf("  Root: %s\n", packet.MMRRoot)
	if packet.Signature != "" {
		fmt.Printf("  Signature: %s...\n", packet.Signature[:32])
	}
}

// Helper functions

func processExists(pid int) bool {
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	// On Unix, FindProcess always succeeds, we need to send signal 0
	err = process.Signal(os.Signal(nil))
	return err == nil
}

func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

func loadSignatureEntries(path string) []SignatureEntry {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	var entries []SignatureEntry
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}

		var timestamp, rootHex, sigHex string
		var size uint64
		n, err := fmt.Sscanf(line, "%s %s %s %d", &timestamp, &rootHex, &sigHex, &size)
		if err != nil || n != 4 {
			continue
		}

		ts, err := time.Parse(time.RFC3339, timestamp)
		if err != nil {
			continue
		}

		rootBytes, err := hex.DecodeString(rootHex)
		if err != nil || len(rootBytes) != 32 {
			continue
		}

		var root [32]byte
		copy(root[:], rootBytes)

		entries = append(entries, SignatureEntry{
			Timestamp: ts,
			Root:      root,
			Size:      size,
		})
	}

	return entries
}

// SignatureEntry represents a signed root.
type SignatureEntry struct {
	Timestamp time.Time
	Root      [32]byte
	Size      uint64
}

// Pretty print JSON for debugging
func prettyJSON(v interface{}) string {
	data, _ := json.MarshalIndent(v, "", "  ")
	return string(data)
}

func cmdForensics(filePath string) {
	cfg := loadConfig()

	// Open event store
	eventStore, err := store.Open(cfg.EventStorePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening event store: %v\n", err)
		os.Exit(1)
	}
	defer eventStore.Close()

	// Get all events for this file
	events, err := eventStore.GetEventsByFile(filePath, 0, time.Now().UnixNano())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading events: %v\n", err)
		os.Exit(1)
	}

	if len(events) == 0 {
		fmt.Fprintf(os.Stderr, "No witness events found for: %s\n", filePath)
		os.Exit(1)
	}

	// Convert to forensics types and load regions
	eventData := make([]forensics.EventData, len(events))
	regionsByEvent := make(map[int64][]forensics.RegionData)

	for i, e := range events {
		eventData[i] = forensics.EventData{
			ID:          e.ID,
			TimestampNs: e.TimestampNs,
			FileSize:    e.FileSize,
			SizeDelta:   e.SizeDelta,
			FilePath:    e.FilePath,
		}

		// Load edit regions for this event
		regions, err := eventStore.GetEditRegions(e.ID)
		if err == nil && len(regions) > 0 {
			regData := make([]forensics.RegionData, len(regions))
			for j, r := range regions {
				regData[j] = forensics.RegionData{
					StartPct:  r.StartPct,
					EndPct:    r.EndPct,
					DeltaSign: r.DeltaSign,
					ByteCount: r.ByteCount,
				}
			}
			regionsByEvent[e.ID] = regData
		}
	}

	// Build profile
	profile, err := forensics.BuildProfile(eventData, regionsByEvent)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error building profile: %v\n", err)
		os.Exit(1)
	}

	// Print report
	forensics.PrintReport(os.Stdout, profile)
}

func cmdContext(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: witnessctl context <begin|end|status> [type] [note]")
		os.Exit(1)
	}

	cfg := loadConfig()

	eventStore, err := store.Open(cfg.EventStorePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening event store: %v\n", err)
		os.Exit(1)
	}
	defer eventStore.Close()

	ctxMgr := context.NewManager(eventStore)

	switch args[0] {
	case "begin":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "Usage: witnessctl context begin <type> [note]")
			fmt.Fprintln(os.Stderr, "Types: external (ext), assisted (ai), review (rev)")
			os.Exit(1)
		}

		ctxType, err := context.ValidateType(args[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid context type: %s\n", args[1])
			fmt.Fprintln(os.Stderr, "Valid types: external (ext), assisted (ai), review (rev)")
			os.Exit(1)
		}

		note := ""
		if len(args) >= 3 {
			note = strings.Join(args[2:], " ")
		}

		id, err := ctxMgr.Begin(ctxType, note)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error starting context: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("Context started: %s\n", context.TypeDescription(ctxType))
		if note != "" {
			fmt.Printf("Note: %s\n", note)
		}
		fmt.Printf("ID: %d\n", id)

	case "end":
		err := ctxMgr.End()
		if err != nil {
			if err == context.ErrNoActiveContext {
				fmt.Println("No active context to end.")
			} else {
				fmt.Fprintf(os.Stderr, "Error ending context: %v\n", err)
				os.Exit(1)
			}
			return
		}
		fmt.Println("Context ended.")

	case "status":
		active, err := ctxMgr.Active()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error checking context: %v\n", err)
			os.Exit(1)
		}

		if active == nil {
			fmt.Println("No active context.")
		} else {
			fmt.Println("Active context:")
			fmt.Printf("  Type: %s\n", context.TypeDescription(active.Type))
			fmt.Printf("  Started: %s\n", time.Unix(0, active.StartNs).Format(time.RFC3339))
			if active.Note != "" {
				fmt.Printf("  Note: %s\n", active.Note)
			}
		}

	default:
		fmt.Fprintf(os.Stderr, "Unknown context action: %s\n", args[0])
		fmt.Fprintln(os.Stderr, "Valid actions: begin, end, status")
		os.Exit(1)
	}
}
