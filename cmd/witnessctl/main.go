// witnessctl is the control CLI for witnessd.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"witnessd/internal/attestation"
	"witnessd/internal/config"
	"witnessd/internal/context"
	"witnessd/internal/forensics"
	"witnessd/internal/mmr"
	"witnessd/internal/signer"
	"witnessd/internal/store"
	"witnessd/internal/verify"
)

// Version information (set via ldflags during build)
var (
	Version   = "dev"
	BuildTime = "unknown"
	Commit    = "unknown"
)

var (
	configPath  = flag.String("config", "", "path to config file")
	noColor     = flag.Bool("no-color", false, "disable colored output")
	showVersion = flag.Bool("version", false, "show version information")
	quiet       = flag.Bool("q", false, "suppress banner")
)

// ANSI color codes
type colors struct {
	Reset   string
	Bold    string
	Dim     string
	Red     string
	Green   string
	Yellow  string
	Blue    string
	Magenta string
	Cyan    string
	White   string
}

var c colors

func initColors() {
	// Disable colors if requested, NO_COLOR env, or not a terminal
	if *noColor || os.Getenv("NO_COLOR") != "" || !isTerminal() {
		c = colors{}
		return
	}

	c = colors{
		Reset:   "\033[0m",
		Bold:    "\033[1m",
		Dim:     "\033[2m",
		Red:     "\033[31m",
		Green:   "\033[32m",
		Yellow:  "\033[33m",
		Blue:    "\033[34m",
		Magenta: "\033[35m",
		Cyan:    "\033[36m",
		White:   "\033[37m",
	}
}

func isTerminal() bool {
	if runtime.GOOS == "windows" {
		return os.Getenv("TERM") != "" || os.Getenv("WT_SESSION") != ""
	}
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// Banner with stylized logo
const banner = `
%s          ╦ ╦╦╔╦╗╔╗╔╔═╗╔═╗╔═╗%s
%s          ║║║║ ║ ║║║║╣ ╚═╗╚═╗%s
%s          ╚╩╝╩ ╩ ╝╚╝╚═╝╚═╝╚═╝%s%sctl%s
%s    ─────────────────────────────────%s
%s       Kinetic Proof of Provenance%s

`

func printBanner() {
	fmt.Fprintf(os.Stderr, banner,
		c.Cyan+c.Bold, c.Reset,
		c.Cyan+c.Bold, c.Reset,
		c.Cyan+c.Bold, c.Reset, c.Dim, c.Reset,
		c.Dim, c.Reset,
		c.Dim, c.Reset,
	)
}

func printVersion() {
	fmt.Printf("%switnessctl%s %s%s%s\n", c.Bold, c.Reset, c.Cyan, Version, c.Reset)
	fmt.Printf("  %sBuild%s       %s\n", c.Dim, c.Reset, BuildTime)
	fmt.Printf("  %sCommit%s      %s\n", c.Dim, c.Reset, Commit)
	fmt.Printf("  %sPlatform%s    %s/%s\n", c.Dim, c.Reset, runtime.GOOS, runtime.GOARCH)
	fmt.Printf("  %sGo%s          %s\n", c.Dim, c.Reset, runtime.Version())
}

func main() {
	flag.Parse()
	initColors()

	if *showVersion {
		printVersion()
		os.Exit(0)
	}

	if flag.NArg() < 1 {
		if !*quiet {
			printBanner()
		}
		usage()
		os.Exit(1)
	}

	cmd := flag.Arg(0)

	// Print banner for main commands (not for quick ones like help/version)
	if !*quiet && cmd != "help" && cmd != "version" {
		printBanner()
	}

	switch cmd {
	case "status":
		cmdStatus()
	case "history":
		cmdHistory()
	case "verify":
		if flag.NArg() < 2 {
			printError("Usage: witnessctl verify <file>")
			os.Exit(1)
		}
		cmdVerify(flag.Arg(1))
	case "export":
		if flag.NArg() < 2 {
			printError("Usage: witnessctl export <file> [output.json]")
			os.Exit(1)
		}
		output := ""
		if flag.NArg() >= 3 {
			output = flag.Arg(2)
		}
		cmdExport(flag.Arg(1), output)
	case "forensics":
		if flag.NArg() < 2 {
			printError("Usage: witnessctl forensics <file>")
			os.Exit(1)
		}
		cmdForensics(flag.Arg(1))
	case "context":
		if flag.NArg() < 2 {
			printError("Usage: witnessctl context <begin|end|status> [type] [note]")
			os.Exit(1)
		}
		cmdContext(flag.Args()[1:])
	case "attestation":
		cmdAttestation(flag.Args()[1:])
	case "help":
		if !*quiet {
			printBanner()
		}
		usage()
	case "version":
		printVersion()
	default:
		printError(fmt.Sprintf("Unknown command: %s", cmd))
		usage()
		os.Exit(1)
	}
}

func printError(msg string) {
	fmt.Fprintf(os.Stderr, "%s%s ERROR %s %s\n", c.Bold, c.Red, c.Reset, msg)
}

func printSection(title string) {
	fmt.Printf("\n%s%s %s %s\n\n", c.Bold, c.Cyan, title, c.Reset)
}

func usage() {
	fmt.Fprintf(os.Stderr, `%sUSAGE%s
    witnessctl [options] <command> [arguments]

%sCOMMANDS%s
    %sstatus%s              Show daemon status and statistics
    %shistory%s             Print witness history
    %sverify%s   <file>     Verify a file against the witness database
    %sexport%s   <file>     Export cryptographic evidence for a file
    %sforensics%s <file>    Analyze authorship patterns for a file
    %sattestation%s         Emit a filled TPM attestation template
    %scontext%s   <action>  Manage editing context declarations
        begin <type> [note]   Start context (external, assisted, review)
        end                   End current context
        status                Show active context
    %shelp%s                Show this help message
    %sversion%s             Show version information

%sOPTIONS%s
    -config <path>   Path to config file (default: ~/.witnessd/config.toml)
    -no-color        Disable colored output
    -q               Suppress banner

%sEXAMPLES%s
    witnessctl status
    witnessctl verify manuscript.docx
    witnessctl export report.pdf evidence.json
    witnessctl forensics thesis.tex
    witnessctl context begin assisted "Using AI for editing"
    witnessctl attestation -out attestation.json

%sLEARN MORE%s
    https://github.com/writerslogic/witnessd

`,
		c.Bold+c.White, c.Reset,
		c.Bold+c.White, c.Reset,
		c.Cyan, c.Reset,
		c.Cyan, c.Reset,
		c.Cyan, c.Reset,
		c.Cyan, c.Reset,
		c.Cyan, c.Reset,
		c.Cyan, c.Reset,
		c.Cyan, c.Reset,
		c.Cyan, c.Reset,
		c.Cyan, c.Reset,
		c.Bold+c.White, c.Reset,
		c.Bold+c.White, c.Reset,
		c.Bold+c.White, c.Reset,
	)
}

func loadConfig() *config.Config {
	cfg, err := config.Load(*configPath)
	if err != nil {
		printError(fmt.Sprintf("loading config: %v", err))
		os.Exit(1)
	}
	return cfg
}

func cmdAttestation(args []string) {
	fs := flag.NewFlagSet("attestation", flag.ExitOnError)
	templatePath := fs.String("template", "", "path to attestation template")
	outPath := fs.String("out", "", "output file (default stdout)")
	if err := fs.Parse(args); err != nil {
		printError(fmt.Sprintf("parsing flags: %v", err))
		os.Exit(1)
	}

	templateData := loadAttestationTemplate(*templatePath)

	var doc map[string]any
	if err := json.Unmarshal(templateData, &doc); err != nil {
		printError(fmt.Sprintf("invalid template JSON: %v", err))
		os.Exit(1)
	}

	deviceID, err := newUUID()
	if err != nil {
		printError(fmt.Sprintf("generate device id: %v", err))
		os.Exit(1)
	}
	updateAttestationExample(doc, time.Now().UTC().UnixNano(), deviceID, Version)

	output, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		printError(fmt.Sprintf("marshal output: %v", err))
		os.Exit(1)
	}

	if *outPath == "" {
		if _, err := os.Stdout.Write(append(output, '\n')); err != nil {
			printError(fmt.Sprintf("write output: %v", err))
			os.Exit(1)
		}
		return
	}

	if err := os.WriteFile(*outPath, append(output, '\n'), 0644); err != nil {
		printError(fmt.Sprintf("write output file: %v", err))
		os.Exit(1)
	}
	fmt.Printf("%sWrote attestation template to%s %s\n", c.Green, c.Reset, *outPath)
}

func loadAttestationTemplate(path string) []byte {
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			printError(fmt.Sprintf("read template: %v", err))
			os.Exit(1)
		}
		return data
	}

	if data, err := os.ReadFile("attestation.template.json"); err == nil {
		return data
	}

	return attestation.Template()
}

func updateAttestationExample(doc map[string]any, timestampNs int64, deviceID, version string) {
	example, ok := doc["example_output"].(map[string]any)
	if !ok {
		example = map[string]any{}
		doc["example_output"] = example
	}

	att, ok := example["attestation"].(map[string]any)
	if !ok {
		att = map[string]any{}
		example["attestation"] = att
	}

	meta, ok := att["metadata"].(map[string]any)
	if !ok {
		meta = map[string]any{}
		att["metadata"] = meta
	}

	meta["timestamp_ns"] = timestampNs
	meta["device_id"] = deviceID
	if version != "" {
		meta["witnessd_version"] = version
	}
}

func newUUID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
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
	dir := config.WitnessdDir()
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

func cmdStatus() {
	cfg := loadConfig()
	dir := config.WitnessdDir()

	// Tracking daemon status (for keystroke tracking, not file watching)
	printSection("TRACKING")

	trackingDir := filepath.Join(dir, "tracking")
	pidPath := filepath.Join(trackingDir, "daemon.pid")
	currentSession := filepath.Join(trackingDir, "current_session.json")

	if _, err := os.Stat(currentSession); err == nil {
		// Check if tracking daemon is running
		if pidData, err := os.ReadFile(pidPath); err == nil {
			pid, _ := strconv.Atoi(strings.TrimSpace(string(pidData)))
			if processExists(pid) {
				fmt.Printf("  %sStatus%s        %s%sACTIVE%s (PID %d)\n", c.Dim, c.Reset, c.Bold, c.Green, c.Reset, pid)
			} else {
				fmt.Printf("  %sStatus%s        %s%sPAUSED%s (daemon stopped, session preserved)\n", c.Dim, c.Reset, c.Bold, c.Yellow, c.Reset)
			}
		} else {
			fmt.Printf("  %sStatus%s        %s%sPAUSED%s\n", c.Dim, c.Reset, c.Bold, c.Yellow, c.Reset)
		}

		// Show session info
		if data, err := os.ReadFile(currentSession); err == nil {
			var info map[string]interface{}
			json.Unmarshal(data, &info)
			if id, ok := info["id"].(string); ok {
				fmt.Printf("  %sSession%s       %s\n", c.Dim, c.Reset, id)
			}
			if doc, ok := info["document"].(string); ok {
				fmt.Printf("  %sDocument%s      %s\n", c.Dim, c.Reset, filepath.Base(doc))
			}
		}
	} else {
		fmt.Printf("  %sStatus%s        %sNo active session%s\n", c.Dim, c.Reset, c.Dim, c.Reset)
		fmt.Printf("  %sTip%s           Start with: witnessd track start <file>\n", c.Dim, c.Reset)
	}

	// Secure Database (primary store)
	printSection("SECURE DATABASE")

	secureDB, err := openSecureStore()
	if err != nil {
		if os.IsNotExist(err) || strings.Contains(err.Error(), "read signing key") {
			fmt.Printf("  %sStatus%s        %s%sNOT INITIALIZED%s\n", c.Dim, c.Reset, c.Bold, c.Yellow, c.Reset)
			fmt.Printf("  %sTip%s           Run: witnessd init\n", c.Dim, c.Reset)
		} else if strings.Contains(err.Error(), "integrity") {
			fmt.Printf("  %sStatus%s        %s%sTAMPERED%s\n", c.Dim, c.Reset, c.Bold, c.Red, c.Reset)
			fmt.Printf("  %sError%s         %v\n", c.Red, c.Reset, err)
		} else {
			fmt.Printf("  %sStatus%s        %s%sERROR%s\n", c.Dim, c.Reset, c.Bold, c.Red, c.Reset)
			fmt.Printf("  %sError%s         %v\n", c.Red, c.Reset, err)
		}
	} else {
		defer secureDB.Close()

		stats, err := secureDB.GetStats()
		if err != nil {
			fmt.Printf("  %sError:%s %v\n", c.Red, c.Reset, err)
		} else {
			if stats.IntegrityOK {
				fmt.Printf("  %sIntegrity%s     %s%sVERIFIED%s (tamper-evident)\n", c.Dim, c.Reset, c.Bold, c.Green, c.Reset)
			} else {
				fmt.Printf("  %sIntegrity%s     %s%sFAILED%s (possible tampering)\n", c.Dim, c.Reset, c.Bold, c.Red, c.Reset)
			}
			fmt.Printf("  %sEvents%s        %s%d%s\n", c.Dim, c.Reset, c.Bold+c.White, stats.EventCount, c.Reset)
			fmt.Printf("  %sFiles%s         %d\n", c.Dim, c.Reset, stats.FileCount)

			if stats.EventCount > 0 {
				fmt.Printf("  %sFirst event%s   %s\n", c.Dim, c.Reset, stats.OldestEvent.Format("2006-01-02 15:04"))
				fmt.Printf("  %sLast event%s    %s\n", c.Dim, c.Reset, stats.NewestEvent.Format("2006-01-02 15:04"))
			}

			if len(stats.ChainHash) >= 16 {
				fmt.Printf("  %sChain hash%s    %s%s%s...\n", c.Dim, c.Reset, c.Cyan, stats.ChainHash[:16], c.Reset)
			}

			// Show database file size
			dbPath := filepath.Join(dir, "events.db")
			if info, err := os.Stat(dbPath); err == nil {
				fmt.Printf("  %sSize%s          %s\n", c.Dim, c.Reset, formatBytes(info.Size()))
			}
		}
	}

	// Legacy MMR Database (if exists)
	if _, err := os.Stat(cfg.DatabasePath()); err == nil {
		printSection("LEGACY DATABASE")

		mmrStore, err := mmr.OpenFileStore(cfg.DatabasePath())
		if err != nil {
			fmt.Printf("  %sError:%s %v\n", c.Red, c.Reset, err)
		} else {
			defer mmrStore.Close()
			m, err := mmr.New(mmrStore)
			if err != nil {
				fmt.Printf("  %sError:%s %v\n", c.Red, c.Reset, err)
			} else {
				fmt.Printf("  %sNodes%s         %d\n", c.Dim, c.Reset, m.Size())
				fmt.Printf("  %sWitnesses%s     %d\n", c.Dim, c.Reset, m.LeafCount())
				fmt.Printf("  %sNote%s          %sLegacy format - use 'witnessd commit' for new events%s\n", c.Dim, c.Reset, c.Dim, c.Reset)
			}
		}
	}

	// Signing key
	printSection("SIGNING KEY")

	keyPath := filepath.Join(dir, "signing_key")
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		// Also check old location
		if _, err := os.Stat(cfg.SigningKeyPath()); os.IsNotExist(err) {
			fmt.Printf("  %sStatus%s        %s%sNOT FOUND%s\n", c.Dim, c.Reset, c.Bold, c.Yellow, c.Reset)
		} else {
			pubKeyPath := cfg.SigningKeyPath() + ".pub"
			if pubKey, err := signer.LoadPublicKey(pubKeyPath); err == nil {
				fmt.Printf("  %sPublic Key%s    %s%s%s...\n", c.Dim, c.Reset, c.Cyan, hex.EncodeToString(pubKey[:8]), c.Reset)
			}
			fmt.Printf("  %sPath%s          %s\n", c.Dim, c.Reset, cfg.SigningKeyPath())
		}
	} else {
		pubKeyPath := keyPath + ".pub"
		if pubKey, err := os.ReadFile(pubKeyPath); err == nil && len(pubKey) >= 8 {
			fmt.Printf("  %sPublic Key%s    %s%s%s...\n", c.Dim, c.Reset, c.Cyan, hex.EncodeToString(pubKey[:8]), c.Reset)
		}
		fmt.Printf("  %sPath%s          %s\n", c.Dim, c.Reset, keyPath)
	}

	// JSON chains count
	chainsDir := filepath.Join(dir, "chains")
	if chains, _ := filepath.Glob(filepath.Join(chainsDir, "*.json")); len(chains) > 0 {
		printSection("CHECKPOINT CHAINS")
		fmt.Printf("  %sChains%s        %d JSON files\n", c.Dim, c.Reset, len(chains))
	}

	fmt.Println()
}

func cmdHistory() {
	cfg := loadConfig()

	mmrStore, err := mmr.OpenFileStore(cfg.DatabasePath())
	if err != nil {
		printError(fmt.Sprintf("opening database: %v", err))
		os.Exit(1)
	}
	defer mmrStore.Close()

	m, err := mmr.New(mmrStore)
	if err != nil {
		printError(fmt.Sprintf("reading MMR: %v", err))
		os.Exit(1)
	}

	if m.Size() == 0 {
		fmt.Printf("  %sNo witness events recorded.%s\n", c.Dim, c.Reset)
		return
	}

	signaturesPath := filepath.Join(config.PlatformDataDir(), "signatures.log")
	sigEntries := loadSignatureEntries(signaturesPath)

	printSection("WITNESS HISTORY")

	fmt.Printf("  %s%-8s  %-24s  %-24s%s\n", c.Dim, "INDEX", "HASH", "SIGNED ROOT", c.Reset)
	fmt.Printf("  %s%s%s\n", c.Dim, strings.Repeat("─", 60), c.Reset)

	count := 0
	for i := uint64(0); i < m.Size() && count < 100; i++ {
		node, err := m.Get(i)
		if err != nil {
			continue
		}
		if node.Height != 0 {
			continue
		}

		hashStr := hex.EncodeToString(node.Hash[:12]) + "..."

		var sigInfo string
		for s := len(sigEntries) - 1; s >= 0; s-- {
			entry := sigEntries[s]
			if entry.Size > i {
				sigInfo = hex.EncodeToString(entry.Root[:12]) + "..."
				break
			}
		}

		if sigInfo != "" {
			fmt.Printf("  %-8d  %s%s%s  %s%s%s\n", i, c.Cyan, hashStr, c.Reset, c.Green, sigInfo, c.Reset)
		} else {
			fmt.Printf("  %-8d  %s%s%s  %s—%s\n", i, c.Cyan, hashStr, c.Reset, c.Dim, c.Reset)
		}
		count++
	}

	if count >= 100 {
		fmt.Printf("\n  %s(showing first 100 of %d witnesses)%s\n", c.Dim, m.LeafCount(), c.Reset)
	}
	fmt.Println()
}

func cmdVerify(filePath string) {
	cfg := loadConfig()

	pubKeyPath := cfg.SigningKeyPath() + ".pub"
	signaturesPath := filepath.Join(config.PlatformDataDir(), "signatures.log")

	v, err := verify.NewVerifier(cfg.DatabasePath(), pubKeyPath, signaturesPath)
	if err != nil {
		printError(fmt.Sprintf("initializing verifier: %v", err))
		os.Exit(1)
	}
	defer v.Close()

	result, err := v.VerifyFile(filePath)
	if err != nil {
		fmt.Printf("\n%s%s VERIFICATION FAILED %s\n\n", c.Bold, c.Red, c.Reset)
		fmt.Printf("  %sError%s  %v\n\n", c.Red, c.Reset, err)
		os.Exit(1)
	}

	if result.Valid {
		fmt.Printf("\n%s%s VERIFICATION PASSED %s\n\n", c.Bold, c.Green, c.Reset)
	} else {
		fmt.Printf("\n%s%s VERIFICATION FAILED %s\n\n", c.Bold, c.Red, c.Reset)
	}

	fmt.Printf("  %sFile%s           %s\n", c.Dim, c.Reset, result.Path)
	fmt.Printf("  %sCurrent Hash%s   %s%s%s\n", c.Dim, c.Reset, c.Cyan, result.CurrentHash, c.Reset)
	fmt.Printf("  %sWitnessed%s      %s%s%s\n", c.Dim, c.Reset, c.Cyan, result.WitnessedHash, c.Reset)
	fmt.Printf("  %sMMR Index%s      %d\n", c.Dim, c.Reset, result.MMRIndex)
	fmt.Printf("  %sMMR Root%s       %s%s%s\n", c.Dim, c.Reset, c.Cyan, result.MMRRoot, c.Reset)

	fmt.Println()

	if result.Valid {
		fmt.Printf("  %s✓%s This file has been cryptographically witnessed.\n\n", c.Green, c.Reset)
	} else {
		fmt.Printf("  %s✗%s %s\n\n", c.Red, c.Reset, result.Error)
		os.Exit(1)
	}
}

func cmdExport(filePath, outputPath string) {
	cfg := loadConfig()

	pubKeyPath := cfg.SigningKeyPath() + ".pub"
	signaturesPath := filepath.Join(config.PlatformDataDir(), "signatures.log")

	v, err := verify.NewVerifier(cfg.DatabasePath(), pubKeyPath, signaturesPath)
	if err != nil {
		printError(fmt.Sprintf("initializing verifier: %v", err))
		os.Exit(1)
	}
	defer v.Close()

	packet, err := v.ExportEvidence(filePath)
	if err != nil {
		printError(fmt.Sprintf("exporting evidence: %v", err))
		os.Exit(1)
	}

	if outputPath == "" {
		base := filepath.Base(filePath)
		outputPath = base + ".evidence.json"
	}

	if err := verify.SaveEvidence(packet, outputPath); err != nil {
		printError(fmt.Sprintf("saving evidence: %v", err))
		os.Exit(1)
	}

	fmt.Printf("\n%s%s EVIDENCE EXPORTED %s\n\n", c.Bold, c.Green, c.Reset)
	fmt.Printf("  %sOutput%s         %s%s%s\n", c.Dim, c.Reset, c.Bold+c.White, outputPath, c.Reset)
	fmt.Printf("  %sFile%s           %s\n", c.Dim, c.Reset, packet.FilePath)
	fmt.Printf("  %sHash%s           %s%s%s\n", c.Dim, c.Reset, c.Cyan, packet.FileHash, c.Reset)
	fmt.Printf("  %sMMR Index%s      %d of %d\n", c.Dim, c.Reset, packet.MMRIndex, packet.MMRSize)
	fmt.Printf("  %sRoot%s           %s%s%s\n", c.Dim, c.Reset, c.Cyan, packet.MMRRoot, c.Reset)
	if packet.Signature != "" {
		fmt.Printf("  %sSignature%s      %s%s%s...\n", c.Dim, c.Reset, c.Green, packet.Signature[:32], c.Reset)
	}
	fmt.Println()
}

func cmdForensics(filePath string) {
	cfg := loadConfig()

	eventStore, err := store.Open(cfg.DatabasePath())
	if err != nil {
		printError(fmt.Sprintf("opening event store: %v", err))
		os.Exit(1)
	}
	defer eventStore.Close()

	events, err := eventStore.GetEventsByFile(filePath, 0, time.Now().UnixNano())
	if err != nil {
		printError(fmt.Sprintf("loading events: %v", err))
		os.Exit(1)
	}

	if len(events) == 0 {
		fmt.Printf("  %sNo witness events found for: %s%s\n", c.Yellow, filePath, c.Reset)
		os.Exit(1)
	}

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

	profile, err := forensics.BuildProfile(eventData, regionsByEvent)
	if err != nil {
		printError(fmt.Sprintf("building profile: %v", err))
		os.Exit(1)
	}

	printSection("FORENSIC ANALYSIS")
	forensics.PrintReport(os.Stdout, profile)
}

func cmdContext(args []string) {
	if len(args) == 0 {
		printError("Usage: witnessctl context <begin|end|status> [type] [note]")
		os.Exit(1)
	}

	cfg := loadConfig()

	eventStore, err := store.Open(cfg.DatabasePath())
	if err != nil {
		printError(fmt.Sprintf("opening event store: %v", err))
		os.Exit(1)
	}
	defer eventStore.Close()

	ctxMgr := context.NewManager(eventStore)

	switch args[0] {
	case "begin":
		if len(args) < 2 {
			printError("Usage: witnessctl context begin <type> [note]")
			fmt.Fprintf(os.Stderr, "  %sTypes:%s external (ext), assisted (ai), review (rev)\n", c.Dim, c.Reset)
			os.Exit(1)
		}

		ctxType, err := context.ValidateType(args[1])
		if err != nil {
			printError(fmt.Sprintf("Invalid context type: %s", args[1]))
			fmt.Fprintf(os.Stderr, "  %sValid types:%s external (ext), assisted (ai), review (rev)\n", c.Dim, c.Reset)
			os.Exit(1)
		}

		note := ""
		if len(args) >= 3 {
			note = strings.Join(args[2:], " ")
		}

		id, err := ctxMgr.Begin(ctxType, note)
		if err != nil {
			printError(fmt.Sprintf("starting context: %v", err))
			os.Exit(1)
		}

		fmt.Printf("\n%s%s CONTEXT STARTED %s\n\n", c.Bold, c.Green, c.Reset)
		fmt.Printf("  %sType%s           %s\n", c.Dim, c.Reset, context.TypeDescription(ctxType))
		if note != "" {
			fmt.Printf("  %sNote%s           %s\n", c.Dim, c.Reset, note)
		}
		fmt.Printf("  %sID%s             %d\n", c.Dim, c.Reset, id)
		fmt.Println()

	case "end":
		err := ctxMgr.End()
		if err != nil {
			if err == context.ErrNoActiveContext {
				fmt.Printf("  %sNo active context to end.%s\n", c.Dim, c.Reset)
			} else {
				printError(fmt.Sprintf("ending context: %v", err))
				os.Exit(1)
			}
			return
		}
		fmt.Printf("  %s✓%s Context ended.\n", c.Green, c.Reset)

	case "status":
		active, err := ctxMgr.Active()
		if err != nil {
			printError(fmt.Sprintf("checking context: %v", err))
			os.Exit(1)
		}

		if active == nil {
			fmt.Printf("  %sNo active context.%s\n", c.Dim, c.Reset)
		} else {
			printSection("ACTIVE CONTEXT")
			fmt.Printf("  %sType%s           %s\n", c.Dim, c.Reset, context.TypeDescription(active.Type))
			fmt.Printf("  %sStarted%s        %s\n", c.Dim, c.Reset, time.Unix(0, active.StartNs).Format(time.RFC3339))
			if active.Note != "" {
				fmt.Printf("  %sNote%s           %s\n", c.Dim, c.Reset, active.Note)
			}
			fmt.Println()
		}

	default:
		printError(fmt.Sprintf("Unknown context action: %s", args[0]))
		fmt.Fprintf(os.Stderr, "  %sValid actions:%s begin, end, status\n", c.Dim, c.Reset)
		os.Exit(1)
	}
}

// Helper functions

func processExists(pid int) bool {
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return signalProcess(process)
}

func signalProcess(p *os.Process) bool {
	return p.Signal(syscall.Signal(0)) == nil
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

func prettyJSON(v interface{}) string {
	data, _ := json.MarshalIndent(v, "", "  ")
	return string(data)
}
