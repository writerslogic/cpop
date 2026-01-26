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
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"witnessd/internal/checkpoint"
	"witnessd/internal/declaration"
	"witnessd/internal/evidence"
	"witnessd/internal/presence"
	"witnessd/internal/tpm"
	"witnessd/internal/vdf"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
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
	case "calibrate":
		cmdCalibrate()
	case "status":
		cmdStatus()
	case "daemon":
		cmdDaemon()
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", cmd)
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Println(`witnessd - Cryptographic Authorship Witnessing

USAGE:
    witnessd <command> [options]

COMMANDS:
    init                Initialize witnessd in current directory
    commit <file>       Create a checkpoint for a file
    log <file>          Show checkpoint history for a file
    export <file>       Export evidence packet with declaration
    verify <file>       Verify checkpoint chain integrity
    presence <action>   Manage presence verification sessions
    calibrate           Calibrate VDF performance for this machine
    status              Show witnessd status and configuration
    daemon              (Legacy) Run background monitoring daemon
    help                Show this help message

WORKFLOW:
    1. witnessd init                    # One-time setup
    2. (write your document)
    3. witnessd commit doc.md -m "..."  # Checkpoint when ready
    4. (continue writing)
    5. witnessd commit doc.md -m "..."  # More checkpoints
    6. witnessd export doc.md           # Export evidence when done

The system proves:
    - Content states form an unbroken chain
    - Minimum time elapsed between commits (VDF)
    - Your signed declaration of creative process

See https://github.com/davidcondrey/witnessd for documentation.`)
}

func witnessdDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".witnessd")
}

func cmdInit() {
	dir := witnessdDir()

	// Create directory structure
	dirs := []string{
		dir,
		filepath.Join(dir, "chains"),
		filepath.Join(dir, "sessions"),
	}

	for _, d := range dirs {
		if err := os.MkdirAll(d, 0700); err != nil {
			fmt.Fprintf(os.Stderr, "Error creating directory %s: %v\n", d, err)
			os.Exit(1)
		}
	}

	// Create default config if not exists
	configPath := filepath.Join(dir, "config.json")
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		cfg := map[string]interface{}{
			"version": 2,
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
		}

		data, _ := json.MarshalIndent(cfg, "", "  ")
		if err := os.WriteFile(configPath, data, 0600); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing config: %v\n", err)
			os.Exit(1)
		}
	}

	// Generate signing key if not exists
	keyPath := filepath.Join(dir, "signing_key")
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		fmt.Println("Generating Ed25519 signing key...")
		pub, priv, err := ed25519.GenerateKey(nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error generating key: %v\n", err)
			os.Exit(1)
		}

		if err := os.WriteFile(keyPath, priv, 0600); err != nil {
			fmt.Fprintf(os.Stderr, "Error saving private key: %v\n", err)
			os.Exit(1)
		}

		if err := os.WriteFile(keyPath+".pub", pub, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Error saving public key: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("  Public key: %s\n", hex.EncodeToString(pub[:8])+"...")
	}

	fmt.Println()
	fmt.Println("witnessd initialized!")
	fmt.Println()
	fmt.Println("Next steps:")
	fmt.Println("  1. Run 'witnessd calibrate' to calibrate VDF for your machine")
	fmt.Println("  2. Create checkpoints with 'witnessd commit <file> -m \"message\"'")
	fmt.Println("  3. Export evidence with 'witnessd export <file>'")
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
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "File not found: %s\n", filePath)
		os.Exit(1)
	}

	// Load VDF parameters
	vdfParams := loadVDFParams()

	// Get or create chain
	chain, err := checkpoint.GetOrCreateChain(filePath, witnessdDir(), vdfParams)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading chain: %v\n", err)
		os.Exit(1)
	}

	// Commit
	fmt.Printf("Computing checkpoint...")
	start := time.Now()
	cp, err := chain.Commit(*message)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\nError creating checkpoint: %v\n", err)
		os.Exit(1)
	}
	elapsed := time.Since(start)

	// Save chain
	if err := chain.Save(chain.StoragePath()); err != nil {
		fmt.Fprintf(os.Stderr, "Error saving chain: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf(" done (%s)\n", elapsed.Round(time.Millisecond))
	fmt.Println()
	fmt.Printf("Checkpoint #%d created\n", cp.Ordinal)
	fmt.Printf("  Content hash: %s\n", hex.EncodeToString(cp.ContentHash[:8])+"...")
	fmt.Printf("  Chain hash:   %s\n", hex.EncodeToString(cp.Hash[:8])+"...")
	if cp.VDF != nil {
		fmt.Printf("  VDF proves:   >= %s elapsed\n", cp.VDF.MinElapsedTime(vdfParams).Round(time.Second))
	}
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

	// Find chain
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

	fmt.Printf("=== Checkpoint History: %s ===\n", filepath.Base(filePath))
	fmt.Printf("Document: %s\n", chain.DocumentPath)
	fmt.Printf("Checkpoints: %d\n", len(chain.Checkpoints))
	fmt.Printf("Total elapsed: %s\n", chain.TotalElapsedTime().Round(time.Second))
	fmt.Println()

	for _, cp := range chain.Checkpoints {
		fmt.Printf("[%d] %s\n", cp.Ordinal, cp.Timestamp.Format("2006-01-02 15:04:05"))
		fmt.Printf("    Hash: %s\n", hex.EncodeToString(cp.ContentHash[:]))
		fmt.Printf("    Size: %d bytes\n", cp.ContentSize)
		if cp.VDF != nil {
			fmt.Printf("    VDF:  >= %s\n", cp.VDF.MinElapsedTime(chain.VDFParams).Round(time.Second))
		}
		if cp.Message != "" {
			fmt.Printf("    Msg:  %s\n", cp.Message)
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

	// Add tier-specific evidence
	switch strings.ToLower(*tier) {
	case "standard":
		sessions := loadPresenceSessions(filePath)
		if len(sessions) > 0 {
			builder.WithPresence(sessions)
		}
	case "enhanced":
		sessions := loadPresenceSessions(filePath)
		if len(sessions) > 0 {
			builder.WithPresence(sessions)
		}
		// TPM binding would go here
	case "maximum":
		sessions := loadPresenceSessions(filePath)
		if len(sessions) > 0 {
			builder.WithPresence(sessions)
		}
		// All layers would be added here
	}

	packet, err := builder.Build()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error building evidence: %v\n", err)
		os.Exit(1)
	}

	// Determine output path
	outPath := *output
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
		fmt.Fprintln(os.Stderr, "Usage: witnessd verify <file|evidence.json>")
		os.Exit(1)
	}

	path := os.Args[2]

	// Check if it's an evidence packet
	if strings.HasSuffix(path, ".json") {
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

		// Verify evidence packet
		vdfParams := loadVDFParams()
		if err := packet.Verify(vdfParams); err != nil {
			fmt.Fprintf(os.Stderr, "Verification FAILED: %v\n", err)
			os.Exit(1)
		}

		fmt.Println("=== Evidence Verification ===")
		fmt.Println()
		fmt.Printf("Document: %s\n", packet.Document.Title)
		fmt.Printf("Strength: %s\n", packet.Strength)
		fmt.Printf("Checkpoints: %d\n", len(packet.Checkpoints))
		fmt.Printf("Total elapsed: %s\n", packet.TotalElapsedTime().Round(time.Second))
		fmt.Println()
		fmt.Println("Claims verified:")
		for _, claim := range packet.Claims {
			fmt.Printf("  ✓ %s\n", claim.Description)
		}
		fmt.Println()
		fmt.Println("Verification PASSED")
		return
	}

	// Verify chain for file
	verifyChain(path)
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

	// Count chains
	chainsDir := filepath.Join(dir, "chains")
	chains, _ := filepath.Glob(filepath.Join(chainsDir, "*.json"))
	fmt.Printf("Active chains: %d\n", len(chains))

	// Check for active presence session
	sessionFile := filepath.Join(dir, "sessions", "current.json")
	if _, err := os.Stat(sessionFile); err == nil {
		fmt.Println("Presence session: ACTIVE")
	} else {
		fmt.Println("Presence session: none")
	}

	fmt.Println()
	fmt.Println("TPM: ", func() string {
		if tpm.DetectTPM().Available() {
			return "available"
		}
		return "not available"
	}())
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

// Unused import placeholders for compatibility
var _ = sha256.Sum256
