package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"witnessd/internal/tpm"
	"witnessd/internal/tracking"
)

// Menu colors and formatting (ANSI escape codes)
const (
	colorReset  = "\033[0m"
	colorBold   = "\033[1m"
	colorDim    = "\033[2m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorCyan   = "\033[36m"
	colorRed    = "\033[31m"
)

// Menu represents the interactive menu system
type Menu struct {
	reader *bufio.Reader
	status *SystemStatus
}

// SystemStatus holds the current system state for display
type SystemStatus struct {
	Initialized      bool
	DataDir          string
	PublicKey        string
	VDFCalibrated    bool
	VDFIterPerSec    uint64
	TPMAvailable     bool
	TPMInfo          string
	ActiveTracking   bool
	TrackingInfo     string
	ActivePresence   bool
	PresenceInfo     string
	DatabaseEvents   int
	DatabaseFiles    int
	DatabaseIntegrity bool
}

// NewMenu creates a new interactive menu
func NewMenu() *Menu {
	return &Menu{
		reader: bufio.NewReader(os.Stdin),
	}
}

// Run starts the interactive menu
func (m *Menu) Run() {
	m.refreshStatus()

	for {
		m.clearScreen()
		m.printHeader()
		m.printStatus()
		m.printMainMenu()

		choice := m.prompt("Select an option")

		switch strings.ToLower(strings.TrimSpace(choice)) {
		case "1", "init":
			m.runInit()
		case "2", "commit":
			m.runCommit()
		case "3", "log":
			m.runLog()
		case "4", "export":
			m.runExport()
		case "5", "verify":
			m.runVerify()
		case "6", "track":
			m.trackMenu()
		case "7", "presence":
			m.presenceMenu()
		case "8", "status":
			m.runStatus()
		case "9", "calibrate":
			m.runCalibrate()
		case "h", "help", "?":
			m.showHelp()
		case "q", "quit", "exit", "0":
			m.printGoodbye()
			return
		default:
			m.printError("Invalid option. Press Enter to continue...")
			m.waitForEnter()
		}

		m.refreshStatus()
	}
}

// clearScreen clears the terminal (works on most terminals)
func (m *Menu) clearScreen() {
	fmt.Print("\033[H\033[2J")
}

// printHeader displays the banner and title
func (m *Menu) printHeader() {
	fmt.Println(colorCyan + banner + colorReset)
	fmt.Println(colorBold + "  Cryptographic Authorship Witnessing System" + colorReset)
	fmt.Println(colorDim + "  Version " + Version + colorReset)
	fmt.Println()
}

// printStatus displays the current system status
func (m *Menu) printStatus() {
	fmt.Println(colorBold + "─────────────────────────────────────────────" + colorReset)
	fmt.Println(colorBold + " SYSTEM STATUS" + colorReset)
	fmt.Println(colorBold + "─────────────────────────────────────────────" + colorReset)

	if !m.status.Initialized {
		fmt.Println(colorYellow + " ⚠  Not initialized - run 'Initialize' first" + colorReset)
	} else {
		// Initialization status
		fmt.Printf(" %s Initialized: %s\n", m.checkmark(true), m.status.DataDir)

		// Key status
		if m.status.PublicKey != "" {
			fmt.Printf(" %s Signing Key: %s...\n", m.checkmark(true), m.status.PublicKey)
		}

		// VDF status
		if m.status.VDFCalibrated {
			fmt.Printf(" %s VDF Calibrated: %s iter/sec\n",
				m.checkmark(true), m.formatNumber(m.status.VDFIterPerSec))
		} else {
			fmt.Printf(" %s VDF: %s\n", m.warning(), colorYellow+"not calibrated"+colorReset)
		}

		// TPM status
		if m.status.TPMAvailable {
			fmt.Printf(" %s TPM: %s\n", m.checkmark(true), m.status.TPMInfo)
		} else {
			fmt.Printf(" %s TPM: %s\n", m.info(), colorDim+"not available"+colorReset)
		}

		// Database status
		if m.status.DatabaseEvents > 0 {
			integrityStatus := colorGreen + "verified" + colorReset
			if !m.status.DatabaseIntegrity {
				integrityStatus = colorRed + "COMPROMISED" + colorReset
			}
			fmt.Printf(" %s Database: %d events, %d files (%s)\n",
				m.checkmark(m.status.DatabaseIntegrity),
				m.status.DatabaseEvents,
				m.status.DatabaseFiles,
				integrityStatus)
		}

		// Active sessions
		if m.status.ActiveTracking {
			fmt.Printf(" %s Tracking: %s\n", m.checkmark(true), colorGreen+m.status.TrackingInfo+colorReset)
		}
		if m.status.ActivePresence {
			fmt.Printf(" %s Presence: %s\n", m.checkmark(true), colorGreen+m.status.PresenceInfo+colorReset)
		}
	}

	fmt.Println(colorBold + "─────────────────────────────────────────────" + colorReset)
	fmt.Println()
}

// printMainMenu displays the main menu options
func (m *Menu) printMainMenu() {
	fmt.Println(colorBold + " MAIN MENU" + colorReset)
	fmt.Println()

	if !m.status.Initialized {
		fmt.Println(colorCyan + " [1]" + colorReset + " Initialize        Set up witnessd for first use")
		fmt.Println(colorDim + " [2] Commit           (requires initialization)" + colorReset)
		fmt.Println(colorDim + " [3] Log              (requires initialization)" + colorReset)
		fmt.Println(colorDim + " [4] Export           (requires initialization)" + colorReset)
		fmt.Println(colorDim + " [5] Verify           (requires initialization)" + colorReset)
		fmt.Println(colorDim + " [6] Track            (requires initialization)" + colorReset)
		fmt.Println(colorDim + " [7] Presence         (requires initialization)" + colorReset)
		fmt.Println(colorDim + " [8] Status           (requires initialization)" + colorReset)
		fmt.Println(colorDim + " [9] Calibrate        (requires initialization)" + colorReset)
	} else {
		fmt.Println(colorCyan + " [1]" + colorReset + " Initialize        Re-initialize or repair setup")
		fmt.Println(colorCyan + " [2]" + colorReset + " Commit            Create a checkpoint for a file")
		fmt.Println(colorCyan + " [3]" + colorReset + " Log               View checkpoint history")
		fmt.Println(colorCyan + " [4]" + colorReset + " Export            Export evidence packet")
		fmt.Println(colorCyan + " [5]" + colorReset + " Verify            Verify evidence or chain")
		fmt.Println(colorCyan + " [6]" + colorReset + " Track             Keystroke tracking menu  →")
		fmt.Println(colorCyan + " [7]" + colorReset + " Presence          Presence verification  →")
		fmt.Println(colorCyan + " [8]" + colorReset + " Status            Show detailed status")
		if !m.status.VDFCalibrated {
			fmt.Println(colorYellow + " [9]" + colorReset + " Calibrate        " + colorYellow + "⚠ Calibrate VDF (recommended)" + colorReset)
		} else {
			fmt.Println(colorCyan + " [9]" + colorReset + " Calibrate         Re-calibrate VDF timing")
		}
	}

	fmt.Println()
	fmt.Println(colorDim + " [H] Help    [Q] Quit" + colorReset)
	fmt.Println()
}

// trackMenu displays the tracking sub-menu
func (m *Menu) trackMenu() {
	if !m.status.Initialized {
		m.printError("Please initialize witnessd first.")
		m.waitForEnter()
		return
	}

	for {
		m.clearScreen()
		m.printHeader()

		fmt.Println(colorBold + "─────────────────────────────────────────────" + colorReset)
		fmt.Println(colorBold + " KEYSTROKE TRACKING" + colorReset)
		fmt.Println(colorBold + "─────────────────────────────────────────────" + colorReset)
		fmt.Println()
		fmt.Println(colorDim + " Track keystroke counts and timing patterns to prove")
		fmt.Println(" real-time authorship. NO key content is captured." + colorReset)
		fmt.Println()

		if m.status.ActiveTracking {
			fmt.Println(colorGreen + " ● Session Active: " + m.status.TrackingInfo + colorReset)
			fmt.Println()
		}

		fmt.Println(colorCyan + " [1]" + colorReset + " Start Tracking    Begin tracking for a document")
		fmt.Println(colorCyan + " [2]" + colorReset + " Stop Tracking     Stop and save current session")
		fmt.Println(colorCyan + " [3]" + colorReset + " Status            View current tracking status")
		fmt.Println(colorCyan + " [4]" + colorReset + " List Sessions     View saved tracking sessions")
		fmt.Println(colorCyan + " [5]" + colorReset + " Export Session    Export jitter evidence")
		fmt.Println()
		fmt.Println(colorDim + " [B] Back    [Q] Quit" + colorReset)
		fmt.Println()

		choice := m.prompt("Select an option")

		switch strings.ToLower(strings.TrimSpace(choice)) {
		case "1", "start":
			m.runTrackStart()
		case "2", "stop":
			m.runTrackStop()
		case "3", "status":
			m.runTrackStatus()
		case "4", "list":
			m.runTrackList()
		case "5", "export":
			m.runTrackExport()
		case "b", "back":
			return
		case "q", "quit":
			m.printGoodbye()
			os.Exit(0)
		default:
			m.printError("Invalid option.")
			m.waitForEnter()
		}

		m.refreshStatus()
	}
}

// presenceMenu displays the presence verification sub-menu
func (m *Menu) presenceMenu() {
	if !m.status.Initialized {
		m.printError("Please initialize witnessd first.")
		m.waitForEnter()
		return
	}

	for {
		m.clearScreen()
		m.printHeader()

		fmt.Println(colorBold + "─────────────────────────────────────────────" + colorReset)
		fmt.Println(colorBold + " PRESENCE VERIFICATION" + colorReset)
		fmt.Println(colorBold + "─────────────────────────────────────────────" + colorReset)
		fmt.Println()
		fmt.Println(colorDim + " Prove you were present during document creation")
		fmt.Println(" by responding to periodic challenges." + colorReset)
		fmt.Println()

		if m.status.ActivePresence {
			fmt.Println(colorGreen + " ● Session Active: " + m.status.PresenceInfo + colorReset)
			fmt.Println()
		}

		fmt.Println(colorCyan + " [1]" + colorReset + " Start Session     Begin presence verification")
		fmt.Println(colorCyan + " [2]" + colorReset + " Stop Session      End current session")
		fmt.Println(colorCyan + " [3]" + colorReset + " Status            View session status")
		fmt.Println(colorCyan + " [4]" + colorReset + " Challenge         Respond to a challenge")
		fmt.Println()
		fmt.Println(colorDim + " [B] Back    [Q] Quit" + colorReset)
		fmt.Println()

		choice := m.prompt("Select an option")

		switch strings.ToLower(strings.TrimSpace(choice)) {
		case "1", "start":
			m.runPresenceStart()
		case "2", "stop":
			m.runPresenceStop()
		case "3", "status":
			m.runPresenceStatus()
		case "4", "challenge":
			m.runPresenceChallenge()
		case "b", "back":
			return
		case "q", "quit":
			m.printGoodbye()
			os.Exit(0)
		default:
			m.printError("Invalid option.")
			m.waitForEnter()
		}

		m.refreshStatus()
	}
}

// showHelp displays detailed help information
func (m *Menu) showHelp() {
	m.clearScreen()
	m.printHeader()

	fmt.Println(colorBold + "─────────────────────────────────────────────" + colorReset)
	fmt.Println(colorBold + " HELP & DOCUMENTATION" + colorReset)
	fmt.Println(colorBold + "─────────────────────────────────────────────" + colorReset)
	fmt.Println()

	fmt.Println(colorBold + " WHAT IS WITNESSD?" + colorReset)
	fmt.Println(colorDim + " witnessd creates cryptographic proof that you authored")
	fmt.Println(" a document over time. It does NOT capture what you type," + colorReset)
	fmt.Println(colorDim + " only timing patterns and document state changes." + colorReset)
	fmt.Println()

	fmt.Println(colorBold + " BASIC WORKFLOW:" + colorReset)
	fmt.Println()
	fmt.Println("   1. " + colorCyan + "Initialize" + colorReset + "  →  Set up witnessd (one time)")
	fmt.Println("   2. " + colorCyan + "Calibrate" + colorReset + "   →  Calibrate VDF for your machine")
	fmt.Println("   3. " + colorDim + "(Write your document)" + colorReset)
	fmt.Println("   4. " + colorCyan + "Commit" + colorReset + "      →  Create checkpoints as you work")
	fmt.Println("   5. " + colorDim + "(Continue writing, commit periodically)" + colorReset)
	fmt.Println("   6. " + colorCyan + "Export" + colorReset + "      →  Create evidence packet when done")
	fmt.Println("   7. " + colorCyan + "Verify" + colorReset + "      →  Anyone can verify the evidence")
	fmt.Println()

	fmt.Println(colorBold + " ENHANCED WORKFLOW (with keystroke tracking):" + colorReset)
	fmt.Println()
	fmt.Println("   1. " + colorCyan + "Track → Start" + colorReset + "  →  Start tracking before writing")
	fmt.Println("   2. " + colorDim + "(Write your document)" + colorReset)
	fmt.Println("   3. " + colorCyan + "Commit" + colorReset + "          →  Checkpoints include jitter data")
	fmt.Println("   4. " + colorCyan + "Track → Stop" + colorReset + "   →  Stop tracking when done")
	fmt.Println("   5. " + colorCyan + "Export" + colorReset + "          →  Evidence includes keystroke proof")
	fmt.Println()

	fmt.Println(colorBold + " EVIDENCE TIERS:" + colorReset)
	fmt.Println()
	fmt.Println("   " + colorDim + "Basic" + colorReset + "     →  Checkpoint chain + VDF proofs")
	fmt.Println("   " + colorCyan + "Standard" + colorReset + "  →  + Keystroke/jitter evidence")
	fmt.Println("   " + colorCyan + "Enhanced" + colorReset + "  →  + TPM hardware attestation")
	fmt.Println("   " + colorCyan + "Maximum" + colorReset + "   →  + External timestamp anchors")
	fmt.Println()

	fmt.Println(colorBold + " COMMAND LINE USAGE:" + colorReset)
	fmt.Println()
	fmt.Println("   " + colorDim + "witnessd init" + colorReset)
	fmt.Println("   " + colorDim + "witnessd commit <file> -m \"message\"" + colorReset)
	fmt.Println("   " + colorDim + "witnessd log <file>" + colorReset)
	fmt.Println("   " + colorDim + "witnessd export <file> [-tier standard]" + colorReset)
	fmt.Println("   " + colorDim + "witnessd verify <evidence.json>" + colorReset)
	fmt.Println("   " + colorDim + "witnessd track start|stop|status <file>" + colorReset)
	fmt.Println()

	fmt.Println(colorBold + " MORE INFORMATION:" + colorReset)
	fmt.Println()
	fmt.Println("   Documentation: https://github.com/writerslogic/witnessd")
	fmt.Println("   Man pages:     man witnessd, man witnessctl")
	fmt.Println()

	m.waitForEnter()
}

// Command execution methods

func (m *Menu) runInit() {
	m.clearScreen()
	m.printHeader()
	fmt.Println(colorBold + " INITIALIZE WITNESSD" + colorReset)
	fmt.Println(colorBold + "─────────────────────────────────────────────" + colorReset)
	fmt.Println()

	if m.status.Initialized {
		fmt.Println(colorYellow + " witnessd is already initialized." + colorReset)
		fmt.Println()
		fmt.Println(" This will:")
		fmt.Println("   • Check and repair directory structure")
		fmt.Println("   • Preserve existing keys and data")
		fmt.Println("   • Update configuration if needed")
		fmt.Println()
		if !m.confirm("Continue with re-initialization?") {
			return
		}
	} else {
		fmt.Println(" This will set up witnessd for first use:")
		fmt.Println()
		fmt.Println("   • Create data directory (~/.witnessd)")
		fmt.Println("   • Generate Ed25519 signing keypair")
		fmt.Println("   • Create secure event database")
		fmt.Println("   • Set up default configuration")
		fmt.Println()
		if !m.confirm("Proceed with initialization?") {
			return
		}
	}

	fmt.Println()
	cmdInit()
	fmt.Println()
	m.printSuccess("Initialization complete!")
	m.waitForEnter()
}

func (m *Menu) runCommit() {
	if !m.status.Initialized {
		m.printError("Please initialize witnessd first.")
		m.waitForEnter()
		return
	}

	m.clearScreen()
	m.printHeader()
	fmt.Println(colorBold + " CREATE CHECKPOINT" + colorReset)
	fmt.Println(colorBold + "─────────────────────────────────────────────" + colorReset)
	fmt.Println()
	fmt.Println(colorDim + " A checkpoint records the current state of your document")
	fmt.Println(" with a VDF proof of elapsed time." + colorReset)
	fmt.Println()

	filePath := m.promptRequired("Enter file path")
	if filePath == "" {
		return
	}

	// Check file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		m.printError("File not found: " + filePath)
		m.waitForEnter()
		return
	}

	message := m.prompt("Commit message (optional)")

	fmt.Println()

	// Set up args and call cmdCommit
	oldArgs := os.Args
	if message != "" {
		os.Args = []string{"witnessd", "commit", filePath, "-m", message}
	} else {
		os.Args = []string{"witnessd", "commit", filePath}
	}
	cmdCommit()
	os.Args = oldArgs

	fmt.Println()
	m.waitForEnter()
}

func (m *Menu) runLog() {
	if !m.status.Initialized {
		m.printError("Please initialize witnessd first.")
		m.waitForEnter()
		return
	}

	m.clearScreen()
	m.printHeader()
	fmt.Println(colorBold + " VIEW CHECKPOINT HISTORY" + colorReset)
	fmt.Println(colorBold + "─────────────────────────────────────────────" + colorReset)
	fmt.Println()

	filePath := m.promptRequired("Enter file path")
	if filePath == "" {
		return
	}

	fmt.Println()

	oldArgs := os.Args
	os.Args = []string{"witnessd", "log", filePath}
	cmdLog()
	os.Args = oldArgs

	fmt.Println()
	m.waitForEnter()
}

func (m *Menu) runExport() {
	if !m.status.Initialized {
		m.printError("Please initialize witnessd first.")
		m.waitForEnter()
		return
	}

	m.clearScreen()
	m.printHeader()
	fmt.Println(colorBold + " EXPORT EVIDENCE PACKET" + colorReset)
	fmt.Println(colorBold + "─────────────────────────────────────────────" + colorReset)
	fmt.Println()
	fmt.Println(colorDim + " Create a portable evidence packet containing your")
	fmt.Println(" checkpoint chain, declaration, and optional evidence." + colorReset)
	fmt.Println()

	filePath := m.promptRequired("Enter file path")
	if filePath == "" {
		return
	}

	fmt.Println()
	fmt.Println(" Evidence tier:")
	fmt.Println("   [1] Basic    - Checkpoint chain + VDF proofs")
	fmt.Println("   [2] Standard - + Keystroke evidence (if available)")
	fmt.Println("   [3] Enhanced - + TPM attestation (if available)")
	fmt.Println("   [4] Maximum  - All available evidence")
	fmt.Println()

	tierChoice := m.prompt("Select tier [1]")
	tier := "basic"
	switch tierChoice {
	case "2":
		tier = "standard"
	case "3":
		tier = "enhanced"
	case "4":
		tier = "maximum"
	}

	output := m.prompt("Output file (Enter for default)")

	fmt.Println()

	oldArgs := os.Args
	args := []string{"witnessd", "export", filePath, "-tier", tier}
	if output != "" {
		args = append(args, "-o", output)
	}
	os.Args = args
	cmdExport()
	os.Args = oldArgs

	fmt.Println()
	m.waitForEnter()
}

func (m *Menu) runVerify() {
	m.clearScreen()
	m.printHeader()
	fmt.Println(colorBold + " VERIFY EVIDENCE" + colorReset)
	fmt.Println(colorBold + "─────────────────────────────────────────────" + colorReset)
	fmt.Println()
	fmt.Println(colorDim + " Verify an evidence packet or checkpoint chain." + colorReset)
	fmt.Println()

	filePath := m.promptRequired("Enter file or evidence packet path")
	if filePath == "" {
		return
	}

	fmt.Println()

	oldArgs := os.Args
	os.Args = []string{"witnessd", "verify", filePath}
	cmdVerify()
	os.Args = oldArgs

	fmt.Println()
	m.waitForEnter()
}

func (m *Menu) runStatus() {
	if !m.status.Initialized {
		m.printError("Please initialize witnessd first.")
		m.waitForEnter()
		return
	}

	m.clearScreen()
	m.printHeader()

	cmdStatus()

	fmt.Println()
	m.waitForEnter()
}

func (m *Menu) runCalibrate() {
	if !m.status.Initialized {
		m.printError("Please initialize witnessd first.")
		m.waitForEnter()
		return
	}

	m.clearScreen()
	m.printHeader()
	fmt.Println(colorBold + " CALIBRATE VDF" + colorReset)
	fmt.Println(colorBold + "─────────────────────────────────────────────" + colorReset)
	fmt.Println()
	fmt.Println(colorDim + " VDF (Verifiable Delay Function) calibration measures")
	fmt.Println(" your CPU's hashing speed to accurately prove time elapsed." + colorReset)
	fmt.Println()
	fmt.Println(" This will run a ~2 second benchmark.")
	fmt.Println()

	if !m.confirm("Start calibration?") {
		return
	}

	fmt.Println()
	cmdCalibrate()
	fmt.Println()
	m.printSuccess("Calibration complete!")
	m.waitForEnter()
}

// Track sub-menu commands

func (m *Menu) runTrackStart() {
	m.clearScreen()
	m.printHeader()
	fmt.Println(colorBold + " START KEYSTROKE TRACKING" + colorReset)
	fmt.Println(colorBold + "─────────────────────────────────────────────" + colorReset)
	fmt.Println()
	fmt.Println(colorYellow + " PRIVACY NOTE:" + colorReset)
	fmt.Println(colorDim + " Tracking records keystroke COUNTS and TIMING only.")
	fmt.Println(" NO key values or content are captured. This is NOT a keylogger." + colorReset)
	fmt.Println()

	if m.status.ActiveTracking {
		m.printError("A tracking session is already active.")
		fmt.Println(" Stop it first with 'Stop Tracking'.")
		m.waitForEnter()
		return
	}

	filePath := m.promptRequired("Document file to track")
	if filePath == "" {
		return
	}

	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		m.printError("File not found: " + filePath)
		m.waitForEnter()
		return
	}

	fmt.Println()

	oldArgs := os.Args
	os.Args = []string{"witnessd", "track", "start", filePath}
	cmdTrack()
	os.Args = oldArgs

	fmt.Println()
	m.waitForEnter()
}

func (m *Menu) runTrackStop() {
	m.clearScreen()
	m.printHeader()
	fmt.Println(colorBold + " STOP TRACKING" + colorReset)
	fmt.Println(colorBold + "─────────────────────────────────────────────" + colorReset)
	fmt.Println()

	if !m.status.ActiveTracking {
		m.printError("No active tracking session.")
		m.waitForEnter()
		return
	}

	if !m.confirm("Stop the current tracking session?") {
		return
	}

	fmt.Println()

	oldArgs := os.Args
	os.Args = []string{"witnessd", "track", "stop"}
	cmdTrack()
	os.Args = oldArgs

	fmt.Println()
	m.waitForEnter()
}

func (m *Menu) runTrackStatus() {
	m.clearScreen()
	m.printHeader()
	fmt.Println(colorBold + " TRACKING STATUS" + colorReset)
	fmt.Println(colorBold + "─────────────────────────────────────────────" + colorReset)
	fmt.Println()

	oldArgs := os.Args
	os.Args = []string{"witnessd", "track", "status"}
	cmdTrack()
	os.Args = oldArgs

	fmt.Println()
	m.waitForEnter()
}

func (m *Menu) runTrackList() {
	m.clearScreen()
	m.printHeader()
	fmt.Println(colorBold + " SAVED TRACKING SESSIONS" + colorReset)
	fmt.Println(colorBold + "─────────────────────────────────────────────" + colorReset)
	fmt.Println()

	oldArgs := os.Args
	os.Args = []string{"witnessd", "track", "list"}
	cmdTrack()
	os.Args = oldArgs

	fmt.Println()
	m.waitForEnter()
}

func (m *Menu) runTrackExport() {
	m.clearScreen()
	m.printHeader()
	fmt.Println(colorBold + " EXPORT TRACKING SESSION" + colorReset)
	fmt.Println(colorBold + "─────────────────────────────────────────────" + colorReset)
	fmt.Println()

	sessionID := m.promptRequired("Session ID to export")
	if sessionID == "" {
		return
	}

	fmt.Println()

	oldArgs := os.Args
	os.Args = []string{"witnessd", "track", "export", sessionID}
	cmdTrack()
	os.Args = oldArgs

	fmt.Println()
	m.waitForEnter()
}

// Presence sub-menu commands

func (m *Menu) runPresenceStart() {
	m.clearScreen()
	m.printHeader()
	fmt.Println(colorBold + " START PRESENCE SESSION" + colorReset)
	fmt.Println(colorBold + "─────────────────────────────────────────────" + colorReset)
	fmt.Println()
	fmt.Println(colorDim + " Presence verification proves you were at the keyboard")
	fmt.Println(" by responding to periodic challenges." + colorReset)
	fmt.Println()

	if m.status.ActivePresence {
		m.printError("A presence session is already active.")
		m.waitForEnter()
		return
	}

	if !m.confirm("Start presence verification session?") {
		return
	}

	fmt.Println()

	oldArgs := os.Args
	os.Args = []string{"witnessd", "presence", "start"}
	cmdPresence()
	os.Args = oldArgs

	fmt.Println()
	m.waitForEnter()
}

func (m *Menu) runPresenceStop() {
	m.clearScreen()
	m.printHeader()
	fmt.Println(colorBold + " STOP PRESENCE SESSION" + colorReset)
	fmt.Println(colorBold + "─────────────────────────────────────────────" + colorReset)
	fmt.Println()

	if !m.status.ActivePresence {
		m.printError("No active presence session.")
		m.waitForEnter()
		return
	}

	if !m.confirm("Stop the current presence session?") {
		return
	}

	fmt.Println()

	oldArgs := os.Args
	os.Args = []string{"witnessd", "presence", "stop"}
	cmdPresence()
	os.Args = oldArgs

	fmt.Println()
	m.waitForEnter()
}

func (m *Menu) runPresenceStatus() {
	m.clearScreen()
	m.printHeader()
	fmt.Println(colorBold + " PRESENCE STATUS" + colorReset)
	fmt.Println(colorBold + "─────────────────────────────────────────────" + colorReset)
	fmt.Println()

	oldArgs := os.Args
	os.Args = []string{"witnessd", "presence", "status"}
	cmdPresence()
	os.Args = oldArgs

	fmt.Println()
	m.waitForEnter()
}

func (m *Menu) runPresenceChallenge() {
	m.clearScreen()
	m.printHeader()

	if !m.status.ActivePresence {
		m.printError("No active presence session. Start one first.")
		m.waitForEnter()
		return
	}

	oldArgs := os.Args
	os.Args = []string{"witnessd", "presence", "challenge"}
	cmdPresence()
	os.Args = oldArgs

	fmt.Println()
	m.waitForEnter()
}

// Helper methods

func (m *Menu) refreshStatus() {
	m.status = m.getSystemStatus()
}

func (m *Menu) getSystemStatus() *SystemStatus {
	status := &SystemStatus{}

	dir := witnessdDir()
	status.DataDir = dir

	// Check initialization
	if _, err := os.Stat(dir); err == nil {
		status.Initialized = true
	} else {
		return status
	}

	// Check public key
	keyPath := filepath.Join(dir, "signing_key.pub")
	if pubKey, err := os.ReadFile(keyPath); err == nil && len(pubKey) >= 8 {
		status.PublicKey = fmt.Sprintf("%x", pubKey[:8])
	}

	// Check VDF calibration
	vdfParams := loadVDFParams()
	status.VDFIterPerSec = vdfParams.IterationsPerSecond
	if vdfParams.IterationsPerSecond > 0 {
		// Check if calibrated (not default)
		configPath := filepath.Join(dir, "config.json")
		if data, err := os.ReadFile(configPath); err == nil {
			if strings.Contains(string(data), `"calibrated": true`) ||
			   strings.Contains(string(data), `"calibrated":true`) {
				status.VDFCalibrated = true
			}
		}
	}

	// Check TPM
	tpmProvider := tpm.DetectTPM()
	if tpmProvider.Available() {
		status.TPMAvailable = true
		if err := tpmProvider.Open(); err == nil {
			status.TPMInfo = fmt.Sprintf("%s (v%s)",
				tpmProvider.Manufacturer(), tpmProvider.FirmwareVersion())
			tpmProvider.Close()
		} else {
			status.TPMInfo = "available"
		}
	}

	// Check database
	if db, err := openSecureStore(); err == nil {
		defer db.Close()
		if stats, err := db.GetStats(); err == nil {
			status.DatabaseEvents = int(stats.EventCount)
			status.DatabaseFiles = int(stats.FileCount)
			status.DatabaseIntegrity = stats.IntegrityOK
		}
	}

	// Check active tracking
	trackingDir := filepath.Join(dir, "tracking")
	currentFile := filepath.Join(trackingDir, "current_session.json")
	pidFile := filepath.Join(trackingDir, "daemon.pid")
	if _, err := os.Stat(currentFile); err == nil {
		if isTrackingDaemonRunning(pidFile) {
			status.ActiveTracking = true
			// Get tracking info from current session file
			if data, err := os.ReadFile(currentFile); err == nil {
				var info map[string]interface{}
				if err := json.Unmarshal(data, &info); err == nil {
					if id, ok := info["id"].(string); ok {
						if session, err := tracking.Load(dir, id); err == nil {
							s := session.Status()
							status.TrackingInfo = fmt.Sprintf("%d keystrokes, %s",
								s.KeystrokeCount, s.Duration.Round(time.Second))
						}
					}
				}
			}
		}
	}

	// Check active presence
	sessionFile := filepath.Join(dir, "sessions", "current.json")
	if _, err := os.Stat(sessionFile); err == nil {
		status.ActivePresence = true
		status.PresenceInfo = "session active"
	}

	return status
}

func (m *Menu) prompt(label string) string {
	fmt.Print(colorCyan + " " + label + ": " + colorReset)
	input, _ := m.reader.ReadString('\n')
	return strings.TrimSpace(input)
}

func (m *Menu) promptRequired(label string) string {
	for {
		fmt.Print(colorCyan + " " + label + ": " + colorReset)
		input, _ := m.reader.ReadString('\n')
		input = strings.TrimSpace(input)
		if input != "" {
			return input
		}
		if input == "" {
			// Allow escape with empty input
			fmt.Print(colorDim + " (Press Enter again to cancel) " + colorReset)
			input2, _ := m.reader.ReadString('\n')
			if strings.TrimSpace(input2) == "" {
				return ""
			}
		}
	}
}

func (m *Menu) confirm(message string) bool {
	fmt.Print(colorCyan + " " + message + " [y/N]: " + colorReset)
	input, _ := m.reader.ReadString('\n')
	input = strings.ToLower(strings.TrimSpace(input))
	return input == "y" || input == "yes"
}

func (m *Menu) waitForEnter() {
	fmt.Print(colorDim + " Press Enter to continue..." + colorReset)
	m.reader.ReadString('\n')
}

func (m *Menu) printError(message string) {
	fmt.Println()
	fmt.Println(colorRed + " ✗ " + message + colorReset)
	fmt.Println()
}

func (m *Menu) printSuccess(message string) {
	fmt.Println(colorGreen + " ✓ " + message + colorReset)
}

func (m *Menu) printGoodbye() {
	fmt.Println()
	fmt.Println(colorDim + " Goodbye!" + colorReset)
	fmt.Println()
}

func (m *Menu) checkmark(ok bool) string {
	if ok {
		return colorGreen + "✓" + colorReset
	}
	return colorRed + "✗" + colorReset
}

func (m *Menu) warning() string {
	return colorYellow + "⚠" + colorReset
}

func (m *Menu) info() string {
	return colorDim + "○" + colorReset
}

func (m *Menu) formatNumber(n uint64) string {
	s := strconv.FormatUint(n, 10)
	// Add thousand separators
	if len(s) <= 3 {
		return s
	}

	var result strings.Builder
	remainder := len(s) % 3
	if remainder > 0 {
		result.WriteString(s[:remainder])
		s = s[remainder:]
		if len(s) > 0 {
			result.WriteString(",")
		}
	}
	for i := 0; i < len(s); i += 3 {
		result.WriteString(s[i : i+3])
		if i+3 < len(s) {
			result.WriteString(",")
		}
	}
	return result.String()
}
