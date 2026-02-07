// Package main provides IPC-based commands for witnessctl.
//
// These commands communicate with the witnessd daemon via IPC,
// providing a cleaner architecture where the daemon manages all state.
//
// Patent Pending: USPTO Application No. 19/460,364
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"witnessd/internal/config"
	"witnessd/internal/ipc"
)

// IPCCommands wraps IPC client commands
type IPCCommands struct {
	client *ipc.IPCClient
}

// NewIPCCommands creates a new IPC command handler
func NewIPCCommands() (*IPCCommands, error) {
	cfg := ipc.DefaultClientConfig(config.WitnessdDir())
	cfg.ClientName = "witnessctl"
	cfg.ClientVersion = Version

	client := ipc.NewClient(cfg)
	if err := client.Connect(); err != nil {
		return nil, err
	}

	return &IPCCommands{client: client}, nil
}

// Close closes the IPC connection
func (c *IPCCommands) Close() error {
	return c.client.Close()
}

// cmdIPCStatus shows daemon status via IPC
func cmdIPCStatus() {
	cmds, err := NewIPCCommands()
	if err != nil {
		printError(fmt.Sprintf("Cannot connect to daemon: %v", err))
		fmt.Fprintf(os.Stderr, "  %sTip%s: Start the daemon with: witnessd serve\n", c.Dim, c.Reset)
		os.Exit(1)
	}
	defer cmds.Close()

	status, err := cmds.client.Status()
	if err != nil {
		printError(fmt.Sprintf("Failed to get status: %v", err))
		os.Exit(1)
	}

	printSection("DAEMON STATUS")

	fmt.Printf("  %sVersion%s        %s%s%s\n", c.Dim, c.Reset, c.Cyan, status.Version, c.Reset)
	fmt.Printf("  %sUptime%s         %s\n", c.Dim, c.Reset, status.Uptime.Round(time.Second))
	fmt.Printf("  %sStarted%s        %s\n", c.Dim, c.Reset, status.StartedAt.Format(time.RFC3339))

	if status.Initialized {
		fmt.Printf("  %sStatus%s         %s%sINITIALIZED%s\n", c.Dim, c.Reset, c.Bold, c.Green, c.Reset)
	} else {
		fmt.Printf("  %sStatus%s         %s%sNOT INITIALIZED%s\n", c.Dim, c.Reset, c.Bold, c.Yellow, c.Reset)
	}

	printSection("DATABASE")

	if status.DatabaseStatus.IntegrityOK {
		fmt.Printf("  %sIntegrity%s      %s%sVERIFIED%s\n", c.Dim, c.Reset, c.Bold, c.Green, c.Reset)
	} else {
		fmt.Printf("  %sIntegrity%s      %s%sFAILED%s\n", c.Dim, c.Reset, c.Bold, c.Red, c.Reset)
	}
	fmt.Printf("  %sEvents%s         %d\n", c.Dim, c.Reset, status.DatabaseStatus.EventCount)
	fmt.Printf("  %sFiles%s          %d\n", c.Dim, c.Reset, status.DatabaseStatus.FileCount)

	if status.TPMStatus.Available {
		printSection("TPM")
		fmt.Printf("  %sStatus%s         %s%sAVAILABLE%s\n", c.Dim, c.Reset, c.Bold, c.Green, c.Reset)
		if status.TPMStatus.Manufacturer != "" {
			fmt.Printf("  %sManufacturer%s   %s\n", c.Dim, c.Reset, status.TPMStatus.Manufacturer)
		}
	}

	if len(status.ActiveSessions) > 0 {
		printSection("ACTIVE SESSIONS")
		for _, sess := range status.ActiveSessions {
			fmt.Printf("  %s%s%s\n", c.Cyan, sess.ID, c.Reset)
			fmt.Printf("    %sDocument%s   %s\n", c.Dim, c.Reset, sess.DocumentPath)
			fmt.Printf("    %sDuration%s   %s\n", c.Dim, c.Reset, sess.Duration.Round(time.Second))
			fmt.Printf("    %sKeystrokes%s %d\n", c.Dim, c.Reset, sess.Keystrokes)
		}
	}

	fmt.Println()
}

// cmdIPCTracking handles tracking commands via IPC
func cmdIPCTracking(args []string) {
	if len(args) == 0 {
		printError("Usage: witnessctl track <start|stop|status> [options]")
		os.Exit(1)
	}

	cmds, err := NewIPCCommands()
	if err != nil {
		printError(fmt.Sprintf("Cannot connect to daemon: %v", err))
		fmt.Fprintf(os.Stderr, "  %sTip%s: Start the daemon with: witnessd serve\n", c.Dim, c.Reset)
		os.Exit(1)
	}
	defer cmds.Close()

	action := args[0]

	switch action {
	case "start":
		if len(args) < 2 {
			printError("Usage: witnessctl track start <file>")
			os.Exit(1)
		}
		filePath := args[1]

		resp, err := cmds.client.TrackingStart(filePath, true, true)
		if err != nil {
			printError(fmt.Sprintf("Failed to start tracking: %v", err))
			os.Exit(1)
		}

		if !resp.Success {
			printError(resp.Error)
			os.Exit(1)
		}

		fmt.Printf("\n%s%s TRACKING STARTED %s\n\n", c.Bold, c.Green, c.Reset)
		fmt.Printf("  %sSession%s   %s%s%s\n", c.Dim, c.Reset, c.Cyan, resp.SessionID, c.Reset)
		fmt.Printf("  %sDocument%s  %s\n", c.Dim, c.Reset, filePath)
		fmt.Println()
		fmt.Printf("  %sPrivacy Note%s: Only keystroke counts are recorded.\n", c.Dim, c.Reset)
		fmt.Println()

	case "stop":
		sessionID := ""
		if len(args) >= 2 {
			sessionID = args[1]
		}

		resp, err := cmds.client.TrackingStop(sessionID)
		if err != nil {
			printError(fmt.Sprintf("Failed to stop tracking: %v", err))
			os.Exit(1)
		}

		if !resp.Success {
			printError(resp.Error)
			os.Exit(1)
		}

		fmt.Printf("\n%s%s TRACKING STOPPED %s\n\n", c.Bold, c.Green, c.Reset)
		if resp.SessionSummary != nil {
			fmt.Printf("  %sSession%s     %s\n", c.Dim, c.Reset, resp.SessionSummary.ID)
			fmt.Printf("  %sDuration%s    %s\n", c.Dim, c.Reset, resp.SessionSummary.Duration.Round(time.Second))
			fmt.Printf("  %sKeystrokes%s  %d\n", c.Dim, c.Reset, resp.SessionSummary.KeystrokeCount)
			fmt.Printf("  %sSamples%s     %d\n", c.Dim, c.Reset, resp.SessionSummary.SampleCount)
			if resp.SessionSummary.KeystrokesPerMin > 0 {
				fmt.Printf("  %sRate%s        %.0f/min\n", c.Dim, c.Reset, resp.SessionSummary.KeystrokesPerMin)
			}
		}
		fmt.Println()

	case "status":
		sessionID := ""
		if len(args) >= 2 {
			sessionID = args[1]
		}

		resp, err := cmds.client.TrackingStatus(sessionID)
		if err != nil {
			printError(fmt.Sprintf("Failed to get tracking status: %v", err))
			os.Exit(1)
		}

		if !resp.Active {
			fmt.Printf("  %sNo active tracking session.%s\n", c.Dim, c.Reset)
			return
		}

		printSection("TRACKING STATUS")
		if resp.Session != nil {
			fmt.Printf("  %sSession%s     %s%s%s\n", c.Dim, c.Reset, c.Cyan, resp.Session.ID, c.Reset)
			fmt.Printf("  %sDocument%s    %s\n", c.Dim, c.Reset, resp.Session.DocumentPath)
			fmt.Printf("  %sStarted%s     %s\n", c.Dim, c.Reset, resp.Session.StartedAt.Format(time.RFC3339))
			fmt.Printf("  %sDuration%s    %s\n", c.Dim, c.Reset, resp.Session.Duration.Round(time.Second))
			fmt.Printf("  %sKeystrokes%s  %s%d%s\n", c.Dim, c.Reset, c.Bold+c.White, resp.Session.KeystrokeCount, c.Reset)
			fmt.Printf("  %sSamples%s     %d\n", c.Dim, c.Reset, resp.Session.SampleCount)
			if resp.Session.KeystrokesPerMin > 0 {
				fmt.Printf("  %sRate%s        %.0f keystrokes/min\n", c.Dim, c.Reset, resp.Session.KeystrokesPerMin)
			}
		}
		fmt.Println()

	default:
		printError(fmt.Sprintf("Unknown tracking action: %s", action))
		os.Exit(1)
	}
}

// cmdIPCSessions lists tracking sessions via IPC
func cmdIPCSessions(activeOnly bool, limit int) {
	cmds, err := NewIPCCommands()
	if err != nil {
		printError(fmt.Sprintf("Cannot connect to daemon: %v", err))
		os.Exit(1)
	}
	defer cmds.Close()

	resp, err := cmds.client.ListSessions(activeOnly, limit)
	if err != nil {
		printError(fmt.Sprintf("Failed to list sessions: %v", err))
		os.Exit(1)
	}

	if len(resp.Sessions) == 0 {
		fmt.Printf("  %sNo sessions found.%s\n", c.Dim, c.Reset)
		return
	}

	printSection("TRACKING SESSIONS")

	for _, sess := range resp.Sessions {
		fmt.Printf("  %s%s%s\n", c.Cyan, sess.ID, c.Reset)
		fmt.Printf("    %sDocument%s   %s\n", c.Dim, c.Reset, sess.DocumentPath)
		fmt.Printf("    %sStarted%s    %s\n", c.Dim, c.Reset, sess.StartedAt.Format("2006-01-02 15:04"))
		fmt.Printf("    %sDuration%s   %s\n", c.Dim, c.Reset, sess.Duration.Round(time.Second))
		fmt.Printf("    %sKeystrokes%s %d\n", c.Dim, c.Reset, sess.Keystrokes)
		fmt.Println()
	}
}

// cmdIPCCheckpoint creates a checkpoint via IPC
func cmdIPCCheckpoint(filePath, message string) {
	cmds, err := NewIPCCommands()
	if err != nil {
		printError(fmt.Sprintf("Cannot connect to daemon: %v", err))
		os.Exit(1)
	}
	defer cmds.Close()

	fmt.Printf("Creating checkpoint...")

	resp, err := cmds.client.CommitCheckpoint(filePath, message)
	if err != nil {
		fmt.Println()
		printError(fmt.Sprintf("Failed to create checkpoint: %v", err))
		os.Exit(1)
	}

	if !resp.Success {
		fmt.Println()
		printError(resp.Error)
		os.Exit(1)
	}

	fmt.Printf(" done\n\n")
	fmt.Printf("%s%s CHECKPOINT #%d CREATED %s\n\n", c.Bold, c.Green, resp.CheckpointID, c.Reset)
	fmt.Printf("  %sContent Hash%s  %s%s%s...\n", c.Dim, c.Reset, c.Cyan, resp.ContentHash[:16], c.Reset)
	fmt.Printf("  %sEvent Hash%s    %s%s%s...\n", c.Dim, c.Reset, c.Cyan, resp.EventHash[:16], c.Reset)
	fmt.Printf("  %sVDF Elapsed%s   %s\n", c.Dim, c.Reset, resp.VDFElapsed)
	if message != "" {
		fmt.Printf("  %sMessage%s       %s\n", c.Dim, c.Reset, message)
	}
	fmt.Println()
}

// cmdIPCHistory shows checkpoint history via IPC
func cmdIPCHistory(filePath string, limit int) {
	cmds, err := NewIPCCommands()
	if err != nil {
		printError(fmt.Sprintf("Cannot connect to daemon: %v", err))
		os.Exit(1)
	}
	defer cmds.Close()

	resp, err := cmds.client.GetHistory(filePath, limit, 0)
	if err != nil {
		printError(fmt.Sprintf("Failed to get history: %v", err))
		os.Exit(1)
	}

	if len(resp.Checkpoints) == 0 {
		fmt.Printf("  %sNo checkpoint history found for: %s%s\n", c.Dim, filePath, c.Reset)
		return
	}

	printSection("CHECKPOINT HISTORY")
	fmt.Printf("  %sDocument%s      %s\n", c.Dim, c.Reset, resp.FilePath)
	fmt.Printf("  %sCheckpoints%s   %d\n", c.Dim, c.Reset, resp.Total)
	fmt.Printf("  %sTotal VDF%s     %s\n", c.Dim, c.Reset, resp.TotalVDFTime)
	fmt.Println()

	for _, cp := range resp.Checkpoints {
		fmt.Printf("  %s[%d]%s %s\n", c.Cyan, cp.Ordinal, c.Reset, cp.Timestamp.Format("2006-01-02 15:04:05"))
		fmt.Printf("      %sHash%s  %s...\n", c.Dim, c.Reset, cp.ContentHash[:16])
		fmt.Printf("      %sSize%s  %d bytes", c.Dim, c.Reset, cp.FileSize)
		if cp.SizeDelta != 0 {
			if cp.SizeDelta > 0 {
				fmt.Printf(" %s(+%d)%s", c.Green, cp.SizeDelta, c.Reset)
			} else {
				fmt.Printf(" %s(%d)%s", c.Red, cp.SizeDelta, c.Reset)
			}
		}
		fmt.Println()
		fmt.Printf("      %sVDF%s   %s\n", c.Dim, c.Reset, cp.VDFElapsed)
		if cp.Message != "" {
			fmt.Printf("      %sMsg%s   %s\n", c.Dim, c.Reset, cp.Message)
		}
		fmt.Println()
	}
}

// cmdIPCSubscribe subscribes to events and prints them
func cmdIPCSubscribe() {
	cmds, err := NewIPCCommands()
	if err != nil {
		printError(fmt.Sprintf("Cannot connect to daemon: %v", err))
		os.Exit(1)
	}
	defer cmds.Close()

	// Subscribe to all events
	if err := cmds.client.Subscribe(nil); err != nil {
		printError(fmt.Sprintf("Failed to subscribe: %v", err))
		os.Exit(1)
	}

	fmt.Printf("%s%s SUBSCRIBED TO EVENTS %s\n\n", c.Bold, c.Green, c.Reset)
	fmt.Println("Waiting for events... Press Ctrl+C to stop")
	fmt.Println()

	// Print events as they come in
	for event := range cmds.client.Events() {
		data, _ := json.MarshalIndent(event, "", "  ")
		fmt.Printf("[%s] %s\n%s\n\n",
			event.Timestamp.Format("15:04:05"),
			eventTypeName(event.Type),
			string(data))
	}
}

// eventTypeName returns a human-readable event type name
func eventTypeName(et ipc.EventType) string {
	switch et {
	case ipc.EventKeystrokeUpdate:
		return "KeystrokeUpdate"
	case ipc.EventSessionStart:
		return "SessionStart"
	case ipc.EventSessionStop:
		return "SessionStop"
	case ipc.EventCheckpointCreated:
		return "CheckpointCreated"
	case ipc.EventTrackingUpdate:
		return "TrackingUpdate"
	case ipc.EventError:
		return "Error"
	case ipc.EventDaemonShutdown:
		return "DaemonShutdown"
	case ipc.EventConfigChanged:
		return "ConfigChanged"
	default:
		return fmt.Sprintf("Unknown(%d)", et)
	}
}

// cmdIPCPing pings the daemon
func cmdIPCPing() {
	cfg := ipc.DefaultClientConfig(config.WitnessdDir())
	client := ipc.NewClient(cfg)

	if err := client.Connect(); err != nil {
		fmt.Printf("  %sDaemon%s  %s%sNOT RUNNING%s\n", c.Dim, c.Reset, c.Bold, c.Red, c.Reset)
		os.Exit(1)
	}
	defer client.Close()

	start := time.Now()
	if err := client.Ping(); err != nil {
		fmt.Printf("  %sDaemon%s  %s%sNOT RESPONDING%s (%v)\n", c.Dim, c.Reset, c.Bold, c.Red, c.Reset, err)
		os.Exit(1)
	}
	latency := time.Since(start)

	fmt.Printf("  %sDaemon%s  %s%sRUNNING%s (latency: %s)\n", c.Dim, c.Reset, c.Bold, c.Green, c.Reset, latency.Round(time.Microsecond))
}
