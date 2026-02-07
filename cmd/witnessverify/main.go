// Command witnessverify is a standalone tool for verifying witnessd evidence packets.
//
// This tool can verify evidence packets without requiring a running witnessd daemon,
// making it suitable for:
// - Offline verification
// - Third-party audits
// - Automated verification pipelines
// - Cross-platform verification
//
// Usage:
//
//	witnessverify [flags] <evidence.json>
//
// Examples:
//
//	# Basic verification
//	witnessverify evidence.json
//
//	# Verbose JSON output
//	witnessverify -format json -verbose evidence.json
//
//	# Forensic-level verification
//	witnessverify -level forensic evidence.json
//
//	# Verify with external anchor checking
//	witnessverify -level paranoid -anchors evidence.json
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"witnessd/internal/evidence"
	"witnessd/internal/vdf"
	"witnessd/internal/verify"
	"witnessd/pkg/anchors"
)

var (
	// Version information (set at build time)
	version   = "dev"
	commit    = "unknown"
	buildTime = "unknown"
)

func main() {
	// Parse flags
	levelStr := flag.String("level", "standard", "verification level: quick, standard, forensic, paranoid")
	formatStr := flag.String("format", "text", "output format: text, json, markdown, html")
	output := flag.String("output", "", "output file (default: stdout)")
	verbose := flag.Bool("verbose", false, "verbose output with details")
	checkAnchors := flag.Bool("anchors", false, "verify external anchors (requires network)")
	timeout := flag.Duration("timeout", 5*time.Minute, "verification timeout")
	versionFlag := flag.Bool("version", false, "print version and exit")
	quiet := flag.Bool("quiet", false, "quiet mode - only print result code")
	exitCode := flag.Bool("exit-code", true, "exit with non-zero code on verification failure")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "witnessverify - Verify witnessd evidence packets\n\n")
		fmt.Fprintf(os.Stderr, "Usage: %s [flags] <evidence.json>\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nVerification Levels:\n")
		fmt.Fprintf(os.Stderr, "  quick     - Fast structural checks only\n")
		fmt.Fprintf(os.Stderr, "  standard  - Full cryptographic verification (default)\n")
		fmt.Fprintf(os.Stderr, "  forensic  - Deep forensic analysis including timing checks\n")
		fmt.Fprintf(os.Stderr, "  paranoid  - All checks including external anchor verification\n")
		fmt.Fprintf(os.Stderr, "\nOutput Formats:\n")
		fmt.Fprintf(os.Stderr, "  text      - Human-readable text (default)\n")
		fmt.Fprintf(os.Stderr, "  json      - JSON format for programmatic processing\n")
		fmt.Fprintf(os.Stderr, "  markdown  - Markdown format for documentation\n")
		fmt.Fprintf(os.Stderr, "  html      - HTML format for web display\n")
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s evidence.json\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -level forensic -format json evidence.json\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -level paranoid -anchors evidence.json\n", os.Args[0])
	}

	flag.Parse()

	// Handle version flag
	if *versionFlag {
		fmt.Printf("witnessverify %s (commit: %s, built: %s)\n", version, commit, buildTime)
		os.Exit(0)
	}

	// Require input file
	if flag.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "Error: evidence file required\n\n")
		flag.Usage()
		os.Exit(2)
	}

	inputFile := flag.Arg(0)

	// Parse verification level
	level, err := parseLevel(*levelStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(2)
	}

	// Parse output format
	format, err := parseFormat(*formatStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(2)
	}

	// Load evidence packet
	packet, err := loadPacket(inputFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading evidence: %v\n", err)
		os.Exit(1)
	}

	// Configure verifier
	opts := []verify.VerifierOption{
		verify.WithLevel(level),
		verify.WithTimeout(*timeout),
		verify.WithVDFParams(vdf.DefaultParameters()),
	}

	// Configure anchor verification if requested
	if *checkAnchors && level >= verify.LevelParanoid {
		registry := anchors.NewRegistry()
		registry.RegisterDefaults()
		opts = append(opts, verify.WithAnchorRegistry(registry))
	}

	verifier := verify.NewPacketVerifier(opts...)

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	// Perform verification
	report, err := verifier.Verify(ctx, packet)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Verification error: %v\n", err)
		os.Exit(1)
	}

	// Handle output
	var w io.Writer = os.Stdout
	if *output != "" {
		f, err := os.Create(*output)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating output file: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		w = f
	}

	// Generate report
	if !*quiet {
		generator := verify.NewReportGenerator(format).WithVerbose(*verbose)
		if err := generator.Generate(report, w); err != nil {
			fmt.Fprintf(os.Stderr, "Error generating report: %v\n", err)
			os.Exit(1)
		}
	}

	// Exit code
	if *exitCode && !report.Valid {
		os.Exit(1)
	}
}

// loadPacket loads an evidence packet from a JSON file.
func loadPacket(path string) (*evidence.Packet, error) {
	// Resolve path
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("invalid path: %w", err)
	}

	// Read file
	data, err := os.ReadFile(absPath)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}

	// Decode packet
	packet, err := evidence.Decode(data)
	if err != nil {
		// Try loading as raw JSON
		var rawPacket evidence.Packet
		if jsonErr := json.Unmarshal(data, &rawPacket); jsonErr != nil {
			return nil, fmt.Errorf("decode packet: %w", err)
		}
		return &rawPacket, nil
	}

	return packet, nil
}

// parseLevel parses a verification level string.
func parseLevel(s string) (verify.VerificationLevel, error) {
	switch s {
	case "quick":
		return verify.LevelQuick, nil
	case "standard":
		return verify.LevelStandard, nil
	case "forensic":
		return verify.LevelForensic, nil
	case "paranoid":
		return verify.LevelParanoid, nil
	default:
		return 0, fmt.Errorf("unknown level: %s (use quick, standard, forensic, or paranoid)", s)
	}
}

// parseFormat parses an output format string.
func parseFormat(s string) (verify.ReportFormat, error) {
	switch s {
	case "text":
		return verify.FormatText, nil
	case "json":
		return verify.FormatJSON, nil
	case "markdown", "md":
		return verify.FormatMarkdown, nil
	case "html":
		return verify.FormatHTML, nil
	default:
		return "", fmt.Errorf("unknown format: %s (use text, json, markdown, or html)", s)
	}
}
