// Package verify provides verification report generation.
package verify

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/template"
	"time"
)

// ReportFormat specifies the output format for verification reports.
type ReportFormat string

const (
	FormatJSON     ReportFormat = "json"
	FormatText     ReportFormat = "text"
	FormatMarkdown ReportFormat = "markdown"
	FormatHTML     ReportFormat = "html"
)

// ReportGenerator generates verification reports in various formats.
type ReportGenerator struct {
	format   ReportFormat
	verbose  bool
	showPath bool
}

// NewReportGenerator creates a new report generator.
func NewReportGenerator(format ReportFormat) *ReportGenerator {
	return &ReportGenerator{
		format:  format,
		verbose: false,
	}
}

// WithVerbose enables verbose output.
func (g *ReportGenerator) WithVerbose(verbose bool) *ReportGenerator {
	g.verbose = verbose
	return g
}

// WithPathDetails enables detailed path validation in output.
func (g *ReportGenerator) WithPathDetails(show bool) *ReportGenerator {
	g.showPath = show
	return g
}

// Generate produces a report in the configured format.
func (g *ReportGenerator) Generate(report *VerificationReport, w io.Writer) error {
	switch g.format {
	case FormatJSON:
		return g.generateJSON(report, w)
	case FormatText:
		return g.generateText(report, w)
	case FormatMarkdown:
		return g.generateMarkdown(report, w)
	case FormatHTML:
		return g.generateHTML(report, w)
	default:
		return fmt.Errorf("unknown format: %s", g.format)
	}
}

// generateJSON outputs the report as JSON.
func (g *ReportGenerator) generateJSON(report *VerificationReport, w io.Writer) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

// generateText outputs the report as plain text.
func (g *ReportGenerator) generateText(report *VerificationReport, w io.Writer) error {
	// Header
	fmt.Fprintln(w, "================================================================================")
	fmt.Fprintln(w, "                    WITNESSD EVIDENCE VERIFICATION REPORT")
	fmt.Fprintln(w, "================================================================================")
	fmt.Fprintln(w)

	// Summary
	fmt.Fprintf(w, "Result:          %s\n", g.resultString(report.Valid))
	fmt.Fprintf(w, "Evidence Class:  %s (%s)\n", report.EvidenceClass, report.ClassReason)
	fmt.Fprintf(w, "Confidence:      %.1f%%\n", report.Confidence*100)
	fmt.Fprintf(w, "Verification:    %s level\n", report.Level.String())
	fmt.Fprintf(w, "Duration:        %v\n", report.Duration.Round(time.Millisecond))
	fmt.Fprintln(w)

	// Document info
	fmt.Fprintln(w, "--- Document Information ---")
	fmt.Fprintf(w, "Title:           %s\n", report.DocumentTitle)
	fmt.Fprintf(w, "Document Hash:   %s\n", g.truncateHash(report.DocumentHash))
	fmt.Fprintf(w, "Chain Hash:      %s\n", g.truncateHash(report.ChainHash))
	fmt.Fprintf(w, "Strength:        %s\n", report.Strength)
	fmt.Fprintf(w, "Packet Version:  %d\n", report.PacketVersion)
	fmt.Fprintf(w, "Exported:        %s\n", report.ExportedAt.Format(time.RFC3339))
	fmt.Fprintln(w)

	// Component results
	fmt.Fprintln(w, "--- Component Verification ---")
	for _, comp := range report.Components {
		status := g.statusSymbol(comp.Status)
		fmt.Fprintf(w, "[%s] %-24s %s\n", status, comp.Component, comp.Message)
		if g.verbose && comp.Error != "" {
			fmt.Fprintf(w, "    Error: %s\n", comp.Error)
		}
		if g.verbose && comp.Remediation != "" {
			fmt.Fprintf(w, "    Fix: %s\n", comp.Remediation)
		}
	}
	fmt.Fprintln(w)

	// Summary counts
	fmt.Fprintln(w, "--- Summary ---")
	fmt.Fprintf(w, "Passed:   %d\n", report.Passed)
	fmt.Fprintf(w, "Failed:   %d\n", report.Failed)
	fmt.Fprintf(w, "Warnings: %d\n", report.Warnings)
	fmt.Fprintf(w, "Skipped:  %d\n", report.Skipped)
	fmt.Fprintln(w)

	// Tamper indicators
	if len(report.TamperIndicators) > 0 {
		fmt.Fprintln(w, "--- Tamper Indicators ---")
		for _, indicator := range report.TamperIndicators {
			fmt.Fprintf(w, "  * %s\n", indicator)
		}
		fmt.Fprintln(w)
	}

	// Recommendations
	if len(report.Recommendations) > 0 {
		fmt.Fprintln(w, "--- Recommendations ---")
		for _, rec := range report.Recommendations {
			fmt.Fprintf(w, "  * %s\n", rec)
		}
		fmt.Fprintln(w)
	}

	fmt.Fprintln(w, "================================================================================")
	return nil
}

// generateMarkdown outputs the report as Markdown.
func (g *ReportGenerator) generateMarkdown(report *VerificationReport, w io.Writer) error {
	tmpl := `# Witnessd Evidence Verification Report

## Summary

| Property | Value |
|----------|-------|
| **Result** | {{.ResultString}} |
| **Evidence Class** | {{.EvidenceClass}} ({{.ClassReason}}) |
| **Confidence** | {{printf "%.1f%%" (mult .Confidence 100)}} |
| **Verification Level** | {{.Level}} |
| **Duration** | {{.Duration}} |

## Document Information

| Property | Value |
|----------|-------|
| Title | {{.DocumentTitle}} |
| Document Hash | ` + "`{{.DocumentHash}}`" + ` |
| Chain Hash | ` + "`{{.ChainHash}}`" + ` |
| Strength | {{.Strength}} |
| Packet Version | {{.PacketVersion}} |
| Exported | {{.ExportedAt}} |

## Component Verification

| Component | Status | Message |
|-----------|--------|---------|
{{range .Components}}`

	tmpl += "| {{.Component}} | {{statusEmoji .Status}} | {{.Message}} |\n{{end}}"

	tmpl += `

## Summary Counts

- **Passed:** {{.Passed}}
- **Failed:** {{.Failed}}
- **Warnings:** {{.Warnings}}
- **Skipped:** {{.Skipped}}

{{if .TamperIndicators}}
## Tamper Indicators

{{range .TamperIndicators}}- {{.}}
{{end}}
{{end}}

{{if .Recommendations}}
## Recommendations

{{range .Recommendations}}- {{.}}
{{end}}
{{end}}

---
*Report generated at {{.CompletedAt}}*
`

	funcMap := template.FuncMap{
		"mult": func(a, b float64) float64 { return a * b },
		"statusEmoji": func(s ComponentStatus) string {
			switch s {
			case StatusPassed:
				return "PASS"
			case StatusFailed:
				return "FAIL"
			case StatusWarning:
				return "WARN"
			case StatusSkipped:
				return "SKIP"
			default:
				return "?"
			}
		},
	}

	t, err := template.New("report").Funcs(funcMap).Parse(tmpl)
	if err != nil {
		return err
	}

	// Create a view struct with computed fields
	view := struct {
		*VerificationReport
		ResultString string
	}{
		VerificationReport: report,
		ResultString:       g.resultString(report.Valid),
	}

	return t.Execute(w, view)
}

// generateHTML outputs the report as HTML.
func (g *ReportGenerator) generateHTML(report *VerificationReport, w io.Writer) error {
	tmpl := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Witnessd Verification Report</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 900px; margin: 0 auto; padding: 20px; }
        h1 { color: #333; }
        .result-valid { color: #28a745; }
        .result-invalid { color: #dc3545; }
        .summary { background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 20px 0; }
        table { width: 100%; border-collapse: collapse; margin: 15px 0; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #f8f9fa; }
        .status-passed { color: #28a745; }
        .status-failed { color: #dc3545; }
        .status-warning { color: #ffc107; }
        .status-skipped { color: #6c757d; }
        .class-A { background: #28a745; color: white; padding: 2px 8px; border-radius: 3px; }
        .class-B { background: #17a2b8; color: white; padding: 2px 8px; border-radius: 3px; }
        .class-C { background: #ffc107; color: black; padding: 2px 8px; border-radius: 3px; }
        .class-D { background: #dc3545; color: white; padding: 2px 8px; border-radius: 3px; }
        .class-X { background: #343a40; color: white; padding: 2px 8px; border-radius: 3px; }
        .indicators { background: #fff3cd; padding: 15px; border-radius: 5px; margin: 15px 0; }
        .recommendations { background: #d1ecf1; padding: 15px; border-radius: 5px; margin: 15px 0; }
        code { background: #e9ecef; padding: 2px 6px; border-radius: 3px; font-family: 'Courier New', monospace; }
    </style>
</head>
<body>
    <h1>Witnessd Evidence Verification Report</h1>

    <div class="summary">
        <h2>Result: <span class="{{if .Valid}}result-valid{{else}}result-invalid{{end}}">{{if .Valid}}VALID{{else}}INVALID{{end}}</span></h2>
        <p><strong>Evidence Class:</strong> <span class="class-{{.EvidenceClass}}">{{.EvidenceClass}}</span> - {{.ClassReason}}</p>
        <p><strong>Confidence:</strong> {{printf "%.1f%%" (mult .Confidence 100)}}</p>
        <p><strong>Verification Level:</strong> {{.Level}}</p>
        <p><strong>Duration:</strong> {{.Duration}}</p>
    </div>

    <h2>Document Information</h2>
    <table>
        <tr><th>Title</th><td>{{.DocumentTitle}}</td></tr>
        <tr><th>Document Hash</th><td><code>{{.DocumentHash}}</code></td></tr>
        <tr><th>Chain Hash</th><td><code>{{.ChainHash}}</code></td></tr>
        <tr><th>Strength</th><td>{{.Strength}}</td></tr>
        <tr><th>Packet Version</th><td>{{.PacketVersion}}</td></tr>
        <tr><th>Exported</th><td>{{.ExportedAt}}</td></tr>
    </table>

    <h2>Component Verification</h2>
    <table>
        <thead>
            <tr><th>Component</th><th>Status</th><th>Message</th><th>Duration</th></tr>
        </thead>
        <tbody>
            {{range .Components}}
            <tr>
                <td>{{.Component}}</td>
                <td class="status-{{.Status}}">{{.Status}}</td>
                <td>{{.Message}}{{if .Error}}<br><small style="color:#dc3545">{{.Error}}</small>{{end}}</td>
                <td>{{.Duration}}</td>
            </tr>
            {{end}}
        </tbody>
    </table>

    <h2>Summary</h2>
    <table>
        <tr><td>Passed</td><td>{{.Passed}}</td></tr>
        <tr><td>Failed</td><td>{{.Failed}}</td></tr>
        <tr><td>Warnings</td><td>{{.Warnings}}</td></tr>
        <tr><td>Skipped</td><td>{{.Skipped}}</td></tr>
    </table>

    {{if .TamperIndicators}}
    <div class="indicators">
        <h3>Tamper Indicators</h3>
        <ul>
            {{range .TamperIndicators}}<li>{{.}}</li>{{end}}
        </ul>
    </div>
    {{end}}

    {{if .Recommendations}}
    <div class="recommendations">
        <h3>Recommendations</h3>
        <ul>
            {{range .Recommendations}}<li>{{.}}</li>{{end}}
        </ul>
    </div>
    {{end}}

    <footer style="margin-top: 30px; padding-top: 15px; border-top: 1px solid #ddd; color: #6c757d;">
        Report generated at {{.CompletedAt}}
    </footer>
</body>
</html>`

	funcMap := template.FuncMap{
		"mult": func(a, b float64) float64 { return a * b },
	}

	t, err := template.New("report").Funcs(funcMap).Parse(tmpl)
	if err != nil {
		return err
	}

	return t.Execute(w, report)
}

// Helper functions

func (g *ReportGenerator) resultString(valid bool) string {
	if valid {
		return "VALID"
	}
	return "INVALID"
}

func (g *ReportGenerator) statusSymbol(status ComponentStatus) string {
	switch status {
	case StatusPassed:
		return "OK"
	case StatusFailed:
		return "!!"
	case StatusWarning:
		return "??"
	case StatusSkipped:
		return "--"
	case StatusPending:
		return ".."
	default:
		return "  "
	}
}

func (g *ReportGenerator) truncateHash(hash string) string {
	if len(hash) <= 16 {
		return hash
	}
	if g.verbose {
		return hash
	}
	return hash[:8] + "..." + hash[len(hash)-8:]
}

// Summary generates a one-line summary of the report.
func (report *VerificationReport) Summary() string {
	var sb strings.Builder

	if report.Valid {
		sb.WriteString("[VALID]")
	} else {
		sb.WriteString("[INVALID]")
	}

	sb.WriteString(fmt.Sprintf(" Class %s", report.EvidenceClass))
	sb.WriteString(fmt.Sprintf(" (%.0f%% confidence)", report.Confidence*100))
	sb.WriteString(fmt.Sprintf(" - %d/%d checks passed",
		report.Passed, report.Passed+report.Failed+report.Warnings))

	if report.Failed > 0 {
		sb.WriteString(fmt.Sprintf(", %d failed", report.Failed))
	}
	if report.Warnings > 0 {
		sb.WriteString(fmt.Sprintf(", %d warnings", report.Warnings))
	}

	return sb.String()
}

// IsForensicReady returns true if the evidence is suitable for forensic use.
func (report *VerificationReport) IsForensicReady() bool {
	return report.Valid && (report.EvidenceClass == "A" || report.EvidenceClass == "B")
}

// FailedComponents returns the list of failed component names.
func (report *VerificationReport) FailedComponents() []string {
	var failed []string
	for _, comp := range report.Components {
		if comp.Status == StatusFailed {
			failed = append(failed, comp.Component)
		}
	}
	return failed
}

// WarningComponents returns the list of components with warnings.
func (report *VerificationReport) WarningComponents() []string {
	var warnings []string
	for _, comp := range report.Components {
		if comp.Status == StatusWarning {
			warnings = append(warnings, comp.Component)
		}
	}
	return warnings
}
