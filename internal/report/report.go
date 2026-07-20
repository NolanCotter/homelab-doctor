// Package report defines portable, redacted diagnostic reports and renderers.
package report

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityCritical Severity = "critical"
)

type Status string

const (
	StatusPass    Status = "pass"
	StatusFinding Status = "finding"
	StatusSkipped Status = "skipped"
)

// Finding has stable machine-readable identity and human-safe remediation text.
type Finding struct {
	ID          string   `json:"id"`
	Profile     string   `json:"profile"`
	Status      Status   `json:"status"`
	Severity    Severity `json:"severity"`
	Evidence    []string `json:"evidence"`
	Explanation string   `json:"explanation"`
	Remediation string   `json:"remediation"`
}

type Report struct {
	SchemaVersion string    `json:"schema_version"`
	GeneratedAt   time.Time `json:"generated_at"`
	ToolVersion   string    `json:"tool_version"`
	Findings      []Finding `json:"findings"`
}

func (r Report) JSON() ([]byte, error) { return json.MarshalIndent(r, "", "  ") }

func (r Report) Markdown() string {
	var b strings.Builder
	b.WriteString("# Homelab Doctor report\n\n")
	fmt.Fprintf(&b, "Generated: %s  \n\n", r.GeneratedAt.UTC().Format(time.RFC3339))
	b.WriteString("| ID | Status | Severity | Evidence |\n|---|---|---|---|\n")
	for _, f := range r.Findings {
		fmt.Fprintf(&b, "| `%s` | %s | %s | %s |\n", f.ID, f.Status, f.Severity, strings.ReplaceAll(strings.Join(f.Evidence, "; "), "|", "\\|"))
	}
	b.WriteString("\n## Details\n")
	for _, f := range r.Findings {
		fmt.Fprintf(&b, "\n### %s\n\n%s\n\n**Safe remediation:** %s\n", f.ID, f.Explanation, f.Remediation)
	}
	return b.String()
}

func (r Report) Terminal() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Homelab Doctor — %d checks\n", len(r.Findings))
	for _, f := range r.Findings {
		fmt.Fprintf(&b, "[%s] %-30s %-8s %s\n", strings.ToUpper(string(f.Status)), f.ID, strings.ToUpper(string(f.Severity)), strings.Join(f.Evidence, "; "))
	}
	return b.String()
}

// Sanitized returns a copy suitable for display or sharing.
func (r Report) Sanitized(privateIPs bool) Report {
	for i := range r.Findings {
		r.Findings[i].Evidence = RedactLines(r.Findings[i].Evidence, privateIPs)
		r.Findings[i].Explanation = Redact(r.Findings[i].Explanation, privateIPs)
		r.Findings[i].Remediation = Redact(r.Findings[i].Remediation, privateIPs)
	}
	return r
}
