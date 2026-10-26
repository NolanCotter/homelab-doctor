package report

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestJSONRoundTrip(t *testing.T) {
	in := Report{
		SchemaVersion: "1.0",
		GeneratedAt:   time.Date(2026, 7, 19, 0, 0, 0, 0, time.UTC),
		ToolVersion:   "1.0.0",
		Findings: []Finding{{
			ID:          "storage.filesystem_capacity",
			Profile:     "storage",
			Status:      StatusFinding,
			Severity:    SeverityWarning,
			Evidence:    []string{"/data free=4%"},
			Explanation: "Filesystem capacity is low.",
			Remediation: "Review capacity before changing anything.",
		}},
	}
	b, err := in.JSON()
	if err != nil {
		t.Fatal(err)
	}
	var out Report
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if out.SchemaVersion != in.SchemaVersion || out.ToolVersion != in.ToolVersion || len(out.Findings) != 1 {
		t.Fatalf("round trip mismatch: %+v", out)
	}
	if out.Findings[0].ID != in.Findings[0].ID || out.Findings[0].Status != StatusFinding {
		t.Fatalf("finding mismatch: %+v", out.Findings[0])
	}
}

func TestMarkdownRendersDetailsAndEscapesPipes(t *testing.T) {
	r := Report{
		GeneratedAt: time.Date(2026, 7, 19, 0, 0, 0, 0, time.UTC),
		Findings: []Finding{{
			ID:          "docker.exposed_ports",
			Status:      StatusFinding,
			Severity:    SeverityWarning,
			Evidence:    []string{"web: 0.0.0.0:8080->80/tcp|other"},
			Explanation: "Published ports expand reachability.",
			Remediation: "Bind to the intended interface.",
		}},
	}
	md := r.Markdown()
	for _, want := range []string{
		"# Homelab Doctor report",
		"Generated: 2026-07-19T00:00:00Z",
		"| `docker.exposed_ports` | finding | warning |",
		`0.0.0.0:8080->80/tcp\|other`,
		"## Details",
		"Published ports expand reachability.",
		"**Safe remediation:** Bind to the intended interface.",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown missing %q:\n%s", want, md)
		}
	}
}

func TestTerminalReportsCountAndFields(t *testing.T) {
	r := Report{Findings: []Finding{
		{ID: "system.uptime", Status: StatusPass, Severity: SeverityInfo, Evidence: []string{"uptime seconds: 10"}},
		{ID: "security.plaintext_compose_password", Status: StatusFinding, Severity: SeverityWarning, Evidence: []string{"compose.yml: DB_PASSWORD=[REDACTED]"}},
	}}
	out := r.Terminal()
	if !strings.Contains(out, "Homelab Doctor — 2 checks") {
		t.Errorf("missing count: %q", out)
	}
	for _, want := range []string{"[PASS]", "[FINDING]", "system.uptime", "security.plaintext_compose_password", "WARNING"} {
		if !strings.Contains(out, want) {
			t.Errorf("terminal output missing %q: %q", want, out)
		}
	}
}

func TestSanitizedReturnsCopyWithoutMutatingOriginal(t *testing.T) {
	r := Report{Findings: []Finding{{
		ID:          "security.plaintext_compose_password",
		Evidence:    []string{"PASSWORD=hunter2 from 10.1.2.3"},
		Explanation: "token: abc",
		Remediation: "cookie=def",
	}}}
	s := r.Sanitized(true)
	if contains(s.Findings[0].Evidence[0], "hunter2") || contains(s.Findings[0].Evidence[0], "10.1.2.3") {
		t.Errorf("sanitized evidence not redacted: %q", s.Findings[0].Evidence[0])
	}
	if contains(s.Findings[0].Explanation, "abc") || contains(s.Findings[0].Remediation, "def") {
		t.Errorf("sanitized text not redacted: %+v", s.Findings[0])
	}
	if r.Findings[0].Evidence[0] != "PASSWORD=hunter2 from 10.1.2.3" {
		t.Errorf("original evidence mutated: %q", r.Findings[0].Evidence[0])
	}
	if r.Findings[0].Explanation != "token: abc" {
		t.Errorf("original explanation mutated: %q", r.Findings[0].Explanation)
	}
}

func TestSanitizedPreservesNilFindings(t *testing.T) {
	r := Report{}
	s := r.Sanitized(false)
	if s.Findings != nil {
		t.Fatalf("nil findings became %#v", s.Findings)
	}
}
