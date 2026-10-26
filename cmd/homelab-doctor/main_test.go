package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/homelab-doctor/homelab-doctor/internal/checks"
	"github.com/homelab-doctor/homelab-doctor/internal/report"
)

func runCLI(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func TestRunUsageAndUnknownCommands(t *testing.T) {
	code, _, stderr := runCLI(t)
	if code != 2 || !strings.Contains(stderr, "Usage: homelab-doctor") {
		t.Fatalf("no args: code=%d stderr=%q", code, stderr)
	}
	code, _, stderr = runCLI(t, "nope")
	if code != 2 || !strings.Contains(stderr, "Usage: homelab-doctor") {
		t.Fatalf("unknown command: code=%d stderr=%q", code, stderr)
	}
}

func TestVersion(t *testing.T) {
	for _, command := range []string{"version", "--version", "-version"} {
		code, stdout, _ := runCLI(t, command)
		if code != 0 || strings.TrimSpace(stdout) != version {
			t.Errorf("%s: code=%d stdout=%q", command, code, stdout)
		}
	}
	code, stdout, stderr := runCLI(t, "version", "--dry-run")
	if code != 0 || strings.TrimSpace(stdout) != version || !strings.Contains(stderr, "dry-run") {
		t.Errorf("version --dry-run: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestListChecks(t *testing.T) {
	code, stdout, stderr := runCLI(t, "list-checks", "--dry-run")
	if code != 0 || !strings.Contains(stderr, "dry-run") {
		t.Fatalf("code=%d stderr=%q", code, stderr)
	}
	lines := strings.Fields(stdout)
	if len(lines) != len(checks.IDs()) {
		t.Fatalf("got %d IDs, want %d", len(lines), len(checks.IDs()))
	}
	if lines[0] != checks.IDs()[0] || lines[len(lines)-1] != checks.IDs()[len(checks.IDs())-1] {
		t.Errorf("unexpected catalog order: first=%q last=%q", lines[0], lines[len(lines)-1])
	}
	if code, _, _ := runCLI(t, "list-checks", "extra"); code != 2 {
		t.Errorf("extra argument: code=%d", code)
	}
}

func TestExplain(t *testing.T) {
	code, stdout, _ := runCLI(t, "explain", "docker.restart_loop")
	if code != 0 || !strings.Contains(stdout, "docker.restart_loop") || !strings.Contains(stdout, "Safe remediation:") {
		t.Fatalf("code=%d stdout=%q", code, stdout)
	}
	code, stdout, stderr := runCLI(t, "explain", "--dry-run", "docker.restart_loop")
	if code != 0 || !strings.Contains(stdout, "docker.restart_loop") || !strings.Contains(stderr, "dry-run") {
		t.Fatalf("dry run: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	for _, args := range [][]string{{"explain"}, {"explain", "unknown.check"}, {"explain", "one", "two"}} {
		if code, _, _ := runCLI(t, args...); code != 2 {
			t.Errorf("%v: code=%d", args, code)
		}
	}
}

func TestCheckRejectsInvalidFlags(t *testing.T) {
	for _, args := range [][]string{
		{"check", "--profile", "bogus"},
		{"check", "--format", "yaml"},
		{"check", "extra"},
		{"check", "--not-a-flag"},
	} {
		if code, _, _ := runCLI(t, args...); code != 2 {
			t.Errorf("%v: code=%d", args, code)
		}
	}
	code, _, _ := runCLI(t, "check", "-h")
	if code != 0 {
		t.Errorf("check -h: code=%d", code)
	}
}

func TestCheckFormats(t *testing.T) {
	code, stdout, _ := runCLI(t, "check", "--profile", "networking", "--dry-run")
	if code != 0 || !strings.Contains(stdout, "Homelab Doctor —") {
		t.Fatalf("terminal: code=%d stdout=%q", code, stdout)
	}

	code, stdout, _ = runCLI(t, "check", "--profile", "networking", "--format", "json")
	if code != 0 {
		t.Fatalf("json: code=%d", code)
	}
	var r report.Report
	if err := json.Unmarshal([]byte(stdout), &r); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, stdout)
	}
	if r.SchemaVersion != "1.0" || r.ToolVersion != version || len(r.Findings) == 0 {
		t.Errorf("bad report: %+v", r)
	}

	code, stdout, _ = runCLI(t, "check", "--profile", "networking", "--format", "markdown")
	if code != 0 || !strings.HasPrefix(stdout, "# Homelab Doctor report") {
		t.Fatalf("markdown: code=%d stdout=%q", code, stdout)
	}
}

func TestCheckProfileAll(t *testing.T) {
	code, stdout, _ := runCLI(t, "check", "--profile", "all", "--format", "json")
	if code != 0 {
		t.Fatalf("code=%d", code)
	}
	var r report.Report
	if err := json.Unmarshal([]byte(stdout), &r); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, f := range r.Findings {
		seen[f.ID] = true
	}
	for _, id := range checks.IDs() {
		if !seen[id] {
			t.Errorf("all profile missing %s", id)
		}
	}
}

func TestBundleDryRunAndErrors(t *testing.T) {
	dir := t.TempDir()
	output := filepath.Join(dir, "diagnostics.tar.gz")
	code, stdout, _ := runCLI(t, "bundle", "--dry-run", "--output", output)
	if code != 0 || !strings.Contains(stdout, "would write "+output) {
		t.Fatalf("dry run: code=%d stdout=%q", code, stdout)
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatalf("dry run wrote output")
	}
	for _, args := range [][]string{
		{"bundle", "--privacy", "bogus"},
		{"bundle", "extra"},
		{"bundle", "--output", filepath.Join(dir, "missing", "diagnostics.tar.gz")},
	} {
		if code, _, _ := runCLI(t, args...); code != 2 {
			t.Errorf("%v: code=%d", args, code)
		}
	}
}

func TestRenderRejectsUnknownFormat(t *testing.T) {
	var out bytes.Buffer
	if err := render(report.Report{}, "xml", &out); err == nil {
		t.Fatal("expected error")
	}
}

func TestParseResult(t *testing.T) {
	if got := parseResult(flag.ErrHelp); got != 0 {
		t.Errorf("help = %d", got)
	}
	if got := parseResult(os.ErrNotExist); got != 2 {
		t.Errorf("error = %d", got)
	}
}
