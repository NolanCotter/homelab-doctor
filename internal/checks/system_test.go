package checks

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/homelab-doctor/homelab-doctor/internal/report"
)

func writeRootFile(t *testing.T, root, name, content string) {
	t.Helper()
	path := filepath.Join(root, strings.TrimPrefix(name, "/"))
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestSystemReadsHostFilesAndFlagsPressure(t *testing.T) {
	root := t.TempDir()
	writeRootFile(t, root, "/proc/version", "Linux version 6.1.0-test (builder@example) #1\n")
	writeRootFile(t, root, "/etc/os-release", "NAME=\"Example Linux\"\nPRETTY_NAME=\"Example Linux 1.0\"\n")
	writeRootFile(t, root, "/proc/uptime", "123.45 100.00\n")
	writeRootFile(t, root, "/proc/meminfo", "MemTotal:       100000 kB\nMemAvailable:     5000 kB\n")
	writeRootFile(t, root, "/proc/loadavg", "100.00 1.00 1.00 1/10 123\n")
	r := fakeRunner{
		"systemctl --failed --no-legend --plain":      {Stdout: "broken.service loaded failed failed Broken\n"},
		"timedatectl show -p NTPSynchronized --value": {Stdout: "no\n"},
	}
	fs := system(context.Background(), Config{Root: root, Runner: r})

	dist := find(fs, "system.distribution_kernel")
	if dist.Status != report.StatusPass || len(dist.Evidence) != 2 || dist.Evidence[0] != "Example Linux 1.0" {
		t.Errorf("distribution = %+v", dist)
	}
	if f := find(fs, "system.uptime"); f.Status != report.StatusPass || !strings.Contains(f.Evidence[0], "123.45") {
		t.Errorf("uptime = %+v", f)
	}
	if f := find(fs, "system.memory_pressure"); f.Status != report.StatusFinding || f.Severity != report.SeverityWarning {
		t.Errorf("memory = %+v", f)
	}
	if f := find(fs, "system.load_average"); f.Status != report.StatusFinding {
		t.Errorf("load = %+v", f)
	}
	if f := find(fs, "system.failed_units"); f.Status != report.StatusFinding || len(f.Evidence) != 1 {
		t.Errorf("failed units = %+v", f)
	}
	if f := find(fs, "system.clock_synchronization"); f.Status != report.StatusFinding {
		t.Errorf("clock = %+v", f)
	}
}

func TestSystemHealthyHostPasses(t *testing.T) {
	root := t.TempDir()
	writeRootFile(t, root, "/proc/version", "Linux version 6.1.0-test\n")
	writeRootFile(t, root, "/etc/os-release", "PRETTY_NAME=\"Example Linux\"\n")
	writeRootFile(t, root, "/proc/uptime", "999 100\n")
	writeRootFile(t, root, "/proc/meminfo", "MemTotal: 100000 kB\nMemAvailable: 90000 kB\n")
	writeRootFile(t, root, "/proc/loadavg", "0.10 0.20 0.30 1/10 1\n")
	r := fakeRunner{
		"systemctl --failed --no-legend --plain":      {Stdout: ""},
		"timedatectl show -p NTPSynchronized --value": {Stdout: "yes\n"},
	}
	fs := system(context.Background(), Config{Root: root, Runner: r})
	for _, id := range []string{"system.distribution_kernel", "system.uptime", "system.memory_pressure", "system.load_average", "system.failed_units", "system.clock_synchronization"} {
		if f := find(fs, id); f.Status != report.StatusPass {
			t.Errorf("%s = %s (%+v)", id, f.Status, f)
		}
	}
}

func TestSystemMissingInputsAreSkipped(t *testing.T) {
	fs := system(context.Background(), Config{Root: t.TempDir(), Runner: fakeRunner{}})
	if len(fs) != 6 {
		t.Fatalf("got %d findings", len(fs))
	}
	for _, f := range fs {
		if f.Status != report.StatusSkipped {
			t.Errorf("%s = %s, want skipped", f.ID, f.Status)
		}
	}
}

func TestSystemEmptyUptimeIsSkipped(t *testing.T) {
	root := t.TempDir()
	writeRootFile(t, root, "/proc/uptime", "\n")
	fs := system(context.Background(), Config{Root: root, Runner: fakeRunner{}})
	if f := find(fs, "system.uptime"); f.Status != report.StatusSkipped {
		t.Fatalf("uptime = %+v", f)
	}
}
