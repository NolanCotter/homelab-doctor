package bundle

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/homelab-doctor/homelab-doctor/internal/report"
)

type archiveEntry struct {
	data []byte
	mode os.FileMode
}

func readArchive(t *testing.T, path string) map[string]archiveEntry {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	out := map[string]archiveEntry{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		out[h.Name] = archiveEntry{data: data, mode: h.FileInfo().Mode()}
	}
	return out
}

func TestCreateContainsManifestAndRedacts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "diagnostics.tar.gz")
	r := report.Report{GeneratedAt: time.Now(), ToolVersion: "1.0.0", Findings: []report.Finding{{
		ID: "x", Evidence: []string{"token=abc 10.0.0.1"}, Explanation: "password=hunter2", Remediation: "cookie=xyz",
	}}}
	if err := Create(path, r, true); err != nil {
		t.Fatal(err)
	}
	entries := readArchive(t, path)
	for _, name := range []string{"report.json", "report.md", "manifest.json"} {
		entry, ok := entries[name]
		if !ok {
			t.Fatalf("missing %s", name)
		}
		if entry.mode.Perm() != 0600 {
			t.Errorf("%s mode = %#o", name, entry.mode.Perm())
		}
	}
	all := string(entries["report.json"].data) + string(entries["report.md"].data)
	for _, bad := range []string{"abc", "10.0.0.1", "hunter2", "xyz"} {
		if strings.Contains(all, bad) {
			t.Errorf("archive contains unredacted %q", bad)
		}
	}
	if !strings.Contains(all, "[REDACTED]") || !strings.Contains(all, "[PRIVATE-IP]") {
		t.Errorf("expected redaction markers in archive output")
	}
}

func TestManifestHashesMatchArchiveMembers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "diagnostics.tar.gz")
	r := report.Report{SchemaVersion: "1.0", ToolVersion: "1.0.0", Findings: []report.Finding{{ID: "system.uptime", Evidence: []string{"up"}}}}
	if err := Create(path, r, false); err != nil {
		t.Fatal(err)
	}
	entries := readArchive(t, path)
	var manifest Manifest
	if err := json.Unmarshal(entries["manifest.json"].data, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.SchemaVersion != "1.0" || manifest.GeneratedAt.IsZero() {
		t.Fatalf("bad manifest metadata: %+v", manifest)
	}
	if len(manifest.Files) != 2 {
		t.Fatalf("manifest files = %v", manifest.Files)
	}
	for _, name := range []string{"report.json", "report.md"} {
		sum := sha256.Sum256(entries[name].data)
		if got, want := manifest.Files[name], hex.EncodeToString(sum[:]); got != want {
			t.Errorf("%s hash = %q, want %q", name, got, want)
		}
	}
}

func TestCreateRejectsOutputSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, "link.tar.gz")
	if err := os.WriteFile(target, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skip("symlinks unavailable")
	}
	if err := Create(link, report.Report{}, false); err == nil {
		t.Fatal("expected symlink rejection")
	}
}

func TestCreateRejectsSymlinkedDirectory(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real")
	if err := os.Mkdir(real, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skip("symlinks unavailable")
	}
	if err := Create(filepath.Join(link, "diagnostics.tar.gz"), report.Report{}, false); err == nil {
		t.Fatal("expected symlinked directory rejection")
	}
}

func TestCreateRejectsUnsafeOrExistingOutput(t *testing.T) {
	dir := t.TempDir()
	if err := Create(dir+string(filepath.Separator)+".."+string(filepath.Separator)+"outside.tar.gz", report.Report{}, false); err == nil {
		t.Fatal("expected unsafe path rejection")
	}
	if err := Create("", report.Report{}, false); err == nil {
		t.Fatal("expected empty output rejection")
	}
	if err := Create(".", report.Report{}, false); err == nil {
		t.Fatal("expected dot output rejection")
	}
	path := filepath.Join(dir, "existing.tar.gz")
	if err := os.WriteFile(path, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Create(path, report.Report{}, false); err == nil {
		t.Fatal("expected overwrite rejection")
	}
}

func TestCreateMissingDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "diagnostics.tar.gz")
	if err := Create(path, report.Report{}, false); err == nil {
		t.Fatal("expected missing directory error")
	}
}

func TestSafeName(t *testing.T) {
	for _, name := range []string{"report.json", "report.md", "manifest.json"} {
		if !safeName(name) {
			t.Errorf("safeName(%q) = false", name)
		}
	}
	for _, name := range []string{"", "/report.json", "a/b", "../report.json", "a..b", ".."} {
		if safeName(name) {
			t.Errorf("safeName(%q) = true", name)
		}
	}
}
