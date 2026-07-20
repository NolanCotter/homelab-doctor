package bundle

import (
	"archive/tar"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/homelab-doctor/homelab-doctor/internal/report"
)

func TestCreateContainsManifestAndRedacts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "diagnostics.tar.gz")
	r := report.Report{GeneratedAt: time.Now(), Findings: []report.Finding{{ID: "x", Evidence: []string{"token=abc 10.0.0.1"}}}}
	if err := Create(path, r, true); err != nil {
		t.Fatal(err)
	}
	f, e := os.Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	gz, e := gzip.NewReader(f)
	if e != nil {
		t.Fatal(e)
	}
	tr := tar.NewReader(gz)
	seen := map[string]bool{}
	for {
		h, e := tr.Next()
		if e != nil {
			break
		}
		seen[h.Name] = true
	}
	for _, n := range []string{"report.json", "report.md", "manifest.json"} {
		if !seen[n] {
			t.Errorf("missing %s", n)
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

func TestCreateRejectsUnsafeOrExistingOutput(t *testing.T) {
	dir := t.TempDir()
	if err := Create(dir+string(filepath.Separator)+".."+string(filepath.Separator)+"outside.tar.gz", report.Report{}, false); err == nil {
		t.Fatal("expected unsafe path rejection")
	}
	path := filepath.Join(dir, "existing.tar.gz")
	if err := os.WriteFile(path, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Create(path, report.Report{}, false); err == nil {
		t.Fatal("expected overwrite rejection")
	}
}
