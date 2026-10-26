package checks

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/homelab-doctor/homelab-doctor/internal/execx"
	"github.com/homelab-doctor/homelab-doctor/internal/report"
)

func TestRunProfilesAndCatalogCoverage(t *testing.T) {
	root := t.TempDir()
	cfg := Config{Root: root, Runner: fakeRunner{}, ComposeRoots: []string{root}, DockerDataRoot: "/var/lib/docker"}
	all := Run(context.Background(), "", cfg)
	if len(all) != len(IDs()) {
		t.Fatalf("default run returned %d checks, catalog has %d", len(all), len(IDs()))
	}
	seen := map[string]bool{}
	for _, f := range all {
		seen[f.ID] = true
	}
	for _, id := range IDs() {
		if !seen[id] {
			t.Errorf("default run missing %s", id)
		}
	}
	again := Run(context.Background(), "all", cfg)
	if len(again) != len(all) {
		t.Errorf("--profile all returned %d checks, want %d", len(again), len(all))
	}
	for _, profile := range []string{"system", "docker", "storage", "networking"} {
		for _, f := range Run(context.Background(), profile, cfg) {
			switch profile {
			case "system":
				if !strings.HasPrefix(f.ID, "system.") && !strings.HasPrefix(f.ID, "security.") {
					t.Errorf("system profile returned %s", f.ID)
				}
			case "docker":
				if !strings.HasPrefix(f.ID, "docker.") && f.ID != "security.plaintext_compose_password" {
					t.Errorf("docker profile returned %s", f.ID)
				}
			case "networking":
				if !strings.HasPrefix(f.ID, "network.") {
					t.Errorf("networking profile returned %s", f.ID)
				}
			default:
				if !strings.HasPrefix(f.ID, profile+".") {
					t.Errorf("%s profile returned %s", profile, f.ID)
				}
			}
		}
	}
}

func TestCatalogEntriesAreUniqueAndSpecific(t *testing.T) {
	seen := map[string]bool{}
	for _, id := range IDs() {
		if seen[id] {
			t.Fatalf("duplicate %s", id)
		}
		seen[id] = true
		f, ok := Explain(id)
		if !ok {
			t.Fatalf("not explainable: %s", id)
		}
		if f.ID != id || f.Status != report.StatusPass {
			t.Errorf("bad explain result for %s: %+v", id, f)
		}
		if f.Profile != strings.Split(id, ".")[0] {
			t.Errorf("%s profile = %q", id, f.Profile)
		}
		if f.Explanation == "" || f.Remediation == "" {
			t.Errorf("%s has empty explanation or remediation", id)
		}
		if strings.Contains(f.Explanation, "This read-only diagnostic identifies") {
			t.Errorf("%s uses the generic catalog placeholder", id)
		}
	}
	if _, ok := Explain("not.a.check"); ok {
		t.Fatal("unknown ID was explainable")
	}
}

func TestWalkLimitedStopsAtEntryLimit(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < 20; i++ {
		if err := os.WriteFile(filepath.Join(root, "f"+string(rune('a'+i))), []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	visited := 0
	if err := walkLimited(root, 3, func(string, os.DirEntry) error {
		visited++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if visited > 3 {
		t.Fatalf("visited %d entries with limit 3", visited)
	}
}

func TestWalkLimitedDoesNotFollowSymlinks(t *testing.T) {
	root := t.TempDir()
	external := t.TempDir()
	if err := os.WriteFile(filepath.Join(external, "secret"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, filepath.Join(root, "link")); err != nil {
		t.Skip("symlinks unavailable")
	}
	if err := os.WriteFile(filepath.Join(root, "regular"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	var paths []string
	if err := walkLimited(root, 100, func(path string, _ os.DirEntry) error {
		paths = append(paths, path)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		if strings.Contains(path, "secret") {
			t.Fatalf("walk followed symlink to %s", path)
		}
	}
}

func TestDirSizeDoesNotFollowSymlinks(t *testing.T) {
	root := t.TempDir()
	external := t.TempDir()
	if err := os.WriteFile(filepath.Join(external, "large"), make([]byte, 4096), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "small"), []byte("abc"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(external, "large"), filepath.Join(root, "link")); err != nil {
		t.Skip("symlinks unavailable")
	}
	size, err := dirSize(root, 100)
	if err != nil {
		t.Fatal(err)
	}
	if size != 3 {
		t.Fatalf("dirSize followed symlink: got %d, want 3", size)
	}
}

func TestOsReleaseName(t *testing.T) {
	tests := map[string]string{
		"NAME=\"Example Linux\"\nPRETTY_NAME=\"Example Linux 1.0\"\n": "Example Linux 1.0",
		"NAME=Example Linux\n":                "Example Linux",
		"VERSION_ID=1\n":                      "distribution unavailable",
		"":                                    "distribution unavailable",
		"PRETTY_NAME=\"\"\nNAME='Fallback'\n": "Fallback",
	}
	for in, want := range tests {
		if got := osReleaseName(in); got != want {
			t.Errorf("osReleaseName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestHelpers(t *testing.T) {
	if got := firstLine(""); got != "unavailable" {
		t.Errorf("firstLine empty = %q", got)
	}
	if got := firstLine("  one  \n two \n"); got != "one" {
		t.Errorf("firstLine = %q", got)
	}
	if got := nonEmpty("\n a \n\n b\n"); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Errorf("nonEmpty = %#v", got)
	}
	if got := linesOr(nil, "fallback"); len(got) != 1 || got[0] != "fallback" {
		t.Errorf("linesOr = %#v", got)
	}
	if got := linesOr([]string{"x"}, "fallback"); len(got) != 1 || got[0] != "x" {
		t.Errorf("linesOr non-empty = %#v", got)
	}
	if got := commandUnavailable(execx.Result{}); got != "" {
		t.Errorf("commandUnavailable success = %q", got)
	}
	if got := commandUnavailable(execx.Result{Err: context.Canceled}); !strings.Contains(got, "canceled") {
		t.Errorf("commandUnavailable = %q", got)
	}
}
