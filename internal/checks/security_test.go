package checks

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/homelab-doctor/homelab-doctor/internal/report"
)

func TestSecurityFlagsUnsafePermissionsAndPublicListeners(t *testing.T) {
	root := t.TempDir()
	socket := filepath.Join(root, "var/run/docker.sock")
	if err := os.MkdirAll(filepath.Dir(socket), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(socket, nil, 0666); err != nil {
		t.Fatal(err)
	}
	writeRootFile(t, root, "/.env", "PASSWORD=secret\n")
	writeRootFile(t, root, "/id_rsa", "private\n")
	writeRootFile(t, root, "/id_rsa.pub", "public\n")
	writeRootFile(t, root, "/server.pem", "private\n")
	writeRootFile(t, root, "/other.key", "private\n")
	if err := os.Chmod(filepath.Join(root, ".env"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(root, "id_rsa"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(root, "id_rsa.pub"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(root, "other.key"), 0644); err != nil {
		t.Fatal(err)
	}
	r := fakeRunner{"ss -ltnH": {Stdout: "LISTEN 0 4096 0.0.0.0:22 0.0.0.0:*\nLISTEN 0 4096 127.0.0.1:8080 0.0.0.0:*\n"}}
	fs := security(context.Background(), Config{Root: root, Runner: r, ComposeRoots: []string{root}})

	if f := find(fs, "security.docker_socket_exposure"); f.Status != report.StatusFinding || f.Severity != report.SeverityCritical {
		t.Errorf("socket = %+v", f)
	}
	env := find(fs, "security.world_readable_env")
	if env.Status != report.StatusFinding || !strings.Contains(env.Evidence[0], ".env") {
		t.Errorf("env = %+v", env)
	}
	keys := find(fs, "security.private_key_permissions")
	if keys.Status != report.StatusFinding {
		t.Errorf("keys = %+v", keys)
	}
	joined := strings.Join(keys.Evidence, ";")
	if !strings.Contains(joined, "id_rsa") || !strings.Contains(joined, "other.key") {
		t.Errorf("missing private keys in %q", joined)
	}
	if strings.Contains(joined, "id_rsa.pub") || strings.Contains(joined, "server.pem") {
		t.Errorf("flagged public key or already-private file: %q", joined)
	}
	if f := find(fs, "security.service_all_interfaces"); f.Status != report.StatusFinding || len(f.Evidence) != 1 || f.Evidence[0] != "0.0.0.0:22" {
		t.Errorf("public listeners = %+v", f)
	}
}

func TestSecuritySafePermissionsAndUnavailableData(t *testing.T) {
	root := t.TempDir()
	writeRootFile(t, root, "/.env", "PASSWORD=secret\n")
	writeRootFile(t, root, "/id_rsa", "private\n")
	if err := os.Chmod(filepath.Join(root, ".env"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(root, "id_rsa"), 0600); err != nil {
		t.Fatal(err)
	}
	r := fakeRunner{"ss -ltnH": {Stdout: ""}}
	fs := security(context.Background(), Config{Root: root, Runner: r, ComposeRoots: []string{root}})
	if f := find(fs, "security.world_readable_env"); f.Status != report.StatusPass {
		t.Errorf("env = %+v", f)
	}
	if f := find(fs, "security.private_key_permissions"); f.Status != report.StatusPass {
		t.Errorf("keys = %+v", f)
	}
	if f := find(fs, "security.service_all_interfaces"); f.Status != report.StatusPass {
		t.Errorf("listeners = %+v", f)
	}
	if f := find(fs, "security.docker_socket_exposure"); f.Status != report.StatusSkipped {
		t.Errorf("socket = %+v", f)
	}

	skip := security(context.Background(), Config{Root: t.TempDir(), Runner: fakeRunner{}, ComposeRoots: []string{t.TempDir()}})
	if f := find(skip, "security.service_all_interfaces"); f.Status != report.StatusSkipped {
		t.Errorf("unavailable ss = %+v", f)
	}
}

func TestPrivateKeyFile(t *testing.T) {
	tests := map[string]bool{
		"id_rsa":           true,
		"id_ed25519":       true,
		"id_ecdsa.pub":     false,
		"id_rsa.pub":       false,
		"server.pem":       true,
		"server.key":       true,
		"notes.txt":        false,
		"public_key.pub":   false,
		"some_private_key": false,
	}
	for name, want := range tests {
		if got := privateKeyFile(name); got != want {
			t.Errorf("privateKeyFile(%q) = %v, want %v", name, got, want)
		}
	}
}
