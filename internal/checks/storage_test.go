package checks

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/homelab-doctor/homelab-doctor/internal/report"
)

func createSparseFile(t *testing.T, path string, size int64) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(size); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestStorageMountsSmartAndOversizedDirectories(t *testing.T) {
	root := t.TempDir()
	writeRootFile(t, root, "/proc/mounts", "/dev/sda1 / ext4 ro 0 0\n/dev/sdb1 /data ext4 rw 0 0\n")
	createSparseFile(t, filepath.Join(root, "var/lib/docker/overlay2/blob"), 11<<30)
	createSparseFile(t, filepath.Join(root, "var/log/big.log"), 2<<30)
	r := fakeRunner{"smartctl --version": {Stdout: "smartctl 7.4\n"}}
	fs := storage(context.Background(), Config{Root: root, Runner: r, DockerDataRoot: "/var/lib/docker"})

	if f := find(fs, "storage.read_only_mount"); f.Status != report.StatusFinding || f.Evidence[0] != "/" {
		t.Errorf("read-only mount = %+v", f)
	}
	if f := find(fs, "storage.smart_availability"); f.Status != report.StatusPass {
		t.Errorf("smart = %+v", f)
	}
	if f := find(fs, "storage.docker_data_root"); f.Status != report.StatusFinding {
		t.Errorf("docker data root = %+v", f)
	}
	if f := find(fs, "storage.large_logs"); f.Status != report.StatusFinding {
		t.Errorf("large logs = %+v", f)
	}
	if f := find(fs, "storage.filesystem_capacity"); f.ID == "" {
		t.Errorf("capacity finding missing")
	}
	if f := find(fs, "storage.inode_capacity"); f.ID == "" {
		t.Errorf("inode finding missing")
	}
}

func TestStorageMissingInputsAreSkipped(t *testing.T) {
	fs := storage(context.Background(), Config{Root: t.TempDir(), Runner: fakeRunner{}, DockerDataRoot: "/var/lib/docker"})
	for _, id := range []string{"storage.filesystem_capacity", "storage.inode_capacity", "storage.read_only_mount", "storage.smart_availability", "storage.docker_data_root"} {
		if f := find(fs, id); f.Status != report.StatusSkipped {
			t.Errorf("%s = %s, want skipped", id, f.Status)
		}
	}
	if f := find(fs, "storage.large_logs"); f.Status != report.StatusPass {
		t.Errorf("large logs = %+v", f)
	}
}

func TestStorageHealthyDirectoriesPass(t *testing.T) {
	root := t.TempDir()
	writeRootFile(t, root, "/proc/mounts", "/dev/sda1 / ext4 rw 0 0\n")
	if err := os.MkdirAll(filepath.Join(root, "var/lib/docker"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "var/log"), 0700); err != nil {
		t.Fatal(err)
	}
	writeRootFile(t, root, "/var/log/small.log", strings.Repeat("x", 16))
	r := fakeRunner{"smartctl --version": {Stdout: "smartctl 7.4\n"}}
	fs := storage(context.Background(), Config{Root: root, Runner: r, DockerDataRoot: "/var/lib/docker"})
	for _, id := range []string{"storage.read_only_mount", "storage.smart_availability", "storage.docker_data_root", "storage.large_logs"} {
		if f := find(fs, id); f.Status != report.StatusPass {
			t.Errorf("%s = %s (%+v)", id, f.Status, f)
		}
	}
}
