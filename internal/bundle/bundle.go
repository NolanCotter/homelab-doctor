// Package bundle writes self-contained, privacy-redacted diagnostic archives.
package bundle

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/homelab-doctor/homelab-doctor/internal/report"
)

type Manifest struct {
	SchemaVersion string            `json:"schema_version"`
	GeneratedAt   time.Time         `json:"generated_at"`
	Files         map[string]string `json:"files"`
}

// Create writes only generated report files. Existing symlink outputs and unsafe archive names are rejected.
func Create(output string, r report.Report, privateIPs bool) error {
	if output == "" {
		return errors.New("bundle output is required")
	}
	for _, part := range strings.Split(filepath.ToSlash(output), "/") {
		if part == ".." {
			return errors.New("unsafe bundle output path")
		}
	}
	if filepath.Base(output) == "." {
		return errors.New("unsafe bundle output path")
	}
	if _, err := os.Lstat(output); err == nil {
		return errors.New("refusing to overwrite an existing bundle path")
	}
	dir := filepath.Dir(output)
	if err := safeDirectory(dir); err != nil {
		return err
	}
	if st, err := os.Lstat(dir); err != nil || !st.IsDir() {
		return errors.New("bundle directory is not a safe directory")
	}
	r = r.Sanitized(privateIPs)
	js, err := r.JSON()
	if err != nil {
		return err
	}
	md := []byte(r.Markdown())
	files := map[string][]byte{"report.json": js, "report.md": md}
	manifest := Manifest{SchemaVersion: "1.0", GeneratedAt: time.Now().UTC(), Files: map[string]string{}}
	for name, data := range files {
		if !safeName(name) {
			return errors.New("unsafe archive name")
		}
		sum := sha256.Sum256(data)
		manifest.Files[name] = hex.EncodeToString(sum[:])
	}
	mb, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	files["manifest.json"] = mb
	tmp, err := os.CreateTemp(dir, ".homelab-doctor-*.tar.gz")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	gz := gzip.NewWriter(tmp)
	tw := tar.NewWriter(gz)
	for _, name := range []string{"report.json", "report.md", "manifest.json"} {
		data := files[name]
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: int64(len(data)), ModTime: manifest.GeneratedAt}); err != nil {
			_ = tmp.Close()
			return err
		}
		if _, err := tw.Write(data); err != nil {
			_ = tmp.Close()
			return err
		}
	}
	if err := tw.Close(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := gz.Close(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, output)
}

func safeDirectory(dir string) error {
	current := "."
	if filepath.IsAbs(dir) {
		current = string(filepath.Separator)
	}
	for _, part := range strings.Split(filepath.Clean(dir), string(filepath.Separator)) {
		if part == "" || part == "." {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("refusing bundle path with symlinked directory")
		}
	}
	return nil
}
func safeName(name string) bool {
	return name != "" && !strings.HasPrefix(name, "/") && !strings.Contains(name, "..") && filepath.Base(name) == name
}

var _ io.Writer
