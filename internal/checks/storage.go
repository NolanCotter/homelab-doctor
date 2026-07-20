package checks

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/homelab-doctor/homelab-doctor/internal/report"
)

func storage(ctx context.Context, c Config) []report.Finding {
	_ = ctx
	var out []report.Finding
	mounts, err := readFile(c.path("/proc/mounts"))
	if err != nil {
		out = append(out, skipped("storage", "storage.filesystem_capacity", err.Error()), skipped("storage", "storage.inode_capacity", err.Error()), skipped("storage", "storage.read_only_mount", err.Error()))
	} else {
		var capacity, inodes, ro []string
		for _, line := range strings.Split(mounts, "\n") {
			f := strings.Fields(line)
			if len(f) < 4 || !strings.HasPrefix(f[1], "/") {
				continue
			}
			var st syscall.Statfs_t
			if err := syscall.Statfs(c.path(f[1]), &st); err != nil {
				continue
			}
			free := int64(st.Bavail) * 100 / max64(int64(st.Blocks), 1)
			if free < 10 {
				capacity = append(capacity, fmt.Sprintf("%s free=%d%%", f[1], free))
			}
			if st.Files > 0 && int64(st.Ffree)*100/int64(st.Files) < 10 {
				inodes = append(inodes, fmt.Sprintf("%s inode-free=%d%%", f[1], int64(st.Ffree)*100/int64(st.Files)))
			}
			if strings.Contains(","+f[3]+",", ",ro,") {
				ro = append(ro, f[1])
			}
		}
		out = append(out, capacityFinding("storage.filesystem_capacity", capacity, "Filesystem capacity below 10% can break databases, image pulls, and logs."), capacityFinding("storage.inode_capacity", inodes, "Low inode capacity prevents new files even when bytes remain."))
		status, sev := report.StatusPass, report.SeverityInfo
		if len(ro) > 0 {
			status, sev = report.StatusFinding, report.SeverityWarning
		}
		out = append(out, finding("storage", "storage.read_only_mount", status, sev, linesOr(ro, "no read-only mounts detected"), "Read-only mounts may be intentional, but an unexpected remount often follows storage errors.", "Confirm intended read-only mounts and inspect kernel/storage logs for unexpected remounts."))
	}

	smart := c.runner().Run(ctx, "smartctl", "--version")
	if smart.Err != nil {
		out = append(out, skipped("storage", "storage.smart_availability", "smartctl is not available; no SMART command was run"))
	} else {
		out = append(out, finding("storage", "storage.smart_availability", report.StatusPass, report.SeverityInfo, []string{"smartctl available"}, "SMART tooling is available for an operator to run when device-level investigation is appropriate.", "Run vendor-appropriate, read-only SMART queries for devices you administer."))
	}

	data := c.path(c.DockerDataRoot)
	usage, err := dirSize(data, 10000)
	if err != nil {
		out = append(out, skipped("storage", "storage.docker_data_root", err.Error()))
	} else {
		status, sev := report.StatusPass, report.SeverityInfo
		if usage > 10*1024*1024*1024 {
			status, sev = report.StatusFinding, report.SeverityWarning
		}
		out = append(out, finding("storage", "storage.docker_data_root", status, sev, []string{fmt.Sprintf("%s sampled usage=%d bytes", c.DockerDataRoot, usage)}, "Docker data-root growth can exhaust its filesystem.", "Review images, volumes, and logs; remove resources only through an explicitly approved maintenance process."))
	}

	logs := []string{"/var/log", "/var/lib/docker/containers"}
	var large []string
	for _, root := range logs {
		size, e := dirSize(c.path(root), 5000)
		if e == nil && size > 1024*1024*1024 {
			large = append(large, fmt.Sprintf("%s sampled usage=%d bytes", root, size))
		}
	}
	status, sev := report.StatusPass, report.SeverityInfo
	if len(large) > 0 {
		status, sev = report.StatusFinding, report.SeverityWarning
	}
	out = append(out, finding("storage", "storage.large_logs", status, sev, linesOr(large, "no sampled log directory exceeds 1 GiB"), "Log directory scanning is bounded and never follows symlinks.", "Review retention and rotation settings; preserve logs needed for incident analysis before archival or deletion."))
	return out
}

func capacityFinding(id string, evidence []string, explanation string) report.Finding {
	status, sev := report.StatusPass, report.SeverityInfo
	if len(evidence) > 0 {
		status, sev = report.StatusFinding, report.SeverityWarning
	}
	return finding("storage", id, status, sev, linesOr(evidence, "all inspected filesystems have at least 10% free"), explanation, "Free capacity safely by reviewing data ownership and retention; do not delete diagnostic resources automatically.")
}
func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
func dirSize(root string, limit int) (int64, error) {
	var size int64
	if _, err := os.Lstat(root); err != nil {
		return 0, err
	}
	err := walkLimited(root, limit, func(_ string, d fs.DirEntry) error {
		if d.Type().IsRegular() {
			i, e := d.Info()
			if e == nil {
				size += i.Size()
			}
		}
		return nil
	})
	return size, err
}

var _ = filepath.Separator
