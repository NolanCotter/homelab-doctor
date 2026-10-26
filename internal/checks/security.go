package checks

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/homelab-doctor/homelab-doctor/internal/report"
)

func security(ctx context.Context, c Config) []report.Finding {
	_ = ctx
	var out []report.Finding
	socket := c.path("/var/run/docker.sock")
	info, e := os.Lstat(socket)
	if e != nil {
		out = append(out, skipped("security", "security.docker_socket_exposure", e.Error()))
	} else {
		unsafe := info.Mode().Perm()&0007 != 0
		status, sev := report.StatusPass, report.SeverityInfo
		if unsafe {
			status, sev = report.StatusFinding, report.SeverityCritical
		}
		out = append(out, finding("security", "security.docker_socket_exposure", status, sev, []string{fmt.Sprintf("%s mode=%#o", socket, info.Mode().Perm())}, "Docker socket access generally grants effective root-equivalent control of the host.", "Restrict socket access to a tightly controlled group; review all members before changing permissions."))
	}
	roots := c.ComposeRoots
	if len(roots) == 0 {
		roots = []string{"."}
	}
	var envs, keys []string
	var walkErr error
	for _, root := range roots {
		if err := walkLimited(root, 3000, func(path string, d fs.DirEntry) error {
			if d.IsDir() {
				return nil
			}
			name := strings.ToLower(d.Name())
			info, e := d.Info()
			if e != nil {
				return nil
			}
			if (name == ".env" || strings.HasSuffix(name, ".env")) && info.Mode().Perm()&0004 != 0 {
				envs = append(envs, filepath.Base(path)+fmt.Sprintf(" mode=%#o", info.Mode().Perm()))
			}
			if privateKeyFile(name) && info.Mode().Perm()&0077 != 0 {
				keys = append(keys, filepath.Base(path)+fmt.Sprintf(" mode=%#o", info.Mode().Perm()))
			}
			return nil
		}); err != nil && walkErr == nil {
			walkErr = err
		}
	}
	if walkErr != nil && len(envs) == 0 && len(keys) == 0 {
		out = append(out, skipped("security", "security.world_readable_env", walkErr.Error()), skipped("security", "security.private_key_permissions", walkErr.Error()))
	} else {
		out = append(out, securityFinding("security.world_readable_env", envs, "World-readable environment files can expose credentials to local users."), securityFinding("security.private_key_permissions", keys, "Private keys readable by group or other users are at risk of disclosure."))
	}
	ss := c.runner().Run(ctx, "ss", "-ltnH")
	if ss.Err != nil {
		out = append(out, skipped("security", "security.service_all_interfaces", commandUnavailable(ss)))
	} else {
		var public []string
		for _, line := range nonEmpty(ss.Stdout) {
			f := strings.Fields(line)
			if len(f) > 3 && (strings.HasPrefix(f[3], "0.0.0.0:") || strings.HasPrefix(f[3], "*:") || strings.HasPrefix(f[3], "[::]:")) {
				public = append(public, f[3])
			}
		}
		out = append(out, securityFinding("security.service_all_interfaces", public, "Services listening on all interfaces can be reachable from networks beyond their intended audience."))
	}
	return out
}
func privateKeyFile(name string) bool {
	if strings.HasSuffix(name, ".pub") {
		return false
	}
	if strings.HasSuffix(name, ".pem") || strings.HasSuffix(name, ".key") {
		return true
	}
	for _, prefix := range []string{"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

func securityFinding(id string, e []string, ex string) report.Finding {
	status, sev := report.StatusPass, report.SeverityInfo
	if len(e) > 0 {
		status, sev = report.StatusFinding, report.SeverityWarning
	}
	return finding("security", id, status, sev, linesOr(e, "no concerns detected"), ex, "Confirm ownership and access requirements, then make the smallest safe configuration change through your normal change process.")
}
