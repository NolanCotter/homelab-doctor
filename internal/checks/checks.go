// Package checks contains read-only host diagnostics.
package checks

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/homelab-doctor/homelab-doctor/internal/execx"
	"github.com/homelab-doctor/homelab-doctor/internal/report"
)

type Config struct {
	Runner          execx.Runner
	Root            string // test root; empty means the host root
	ComposeRoots    []string
	DockerDataRoot  string
	TCPProbeTargets []string
}

func (c Config) path(p string) string {
	if c.Root == "" {
		return p
	}
	return filepath.Join(c.Root, strings.TrimPrefix(p, "/"))
}

func (c Config) runner() execx.Runner {
	if c.Runner != nil {
		return c.Runner
	}
	return execx.OSRunner{}
}

func finding(profile, id string, status report.Status, severity report.Severity, evidence []string, explanation, remediation string) report.Finding {
	return report.Finding{ID: id, Profile: profile, Status: status, Severity: severity, Evidence: evidence, Explanation: explanation, Remediation: remediation}
}

func skipped(profile, id, why string) report.Finding {
	return finding(profile, id, report.StatusSkipped, report.SeverityInfo, []string{why}, "The check could not obtain the required read-only information.", "Run as a user permitted to read this information; do not change system state merely to satisfy the check.")
}

// Run returns only checks requested by profile. No checker changes the host.
func Run(ctx context.Context, profile string, c Config) []report.Finding {
	if c.DockerDataRoot == "" {
		c.DockerDataRoot = "/var/lib/docker"
	}
	var all []report.Finding
	if profile == "" || profile == "system" {
		all = append(all, system(ctx, c)...)
		all = append(all, security(ctx, c)...)
	}
	if profile == "" || profile == "storage" {
		all = append(all, storage(ctx, c)...)
	}
	if profile == "" || profile == "docker" {
		all = append(all, docker(ctx, c)...)
	}
	if profile == "" || profile == "networking" {
		all = append(all, networking(ctx, c)...)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].ID < all[j].ID })
	return all
}

// IDs exposes the complete stable check catalog without executing it.
func IDs() []string {
	return []string{
		"docker.compose.missing_env", "docker.daemon.availability", "docker.dangling_resources", "docker.exposed_ports", "docker.healthcheck", "docker.missing_bind_source", "docker.restart_loop", "docker.unhealthy_containers",
		"network.default_route", "network.dns_resolver", "network.duplicate_port_binding", "network.listening_ports", "network.local_tcp_probe", "network.public_ip_lookup",
		"security.docker_socket_exposure", "security.plaintext_compose_password", "security.private_key_permissions", "security.service_all_interfaces", "security.world_readable_env",
		"storage.docker_data_root", "storage.filesystem_capacity", "storage.inode_capacity", "storage.large_logs", "storage.read_only_mount", "storage.smart_availability",
		"system.clock_synchronization", "system.distribution_kernel", "system.failed_units", "system.load_average", "system.memory_pressure", "system.uptime",
	}
}

func Explain(id string) (report.Finding, bool) {
	for _, f := range catalog() {
		if f.ID == id {
			return f, true
		}
	}
	return report.Finding{}, false
}

func catalog() []report.Finding {
	var out []report.Finding
	for _, id := range IDs() {
		parts := strings.Split(id, ".")
		profile := parts[0]
		out = append(out, finding(profile, id, report.StatusPass, report.SeverityInfo, nil, "This read-only diagnostic identifies a likely host configuration or health concern.", "Review the evidence and apply the least-privilege remediation appropriate for your environment."))
	}
	return out
}

func readFile(path string) (string, error) { b, err := os.ReadFile(path); return string(b), err }

func walkLimited(root string, maxEntries int, fn func(string, os.DirEntry) error) error {
	entries := 0
	return filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		entries++
		if entries > maxEntries {
			return filepath.SkipDir
		}
		if d.Type()&os.ModeSymlink != 0 {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		return fn(path, d)
	})
}

func commandUnavailable(res execx.Result) string {
	if res.Err == nil {
		return ""
	}
	return fmt.Sprintf("command unavailable or inaccessible: %v", res.Err)
}
