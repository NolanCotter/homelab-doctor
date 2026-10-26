// Package checks contains read-only host diagnostics.
package checks

import (
	"context"
	"fmt"
	"io/fs"
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
	if profile == "" || profile == "all" || profile == "system" {
		all = append(all, system(ctx, c)...)
		all = append(all, security(ctx, c)...)
	}
	if profile == "" || profile == "all" || profile == "storage" {
		all = append(all, storage(ctx, c)...)
	}
	if profile == "" || profile == "all" || profile == "docker" {
		all = append(all, docker(ctx, c)...)
	}
	if profile == "" || profile == "all" || profile == "networking" {
		all = append(all, networking(ctx, c)...)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].ID < all[j].ID })
	return all
}

type catalogEntry struct {
	id          string
	explanation string
	remediation string
}

// catalogEntries is the stable check catalog. IDs are never renamed once released.
var catalogEntries = []catalogEntry{
	{"docker.compose.missing_env", "Compose variables that are unset can silently become empty or select unintended defaults.", "Define the variables in a reviewed environment file or the Compose deployment configuration before starting services."},
	{"docker.daemon.availability", "The Docker daemon responded to a read-only status request, or could not be reached.", "Keep daemon access restricted to trusted operators; inspect service status and logs if the daemon is unreachable."},
	{"docker.dangling_resources", "Dangling images and volumes consume disk space and are reported only; Homelab Doctor never removes them.", "Review Docker resource ownership and use an explicitly approved maintenance process if cleanup is needed."},
	{"docker.exposed_ports", "Ports published on all host interfaces expand the host's reachable service surface.", "Bind published ports to the intended interface or firewall them; make changes through your normal deployment workflow."},
	{"docker.healthcheck", "Container health and exit state need operator review.", "Inspect container logs and configuration; make changes through your normal deployment workflow."},
	{"docker.missing_bind_source", "A missing bind-mount source can cause a container to start with unexpected data or fail.", "Restore or correct the host path through your normal deployment workflow, without deleting container data."},
	{"docker.restart_loop", "Restarting or repeatedly exited containers can hide a persistent application failure.", "Inspect container logs and configuration; make changes through your normal deployment workflow."},
	{"docker.unhealthy_containers", "Containers reporting unhealthy may be unable to serve their intended workload.", "Inspect container logs and configuration; make changes through your normal deployment workflow."},
	{"network.default_route", "A default route is normally necessary for off-subnet access.", "Verify routing configuration if this host should have external connectivity."},
	{"network.dns_resolver", "Name resolution is required by most package, certificate, and service workflows.", "Verify the resolver source and test the names your workloads use."},
	{"network.duplicate_port_binding", "Multiple listener entries for one address can be intentional (for example, IPv4 and IPv6) but merit review.", "Inspect the owning processes before modifying port mappings."},
	{"network.listening_ports", "Listening ports reveal services reachable on this host.", "Confirm each listener is expected and scoped to the intended interface."},
	{"network.local_tcp_probe", "Local TCP probes test configured endpoints without sending data beyond connection setup.", "Check listener state, target address, and service logs for failed probes."},
	{"network.public_ip_lookup", "Public-IP lookup is disabled by default so diagnostics never make an unexpected external request.", "No action is required; run an explicit public-IP query yourself if you need that information."},
	{"security.docker_socket_exposure", "Docker socket access generally grants effective root-equivalent control of the host.", "Restrict socket access to a tightly controlled group; review all members before changing permissions."},
	{"security.plaintext_compose_password", "Plaintext Compose passwords are easy to leak through backups, source control, and support artifacts.", "Move secrets to a protected secret store or environment mechanism supported by your deployment workflow."},
	{"security.private_key_permissions", "Private keys readable by group or other users are at risk of disclosure.", "Confirm ownership and access requirements, then make the smallest safe permission change through your normal change process."},
	{"security.service_all_interfaces", "Services listening on all interfaces can be reachable from networks beyond their intended audience.", "Confirm each listener is intended for external access; bind it to a specific interface or firewall it if not."},
	{"security.world_readable_env", "World-readable environment files can expose credentials to local users.", "Confirm ownership and access requirements, then make the smallest safe permission change through your normal change process."},
	{"storage.docker_data_root", "Docker data-root growth can exhaust its filesystem.", "Review images, volumes, and logs; remove resources only through an explicitly approved maintenance process."},
	{"storage.filesystem_capacity", "Filesystem capacity below 10% can break databases, image pulls, and logs.", "Free capacity safely by reviewing data ownership and retention; do not delete diagnostic resources automatically."},
	{"storage.inode_capacity", "Low inode capacity prevents new files even when bytes remain.", "Free capacity safely by reviewing data ownership and retention; do not delete diagnostic resources automatically."},
	{"storage.large_logs", "Log directory scanning is bounded and never follows symlinks; oversized logs can exhaust a filesystem.", "Review retention and rotation settings; preserve logs needed for incident analysis before archival or deletion."},
	{"storage.read_only_mount", "Read-only mounts may be intentional, but an unexpected remount often follows storage errors.", "Confirm intended read-only mounts and inspect kernel/storage logs for unexpected remounts."},
	{"storage.smart_availability", "SMART tooling is available for an operator to run when device-level investigation is appropriate.", "Run vendor-appropriate, read-only SMART queries for devices you administer."},
	{"system.clock_synchronization", "Accurate time matters for TLS, logs, backups, and clustered services.", "Verify the configured time service and its upstream reachability."},
	{"system.distribution_kernel", "Kernel and distribution information establishes diagnostic context.", "Keep your distribution and supported kernel security updates current."},
	{"system.failed_units", "Failed units can prevent dependencies from starting or recovering.", "Inspect each unit with journalctl and systemctl status; correct configuration before manually restarting it."},
	{"system.load_average", "Sustained load well above CPU capacity can indicate CPU, I/O, or uninterruptible work contention.", "Correlate load with CPU, disk I/O, and process-level metrics before changing workloads."},
	{"system.memory_pressure", "Low available memory can cause swapping, OOM kills, and service latency.", "Identify memory-heavy workloads and size limits; reserve enough memory for the host."},
	{"system.uptime", "Long uptimes are informational; they can help correlate a problem with a deployment or reboot.", "Plan maintenance reboots when kernel updates or service changes require them."},
}

// IDs exposes the complete stable check catalog without executing it.
func IDs() []string {
	out := make([]string, 0, len(catalogEntries))
	for _, entry := range catalogEntries {
		out = append(out, entry.id)
	}
	return out
}

func Explain(id string) (report.Finding, bool) {
	for _, entry := range catalogEntries {
		if entry.id == id {
			return finding(strings.Split(entry.id, ".")[0], entry.id, report.StatusPass, report.SeverityInfo, nil, entry.explanation, entry.remediation), true
		}
	}
	return report.Finding{}, false
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
			return fs.SkipAll
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
