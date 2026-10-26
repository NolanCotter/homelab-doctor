package checks

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/homelab-doctor/homelab-doctor/internal/report"
)

type dockerContainer struct {
	Names  string `json:"Names"`
	Status string `json:"Status"`
	State  string `json:"State"`
	Ports  string `json:"Ports"`
	Mounts string `json:"Mounts"`
}

func docker(ctx context.Context, c Config) []report.Finding {
	var out []report.Finding
	info := c.runner().Run(ctx, "docker", "info", "--format", "{{json .}}")
	if info.Err != nil {
		out = append(out, skipped("docker", "docker.daemon.availability", commandUnavailable(info)))
		out = append(out, skipped("docker", "docker.unhealthy_containers", "Docker daemon unavailable"), skipped("docker", "docker.restart_loop", "Docker daemon unavailable"), skipped("docker", "docker.missing_bind_source", "Docker daemon unavailable"), skipped("docker", "docker.exposed_ports", "Docker daemon unavailable"), skipped("docker", "docker.dangling_resources", "Docker daemon unavailable"), skipped("docker", "docker.healthcheck", "Docker daemon unavailable"))
	} else {
		out = append(out, finding("docker", "docker.daemon.availability", report.StatusPass, report.SeverityInfo, []string{"docker info succeeded"}, "The Docker daemon responded to a read-only status request.", "Keep daemon access restricted to trusted operators."))
		ps := c.runner().Run(ctx, "docker", "ps", "-a", "--format", "{{json .}}")
		if ps.Err != nil {
			for _, id := range []string{"docker.unhealthy_containers", "docker.restart_loop", "docker.missing_bind_source", "docker.exposed_ports", "docker.healthcheck"} {
				out = append(out, skipped("docker", id, commandUnavailable(ps)))
			}
		} else {
			out = append(out, dockerContainers(ps.Stdout, c)...)
		}
		images := c.runner().Run(ctx, "docker", "images", "--filter", "dangling=true", "--format", "{{.ID}}")
		volumes := c.runner().Run(ctx, "docker", "volume", "ls", "--filter", "dangling=true", "--format", "{{.Name}}")
		if images.Err != nil || volumes.Err != nil {
			why := strings.TrimSpace(commandUnavailable(images) + " " + commandUnavailable(volumes))
			out = append(out, skipped("docker", "docker.dangling_resources", why))
		} else {
			var dangling []string
			for _, id := range nonEmpty(images.Stdout) {
				dangling = append(dangling, "image "+id)
			}
			for _, name := range nonEmpty(volumes.Stdout) {
				dangling = append(dangling, "volume "+name)
			}
			status, sev := report.StatusPass, report.SeverityInfo
			if len(dangling) > 0 {
				status, sev = report.StatusFinding, report.SeverityWarning
			}
			out = append(out, finding("docker", "docker.dangling_resources", status, sev, linesOr(dangling, "no dangling images or volumes detected"), "Dangling images and volumes consume disk space and are reported only; Homelab Doctor never removes them.", "Review Docker resource ownership and use an explicitly approved maintenance process if cleanup is needed."))
		}
	}
	out = append(out, composeChecks(c)...)
	return out
}

func dockerContainers(raw string, c Config) []report.Finding {
	var cs []dockerContainer
	var malformed bool
	for _, line := range nonEmpty(raw) {
		var x dockerContainer
		if json.Unmarshal([]byte(line), &x) != nil {
			malformed = true
			continue
		}
		cs = append(cs, x)
	}
	var unhealthy, restarts, missing, ports, health []string
	for _, x := range cs {
		s := strings.ToLower(x.Status + " " + x.State)
		if strings.Contains(s, "unhealthy") {
			unhealthy = append(unhealthy, x.Names)
		}
		if strings.Contains(s, "restarting") || strings.Contains(s, "restart") {
			restarts = append(restarts, x.Names+": "+x.Status)
		}
		if strings.Contains(s, "exited") {
			health = append(health, x.Names+": "+x.Status)
		}
		for _, binding := range strings.Split(x.Ports, ",") {
			binding = strings.TrimSpace(binding)
			if publicPortBinding(binding) {
				ports = append(ports, x.Names+": "+binding)
			}
		}
		for _, m := range strings.Split(x.Mounts, ",") {
			source, _, ok := strings.Cut(strings.TrimSpace(m), ":")
			if !ok {
				continue
			}
			source = strings.TrimSpace(source)
			if strings.HasPrefix(source, "/") {
				if _, err := os.Stat(c.path(source)); err != nil {
					missing = append(missing, x.Names+": "+source)
				}
			}
		}
	}
	if malformed {
		health = append(health, "malformed docker ps JSON ignored")
	}
	return []report.Finding{dockerFinding("docker.unhealthy_containers", unhealthy, "Containers reporting unhealthy may be unable to serve their intended workload."), dockerFinding("docker.restart_loop", restarts, "Restarting or repeatedly exited containers can hide a persistent application failure."), dockerFinding("docker.missing_bind_source", missing, "A missing bind-mount source can cause a container to start with unexpected data or fail."), dockerFinding("docker.exposed_ports", ports, "Published ports expand the host's reachable service surface."), dockerFinding("docker.healthcheck", health, "Container health and exit state need operator review.")}
}
func publicPortBinding(binding string) bool {
	for _, prefix := range []string{"0.0.0.0:", "*:", "[::]:", ":::"} {
		if strings.HasPrefix(binding, prefix) {
			return true
		}
	}
	return false
}

func dockerFinding(id string, e []string, ex string) report.Finding {
	status, sev := report.StatusPass, report.SeverityInfo
	if len(e) > 0 {
		status, sev = report.StatusFinding, report.SeverityWarning
	}
	return finding("docker", id, status, sev, linesOr(e, "no concerns detected"), ex, "Inspect container logs and configuration; make changes through your normal deployment workflow.")
}

var envRef = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)(?::[^}]*)?\}`)
var passwordKey = regexp.MustCompile(`(?i)^\s*([A-Za-z_][\w-]*(?:password|passwd|secret))\s*[:=]\s*(.+)$`)

func composeChecks(c Config) []report.Finding {
	roots := c.ComposeRoots
	if len(roots) == 0 {
		roots = []string{"."}
	}
	var missing, secrets []string
	var walkErr error
	for _, root := range roots {
		if err := walkLimited(root, 2000, func(path string, d os.DirEntry) error {
			if d.IsDir() || !(d.Name() == "compose.yml" || d.Name() == "compose.yaml" || d.Name() == "docker-compose.yml" || d.Name() == "docker-compose.yaml") {
				return nil
			}
			b, e := os.ReadFile(path)
			if e != nil {
				return nil
			}
			text := string(b)
			for _, m := range envRef.FindAllStringSubmatch(text, -1) {
				if os.Getenv(m[1]) == "" {
					missing = append(missing, filepath.Base(path)+": "+m[1])
				}
			}
			for _, line := range strings.Split(text, "\n") {
				if m := passwordKey.FindStringSubmatch(line); len(m) > 0 && !strings.Contains(m[2], "${") {
					secrets = append(secrets, filepath.Base(path)+": "+m[1]+"=[REDACTED]")
				}
			}
			return nil
		}); err != nil && walkErr == nil {
			walkErr = err
		}
	}
	if walkErr != nil && len(missing) == 0 && len(secrets) == 0 {
		return []report.Finding{skipped("docker", "docker.compose.missing_env", walkErr.Error()), skipped("security", "security.plaintext_compose_password", walkErr.Error())}
	}
	return []report.Finding{dockerFinding("docker.compose.missing_env", missing, "Compose variables that are unset can silently become empty or select unintended defaults."), securityFinding("security.plaintext_compose_password", secrets, "Plaintext Compose passwords are easy to leak through backups, source control, and support artifacts.")}
}
