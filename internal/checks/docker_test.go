package checks

import (
	"context"
	"strings"
	"testing"

	"github.com/homelab-doctor/homelab-doctor/internal/report"
)

func TestDockerDaemonUnavailableSkipsChecks(t *testing.T) {
	fs := docker(context.Background(), Config{Runner: fakeRunner{}, ComposeRoots: []string{t.TempDir()}})
	for _, id := range []string{"docker.daemon.availability", "docker.unhealthy_containers", "docker.restart_loop", "docker.missing_bind_source", "docker.exposed_ports", "docker.dangling_resources", "docker.healthcheck"} {
		if f := find(fs, id); f.Status != report.StatusSkipped {
			t.Errorf("%s = %s, want skipped", id, f.Status)
		}
	}
	if f := find(fs, "docker.compose.missing_env"); f.Status != report.StatusPass {
		t.Errorf("compose missing env = %+v", f)
	}
}

func TestDockerDanglingResources(t *testing.T) {
	r := fakeRunner{
		"docker info --format {{json .}}":                            {Stdout: "{}"},
		"docker ps -a --format {{json .}}":                           {Stdout: ""},
		"docker images --filter dangling=true --format {{.ID}}":      {Stdout: "abc123\n"},
		"docker volume ls --filter dangling=true --format {{.Name}}": {Stdout: "orphan-vol\n"},
	}
	fs := docker(context.Background(), Config{Runner: r, ComposeRoots: []string{t.TempDir()}})
	f := find(fs, "docker.dangling_resources")
	if f.Status != report.StatusFinding {
		t.Fatalf("dangling = %+v", f)
	}
	joined := strings.Join(f.Evidence, ";")
	if !strings.Contains(joined, "image abc123") || !strings.Contains(joined, "volume orphan-vol") {
		t.Errorf("evidence = %q", joined)
	}

	clean := fakeRunner{
		"docker info --format {{json .}}":                            {Stdout: "{}"},
		"docker ps -a --format {{json .}}":                           {Stdout: ""},
		"docker images --filter dangling=true --format {{.ID}}":      {Stdout: ""},
		"docker volume ls --filter dangling=true --format {{.Name}}": {Stdout: ""},
	}
	if f := find(docker(context.Background(), Config{Runner: clean, ComposeRoots: []string{t.TempDir()}}), "docker.dangling_resources"); f.Status != report.StatusPass {
		t.Errorf("clean dangling = %+v", f)
	}
}

func TestDockerPartialCommandFailureIsSkipped(t *testing.T) {
	r := fakeRunner{
		"docker info --format {{json .}}":                            {Stdout: "{}"},
		"docker volume ls --filter dangling=true --format {{.Name}}": {Err: context.DeadlineExceeded},
	}
	fs := docker(context.Background(), Config{Runner: r, ComposeRoots: []string{t.TempDir()}})
	if f := find(fs, "docker.daemon.availability"); f.Status != report.StatusPass {
		t.Errorf("daemon = %+v", f)
	}
	for _, id := range []string{"docker.unhealthy_containers", "docker.restart_loop", "docker.missing_bind_source", "docker.exposed_ports", "docker.healthcheck"} {
		if f := find(fs, id); f.Status != report.StatusSkipped {
			t.Errorf("%s = %s, want skipped", id, f.Status)
		}
	}
	if f := find(fs, "docker.dangling_resources"); f.Status != report.StatusSkipped {
		t.Errorf("dangling = %+v", f)
	}
}

func TestDockerBindMountsAndPublicPorts(t *testing.T) {
	root := t.TempDir()
	writeRootFile(t, root, "/data/file", "x")
	ps := `{"Names":"app","Status":"Up 2m","State":"running","Ports":"127.0.0.1:8080->80/tcp, 0.0.0.0:9090->90/tcp, :::9091->91/tcp","Mounts":"/data:/data,/missing:/missing"}`
	r := fakeRunner{
		"docker info --format {{json .}}":      {Stdout: "{}"},
		"docker ps -a --format {{json .}}":     {Stdout: ps},
		"docker system df --format {{json .}}": {Stdout: "{}"},
	}
	fs := docker(context.Background(), Config{Runner: r, Root: root, ComposeRoots: []string{t.TempDir()}})
	missing := find(fs, "docker.missing_bind_source")
	if missing.Status != report.StatusFinding {
		t.Fatalf("missing mount = %+v", missing)
	}
	if joined := strings.Join(missing.Evidence, ";"); strings.Contains(joined, "/data") || !strings.Contains(joined, "/missing") {
		t.Errorf("bind mount evidence = %q", joined)
	}
	ports := find(fs, "docker.exposed_ports")
	if ports.Status != report.StatusFinding {
		t.Fatalf("ports = %+v", ports)
	}
	joined := strings.Join(ports.Evidence, ";")
	if strings.Contains(joined, "8080") || !strings.Contains(joined, "9090") || !strings.Contains(joined, "9091") {
		t.Errorf("port evidence = %q", joined)
	}
}

func TestDockerLoopbackOnlyPortsPass(t *testing.T) {
	ps := `{"Names":"app","Status":"Up 2m","State":"running","Ports":"127.0.0.1:8080->80/tcp"}`
	r := fakeRunner{
		"docker info --format {{json .}}":      {Stdout: "{}"},
		"docker ps -a --format {{json .}}":     {Stdout: ps},
		"docker system df --format {{json .}}": {Stdout: "{}"},
	}
	fs := docker(context.Background(), Config{Runner: r, ComposeRoots: []string{t.TempDir()}})
	if f := find(fs, "docker.exposed_ports"); f.Status != report.StatusPass {
		t.Errorf("ports = %+v", f)
	}
	if f := find(fs, "docker.missing_bind_source"); f.Status != report.StatusPass {
		t.Errorf("mounts = %+v", f)
	}
}

func TestPublicPortBinding(t *testing.T) {
	for binding, want := range map[string]bool{
		"0.0.0.0:80->80/tcp":   true,
		"*:80->80/tcp":         true,
		"[::]:80->80/tcp":      true,
		":::80->80/tcp":        true,
		"127.0.0.1:80->80/tcp": false,
		"[::1]:80->80/tcp":     false,
		"":                     false,
	} {
		if got := publicPortBinding(binding); got != want {
			t.Errorf("publicPortBinding(%q) = %v, want %v", binding, got, want)
		}
	}
}
