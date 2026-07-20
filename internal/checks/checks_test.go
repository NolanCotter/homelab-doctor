package checks

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/homelab-doctor/homelab-doctor/internal/execx"
	"github.com/homelab-doctor/homelab-doctor/internal/report"
)

type fakeRunner map[string]execx.Result

func (f fakeRunner) Run(_ context.Context, name string, args ...string) execx.Result {
	if r, ok := f[name+" "+strings.Join(args, " ")]; ok {
		return r
	}
	return execx.Result{Err: errors.New("not mocked")}
}
func find(fs []report.Finding, id string) report.Finding {
	for _, f := range fs {
		if f.ID == id {
			return f
		}
	}
	return report.Finding{}
}

func TestDockerFixtureFindings(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "compose.yml"), []byte("services:\n  app:\n    image: x:${MISSING_TAG}\n    environment:\n      DB_PASSWORD: topsecret\n"), 0600); err != nil {
		t.Fatal(err)
	}
	r := fakeRunner{"docker info --format {{json .}}": {Stdout: "{}"}, "docker ps -a --format {{json .}}": {Stdout: `{"Names":"web","Status":"Up 2m (unhealthy)","State":"running","Ports":"0.0.0.0:8080->80/tcp"}` + "\n" + `{"Names":"worker","Status":"Restarting (1)","State":"restarting"}`}, "docker system df --format {{json .}}": {Stdout: "{}"}}
	fs := docker(context.Background(), Config{Runner: r, ComposeRoots: []string{root}})
	for _, id := range []string{"docker.unhealthy_containers", "docker.restart_loop", "docker.compose.missing_env", "security.plaintext_compose_password"} {
		if f := find(fs, id); f.Status != report.StatusFinding {
			t.Errorf("%s = %s", id, f.Status)
		}
	}
}
func TestInaccessibleDockerSocketIsSkipped(t *testing.T) {
	fs := security(context.Background(), Config{Root: t.TempDir()})
	if f := find(fs, "security.docker_socket_exposure"); f.Status != report.StatusSkipped {
		t.Fatalf("got %s", f.Status)
	}
}
func TestMalformedDockerOutputDoesNotPanic(t *testing.T) {
	fs := dockerContainers("not json", Config{})
	if f := find(fs, "docker.healthcheck"); f.Status != report.StatusFinding {
		t.Fatalf("got %s", f.Status)
	}
}
func TestCatalogHasStableUniqueIDs(t *testing.T) {
	seen := map[string]bool{}
	for _, id := range IDs() {
		if seen[id] {
			t.Fatalf("duplicate %s", id)
		}
		seen[id] = true
		if _, ok := Explain(id); !ok {
			t.Fatalf("not explainable: %s", id)
		}
	}
}
