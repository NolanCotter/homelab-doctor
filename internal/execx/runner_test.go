package execx

import (
	"context"
	"os/exec"
	"strings"
	"testing"
)

func TestOSRunnerSuccess(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh unavailable")
	}
	res := (OSRunner{}).Run(context.Background(), "sh", "-c", "printf hello")
	if res.Err != nil {
		t.Fatalf("unexpected error: %v", res.Err)
	}
	if res.Stdout != "hello" {
		t.Fatalf("stdout = %q", res.Stdout)
	}
	if res.Stderr != "" {
		t.Fatalf("stderr = %q", res.Stderr)
	}
}

func TestOSRunnerCapturesExitErrorAndStderr(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh unavailable")
	}
	res := (OSRunner{}).Run(context.Background(), "sh", "-c", "printf out; printf err >&2; exit 3")
	if res.Err == nil {
		t.Fatal("expected an error")
	}
	if res.Stdout != "out" {
		t.Fatalf("stdout = %q", res.Stdout)
	}
	if !strings.Contains(res.Stderr, "err") {
		t.Fatalf("stderr = %q", res.Stderr)
	}
}

func TestOSRunnerMissingCommand(t *testing.T) {
	res := (OSRunner{}).Run(context.Background(), "homelab-doctor-command-that-does-not-exist")
	if res.Err == nil {
		t.Fatal("expected a lookup error")
	}
}

func TestOSRunnerCanceledContext(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh unavailable")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res := (OSRunner{}).Run(ctx, "sh", "-c", "sleep 1")
	if res.Err == nil {
		t.Fatal("expected a context error")
	}
}
