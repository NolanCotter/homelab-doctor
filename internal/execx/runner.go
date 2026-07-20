// Package execx isolates host command execution so checks can be tested without host services.
package execx

import (
	"context"
	"os/exec"
)

// Result is the observable result of a command invocation.
type Result struct {
	Stdout string
	Stderr string
	Err    error
}

// Runner executes a command. Production code uses OSRunner; tests can supply a fake.
type Runner interface {
	Run(context.Context, string, ...string) Result
}

type OSRunner struct{}

func (OSRunner) Run(ctx context.Context, name string, args ...string) Result {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.Output()
	if err == nil {
		return Result{Stdout: string(out)}
	}
	if exit, ok := err.(*exec.ExitError); ok {
		return Result{Stdout: string(out), Stderr: string(exit.Stderr), Err: err}
	}
	return Result{Stdout: string(out), Err: err}
}
