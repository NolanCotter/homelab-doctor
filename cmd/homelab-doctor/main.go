package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/homelab-doctor/homelab-doctor/internal/bundle"
	"github.com/homelab-doctor/homelab-doctor/internal/checks"
	"github.com/homelab-doctor/homelab-doctor/internal/report"
)

const version = "1.0.0"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	switch args[0] {
	case "check":
		return check(args[1:], stdout, stderr)
	case "bundle":
		return makeBundle(args[1:], stdout, stderr)
	case "explain":
		return explain(args[1:], stdout, stderr)
	case "list-checks":
		return list(args[1:], stdout, stderr)
	case "version", "--version", "-version":
		return showVersion(args[1:], stdout, stderr)
	default:
		usage(stderr)
		return 2
	}
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "Usage: homelab-doctor <check|bundle|explain|list-checks|version> [flags]")
	fmt.Fprintln(w, "All current commands are read-only and never upload diagnostics.")
}

func newFlagSet(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs
}

func config(probes string) checks.Config {
	var p []string
	for _, target := range strings.Split(probes, ",") {
		if target = strings.TrimSpace(target); target != "" {
			p = append(p, target)
		}
	}
	return checks.Config{TCPProbeTargets: p}
}

func validProfile(profile string) bool {
	switch profile {
	case "", "all", "system", "docker", "storage", "networking":
		return true
	}
	return false
}

func validFormat(format string) bool {
	switch format {
	case "terminal", "json", "markdown":
		return true
	}
	return false
}

func check(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("check", stderr)
	profile := fs.String("profile", "", "all (default), system, docker, storage, or networking")
	format := fs.String("format", "terminal", "terminal, json, or markdown")
	dry := fs.Bool("dry-run", false, "show intended read-only checks")
	probe := fs.String("tcp-probe", "", "comma-separated host:port targets")
	if err := fs.Parse(args); err != nil {
		return parseResult(err)
	}
	if fs.NArg() != 0 {
		fatal(stderr, "unexpected argument: "+fs.Arg(0))
		return 2
	}
	if !validProfile(*profile) {
		fatal(stderr, "unknown profile: "+*profile)
		return 2
	}
	if !validFormat(*format) {
		fatal(stderr, "unknown format: "+*format)
		return 2
	}
	if *dry {
		fmt.Fprintln(stderr, "dry-run: checks are read-only; no commands will alter the machine")
	}
	r := report.Report{SchemaVersion: "1.0", GeneratedAt: time.Now().UTC(), ToolVersion: version, Findings: checks.Run(context.Background(), *profile, config(*probe))}.Sanitized(false)
	if err := render(r, *format, stdout); err != nil {
		fatal(stderr, err.Error())
		return 2
	}
	return 0
}

func makeBundle(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("bundle", stderr)
	output := fs.String("output", "diagnostics.tar.gz", "archive path")
	privacy := fs.String("privacy", "standard", "standard or private-ips")
	dry := fs.Bool("dry-run", false, "validate without writing")
	if err := fs.Parse(args); err != nil {
		return parseResult(err)
	}
	if fs.NArg() != 0 {
		fatal(stderr, "unexpected argument: "+fs.Arg(0))
		return 2
	}
	if *privacy != "standard" && *privacy != "private-ips" {
		fatal(stderr, "unknown privacy mode")
		return 2
	}
	if *dry {
		fmt.Fprintf(stdout, "dry-run: would write %s containing report.json, report.md, and manifest.json\n", *output)
		return 0
	}
	r := report.Report{SchemaVersion: "1.0", GeneratedAt: time.Now().UTC(), ToolVersion: version, Findings: checks.Run(context.Background(), "", config(""))}
	if err := bundle.Create(*output, r, *privacy == "private-ips"); err != nil {
		fatal(stderr, err.Error())
		return 2
	}
	fmt.Fprintf(stdout, "created read-only diagnostic bundle: %s\n", *output)
	return 0
}

func explain(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("explain", stderr)
	dry := fs.Bool("dry-run", false, "show that explain is read-only")
	if err := fs.Parse(args); err != nil {
		return parseResult(err)
	}
	if *dry {
		fmt.Fprintln(stderr, "dry-run: explain only prints check metadata")
	}
	if fs.NArg() != 1 {
		fatal(stderr, "usage: homelab-doctor explain [--dry-run] <CHECK_ID>")
		return 2
	}
	f, ok := checks.Explain(fs.Arg(0))
	if !ok {
		fatal(stderr, "unknown check ID: "+fs.Arg(0))
		return 2
	}
	fmt.Fprintf(stdout, "%s\n\n%s\n\nSafe remediation: %s\n", f.ID, f.Explanation, f.Remediation)
	return 0
}

func list(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("list-checks", stderr)
	dry := fs.Bool("dry-run", false, "show that list-checks is read-only")
	if err := fs.Parse(args); err != nil {
		return parseResult(err)
	}
	if fs.NArg() != 0 {
		fatal(stderr, "unexpected argument: "+fs.Arg(0))
		return 2
	}
	if *dry {
		fmt.Fprintln(stderr, "dry-run: list-checks only prints the check catalog")
	}
	for _, id := range checks.IDs() {
		fmt.Fprintln(stdout, id)
	}
	return 0
}

func showVersion(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("version", stderr)
	dry := fs.Bool("dry-run", false, "show that version is read-only")
	if err := fs.Parse(args); err != nil {
		return parseResult(err)
	}
	if fs.NArg() != 0 {
		fatal(stderr, "unexpected argument: "+fs.Arg(0))
		return 2
	}
	if *dry {
		fmt.Fprintln(stderr, "dry-run: version only prints tool metadata")
	}
	fmt.Fprintln(stdout, version)
	return 0
}

func render(r report.Report, format string, w io.Writer) error {
	switch format {
	case "terminal":
		_, err := io.WriteString(w, r.Terminal())
		return err
	case "json":
		b, err := r.JSON()
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(w, string(b))
		return err
	case "markdown":
		_, err := io.WriteString(w, r.Markdown())
		return err
	default:
		return errors.New("unknown format: " + format)
	}
}

func parseResult(err error) int {
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	return 2
}

func fatal(w io.Writer, s string) { fmt.Fprintln(w, "homelab-doctor:", s) }
