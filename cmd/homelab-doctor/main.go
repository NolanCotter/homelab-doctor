package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/homelab-doctor/homelab-doctor/internal/bundle"
	"github.com/homelab-doctor/homelab-doctor/internal/checks"
	"github.com/homelab-doctor/homelab-doctor/internal/report"
)

const version = "0.1.0"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "check":
		check(os.Args[2:])
	case "bundle":
		makeBundle(os.Args[2:])
	case "explain":
		explain(os.Args[2:])
	case "list-checks":
		list()
	case "version", "--version", "-version":
		fmt.Println(version)
	default:
		usage()
		os.Exit(2)
	}
}
func usage() {
	fmt.Fprintln(os.Stderr, "Usage: homelab-doctor <check|bundle|explain|list-checks> [flags]\nAll current commands are read-only and never upload diagnostics.")
}
func config(probes string) checks.Config {
	var p []string
	if probes != "" {
		p = strings.Split(probes, ",")
	}
	return checks.Config{TCPProbeTargets: p}
}
func check(args []string) {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	profile := fs.String("profile", "", "docker, storage, networking, or all (default)")
	format := fs.String("format", "terminal", "terminal, json, or markdown")
	dry := fs.Bool("dry-run", false, "show intended read-only checks")
	probe := fs.String("tcp-probe", "", "comma-separated host:port targets")
	_ = fs.Parse(args)
	if *profile != "" && *profile != "docker" && *profile != "storage" && *profile != "networking" && *profile != "system" {
		fatal("unknown profile: " + *profile)
	}
	if *dry {
		fmt.Fprintln(os.Stderr, "dry-run: checks are read-only; no commands will alter the machine")
	}
	r := report.Report{SchemaVersion: "1.0", GeneratedAt: time.Now().UTC(), ToolVersion: version, Findings: checks.Run(context.Background(), *profile, config(*probe))}.Sanitized(false)
	render(r, *format)
}
func makeBundle(args []string) {
	fs := flag.NewFlagSet("bundle", flag.ExitOnError)
	output := fs.String("output", "diagnostics.tar.gz", "archive path")
	privacy := fs.String("privacy", "standard", "standard or private-ips")
	dry := fs.Bool("dry-run", false, "validate without writing")
	_ = fs.Parse(args)
	if *privacy != "standard" && *privacy != "private-ips" {
		fatal("unknown privacy mode")
	}
	r := report.Report{SchemaVersion: "1.0", GeneratedAt: time.Now().UTC(), ToolVersion: version, Findings: checks.Run(context.Background(), "", config(""))}
	if *dry {
		fmt.Printf("dry-run: would write %s containing report.json, report.md, and manifest.json\n", *output)
		return
	}
	if err := bundle.Create(*output, r, *privacy == "private-ips"); err != nil {
		fatal(err.Error())
	}
	fmt.Printf("created read-only diagnostic bundle: %s\n", *output)
}
func explain(args []string) {
	if len(args) != 1 {
		fatal("usage: homelab-doctor explain <CHECK_ID>")
	}
	f, ok := checks.Explain(args[0])
	if !ok {
		fatal("unknown check ID: " + args[0])
	}
	fmt.Printf("%s\n\n%s\n\nSafe remediation: %s\n", f.ID, f.Explanation, f.Remediation)
}
func list() {
	for _, id := range checks.IDs() {
		fmt.Println(id)
	}
}
func render(r report.Report, format string) {
	switch format {
	case "terminal":
		fmt.Print(r.Terminal())
	case "json":
		b, e := r.JSON()
		if e != nil {
			fatal(e.Error())
		}
		fmt.Println(string(b))
	case "markdown":
		fmt.Print(r.Markdown())
	default:
		fatal("unknown format: " + format)
	}
}
func fatal(s string) { fmt.Fprintln(os.Stderr, "homelab-doctor:", s); os.Exit(2) }
