package checks

import (
	"context"
	"fmt"
	"runtime"
	"strconv"
	"strings"

	"github.com/homelab-doctor/homelab-doctor/internal/report"
)

func system(ctx context.Context, c Config) []report.Finding {
	var out []report.Finding
	kernel, kerr := readFile(c.path("/proc/version"))
	osrel, oerr := readFile(c.path("/etc/os-release"))
	if kerr != nil && oerr != nil {
		out = append(out, skipped("system", "system.distribution_kernel", "cannot read /proc/version or /etc/os-release"))
	} else {
		out = append(out, finding("system", "system.distribution_kernel", report.StatusPass, report.SeverityInfo, []string{firstLine(osrel), firstLine(kernel)}, "Kernel and distribution information establishes diagnostic context.", "Keep your distribution and supported kernel security updates current."))
	}

	up, err := readFile(c.path("/proc/uptime"))
	if err != nil {
		out = append(out, skipped("system", "system.uptime", err.Error()))
	} else {
		out = append(out, finding("system", "system.uptime", report.StatusPass, report.SeverityInfo, []string{"uptime seconds: " + strings.Fields(up)[0]}, "Long uptimes are informational; they can help correlate a problem with a deployment or reboot.", "Plan maintenance reboots when kernel updates or service changes require them."))
	}

	mem, err := readFile(c.path("/proc/meminfo"))
	if err != nil {
		out = append(out, skipped("system", "system.memory_pressure", err.Error()))
	} else {
		avail, total := memKB(mem, "MemAvailable"), memKB(mem, "MemTotal")
		status, sev := report.StatusPass, report.SeverityInfo
		if total > 0 && avail*100/total < 10 {
			status, sev = report.StatusFinding, report.SeverityWarning
		}
		out = append(out, finding("system", "system.memory_pressure", status, sev, []string{fmt.Sprintf("MemAvailable=%d kB; MemTotal=%d kB", avail, total)}, "Low available memory can cause swapping, OOM kills, and service latency.", "Identify memory-heavy workloads and size limits; reserve enough memory for the host."))
	}

	load, err := readFile(c.path("/proc/loadavg"))
	if err != nil {
		out = append(out, skipped("system", "system.load_average", err.Error()))
	} else {
		fields := strings.Fields(load)
		status, sev := report.StatusPass, report.SeverityInfo
		if len(fields) > 0 {
			if v, e := strconv.ParseFloat(fields[0], 64); e == nil && v > float64(max(1, runtimeCPU()))*2 {
				status, sev = report.StatusFinding, report.SeverityWarning
			}
		}
		out = append(out, finding("system", "system.load_average", status, sev, []string{firstLine(load)}, "Sustained load well above CPU capacity can indicate CPU, I/O, or uninterruptible work contention.", "Correlate load with CPU, disk I/O, and process-level metrics before changing workloads."))
	}

	units := c.runner().Run(ctx, "systemctl", "--failed", "--no-legend", "--plain")
	if units.Err != nil {
		out = append(out, skipped("system", "system.failed_units", commandUnavailable(units)))
	} else {
		lines := nonEmpty(units.Stdout)
		status, sev := report.StatusPass, report.SeverityInfo
		if len(lines) > 0 {
			status, sev = report.StatusFinding, report.SeverityWarning
		}
		out = append(out, finding("system", "system.failed_units", status, sev, linesOr(lines, "no failed systemd units"), "Failed units can prevent dependencies from starting or recovering.", "Inspect each unit with journalctl and systemctl status; correct configuration before manually restarting it."))
	}

	clock := c.runner().Run(ctx, "timedatectl", "show", "-p", "NTPSynchronized", "--value")
	if clock.Err != nil {
		out = append(out, skipped("system", "system.clock_synchronization", commandUnavailable(clock)))
	} else {
		synced := strings.TrimSpace(clock.Stdout) == "yes"
		status, sev := report.StatusPass, report.SeverityInfo
		if !synced {
			status, sev = report.StatusFinding, report.SeverityWarning
		}
		out = append(out, finding("system", "system.clock_synchronization", status, sev, []string{"NTPSynchronized=" + strings.TrimSpace(clock.Stdout)}, "Accurate time matters for TLS, logs, backups, and clustered services.", "Verify the configured time service and its upstream reachability."))
	}
	return out
}

func memKB(s, key string) int64 {
	for _, l := range strings.Split(s, "\n") {
		f := strings.Fields(l)
		if len(f) >= 2 && strings.TrimSuffix(f[0], ":") == key {
			v, _ := strconv.ParseInt(f[1], 10, 64)
			return v
		}
	}
	return 0
}
func firstLine(s string) string {
	l := nonEmpty(s)
	if len(l) == 0 {
		return "unavailable"
	}
	return l[0]
}
func nonEmpty(s string) []string {
	var o []string
	for _, l := range strings.Split(s, "\n") {
		if strings.TrimSpace(l) != "" {
			o = append(o, strings.TrimSpace(l))
		}
	}
	return o
}
func linesOr(a []string, fallback string) []string {
	if len(a) == 0 {
		return []string{fallback}
	}
	return a
}
func runtimeCPU() int { return runtime.NumCPU() }
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
