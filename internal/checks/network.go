package checks

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/homelab-doctor/homelab-doctor/internal/report"
)

func networking(ctx context.Context, c Config) []report.Finding {
	var out []report.Finding
	ss := c.runner().Run(ctx, "ss", "-ltnupH")
	if ss.Err != nil {
		out = append(out, skipped("network", "network.listening_ports", commandUnavailable(ss)), skipped("network", "network.duplicate_port_binding", commandUnavailable(ss)))
	} else {
		lines := nonEmpty(ss.Stdout)
		out = append(out, finding("network", "network.listening_ports", report.StatusPass, report.SeverityInfo, linesOr(lines, "no TCP listeners reported"), "Listening ports reveal services reachable on this host.", "Confirm each listener is expected and scoped to the intended interface."))
		seen := map[string]int{}
		var dup []string
		for _, l := range lines {
			f := strings.Fields(l)
			if len(f) > 4 {
				seen[f[4]]++
				if seen[f[4]] == 2 {
					dup = append(dup, f[4])
				}
			}
		}
		status, sev := report.StatusPass, report.SeverityInfo
		if len(dup) > 0 {
			status, sev = report.StatusFinding, report.SeverityWarning
		}
		out = append(out, finding("network", "network.duplicate_port_binding", status, sev, linesOr(dup, "no duplicate listener addresses detected"), "Multiple listener entries for one address can be intentional (for example, IPv4 and IPv6) but merit review.", "Inspect the owning processes before modifying port mappings."))
	}
	route := c.runner().Run(ctx, "ip", "route", "show", "default")
	if route.Err != nil {
		out = append(out, skipped("network", "network.default_route", commandUnavailable(route)))
	} else {
		status, sev := report.StatusPass, report.SeverityInfo
		if len(nonEmpty(route.Stdout)) == 0 {
			status, sev = report.StatusFinding, report.SeverityWarning
		}
		out = append(out, finding("network", "network.default_route", status, sev, linesOr(nonEmpty(route.Stdout), "no default route"), "A default route is normally necessary for off-subnet access.", "Verify routing configuration if this host should have external connectivity."))
	}
	resolver, err := readFile(c.path("/etc/resolv.conf"))
	if err != nil {
		out = append(out, skipped("network", "network.dns_resolver", err.Error()))
	} else {
		lines := nonEmpty(resolver)
		has := false
		for _, l := range lines {
			if strings.HasPrefix(l, "nameserver ") {
				has = true
			}
		}
		status, sev := report.StatusPass, report.SeverityInfo
		if !has {
			status, sev = report.StatusFinding, report.SeverityWarning
		}
		out = append(out, finding("network", "network.dns_resolver", status, sev, linesOr(lines, "no resolver configuration"), "Name resolution is required by most package, certificate, and service workflows.", "Verify the resolver source and test the names your workloads use."))
	}
	var failures []string
	for _, target := range c.TCPProbeTargets {
		conn, e := net.DialTimeout("tcp", target, 2*time.Second)
		if e != nil {
			failures = append(failures, target+": "+e.Error())
		} else {
			_ = conn.Close()
		}
	}
	if len(c.TCPProbeTargets) == 0 {
		out = append(out, skipped("network", "network.local_tcp_probe", "no --tcp-probe target supplied"))
	} else {
		status, sev := report.StatusPass, report.SeverityInfo
		if len(failures) > 0 {
			status, sev = report.StatusFinding, report.SeverityWarning
		}
		out = append(out, finding("network", "network.local_tcp_probe", status, sev, linesOr(failures, "all local TCP probes succeeded"), "Local TCP probes test configured endpoints without sending data beyond connection setup.", "Check listener state, target address, and service logs for failed probes."))
	}
	out = append(out, skipped("network", "network.public_ip_lookup", "disabled by default; no external request was made"))
	return out
}
