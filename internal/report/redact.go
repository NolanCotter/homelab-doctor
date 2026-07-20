package report

import (
	"net"
	"regexp"
	"strings"
)

var sensitive = regexp.MustCompile(`(?i)(password|passwd|token|api[_-]?key|secret|cookie|authorization)\s*([:=])\s*([^\s,;"']+)`)
var authBearer = regexp.MustCompile(`(?i)(bearer\s+)[A-Za-z0-9._~+/-]+`)
var authHeader = regexp.MustCompile(`(?i)(authorization\s*[:=]\s*)(?:(?:bearer|basic|token|digest)\s+)?[^\s,;"']+`)
var ipv4 = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
var ipv6 = regexp.MustCompile(`(?i)\b[0-9a-f]{1,4}(?::[0-9a-f]{0,4}){2,}\b`)

// Redact masks credential-shaped values while retaining their key names for diagnostics.
func Redact(s string, privateIPs bool) string {
	s = authHeader.ReplaceAllString(s, "${1}[REDACTED]")
	s = sensitive.ReplaceAllString(s, "$1$2[REDACTED]")
	s = authBearer.ReplaceAllString(s, "${1}[REDACTED]")
	if !privateIPs {
		return s
	}
	maskIP := func(v string) string {
		ip := net.ParseIP(v)
		if ip != nil && ip.IsPrivate() {
			return "[PRIVATE-IP]"
		}
		return v
	}
	s = ipv4.ReplaceAllStringFunc(s, maskIP)
	return ipv6.ReplaceAllStringFunc(s, maskIP)
}

func RedactLines(lines []string, privateIPs bool) []string {
	out := make([]string, len(lines))
	for i, v := range lines {
		out[i] = Redact(strings.TrimSpace(v), privateIPs)
	}
	return out
}
