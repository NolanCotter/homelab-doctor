package report

import "testing"

func TestRedactSecretsAndPrivateIPs(t *testing.T) {
	got := Redact("PASSWORD=hunter2 Authorization: Bearer abc.def token: xyz Authorization: Basic Zm9vOmJhcg== at 10.1.2.3", true)
	for _, bad := range []string{"hunter2", "abc.def", "xyz", "Zm9vOmJhcg==", "10.1.2.3"} {
		if contains(got, bad) {
			t.Errorf("unredacted %q in %q", bad, got)
		}
	}
}

func TestRedactKeepsPublicIPsAndKeyNames(t *testing.T) {
	got := Redact("api_key=secret 203.0.113.9", true)
	if contains(got, "secret") {
		t.Errorf("secret not redacted: %q", got)
	}
	if !contains(got, "203.0.113.9") {
		t.Errorf("public IP unexpectedly masked: %q", got)
	}
	if !contains(got, "api_key=") {
		t.Errorf("key name should be retained: %q", got)
	}
}

func TestRedactPrivateIPsOptionalAndIPv6(t *testing.T) {
	in := "host 192.168.1.10 and fd00::1 and 10.0.0.1"
	if got := Redact(in, false); contains(got, "[PRIVATE-IP]") {
		t.Errorf("private IP masked without opt-in: %q", got)
	}
	got := Redact(in, true)
	for _, bad := range []string{"192.168.1.10", "fd00::1", "10.0.0.1"} {
		if contains(got, bad) {
			t.Errorf("private address %q not masked: %q", bad, got)
		}
	}
}

func TestRedactLinesTrimsAndAllocates(t *testing.T) {
	in := []string{"  token=abc  ", "\tPASSWORD=def\n"}
	out := RedactLines(in, false)
	if len(out) != 2 {
		t.Fatalf("got %d lines", len(out))
	}
	for _, line := range out {
		if contains(line, "abc") || contains(line, "def") {
			t.Errorf("line not redacted: %q", line)
		}
		if line != trimSpace(line) {
			t.Errorf("line not trimmed: %q", line)
		}
	}
	if in[0] != "  token=abc  " || in[1] != "\tPASSWORD=def\n" {
		t.Errorf("input mutated: %#v", in)
	}
}

func trimSpace(s string) string {
	start, end := 0, len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t' || s[start] == '\n' || s[start] == '\r') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t' || s[end-1] == '\n' || s[end-1] == '\r') {
		end--
	}
	return s[start:end]
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
