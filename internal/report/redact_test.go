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
func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
