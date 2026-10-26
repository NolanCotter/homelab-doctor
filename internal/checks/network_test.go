package checks

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/homelab-doctor/homelab-doctor/internal/report"
)

func TestNetworkingListenersRoutesDNSAndProbes(t *testing.T) {
	root := t.TempDir()
	writeRootFile(t, root, "/etc/resolv.conf", "nameserver 1.1.1.1\n")
	ss := strings.Join([]string{
		"tcp LISTEN 0 4096 0.0.0.0:22 0.0.0.0:*",
		"tcp LISTEN 0 4096 0.0.0.0:22 0.0.0.0:*",
		"tcp LISTEN 0 4096 127.0.0.1:8080 0.0.0.0:*",
	}, "\n")
	r := fakeRunner{
		"ss -ltnupH":            {Stdout: ss},
		"ip route show default": {Stdout: "default via 192.168.1.1 dev eth0\n"},
	}

	good, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer good.Close()
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	badTarget := closed.Addr().String()
	_ = closed.Close()

	fs := networking(context.Background(), Config{Root: root, Runner: r, TCPProbeTargets: []string{good.Addr().String(), badTarget}})
	if f := find(fs, "network.listening_ports"); f.Status != report.StatusPass || len(f.Evidence) != 3 {
		t.Errorf("listeners = %+v", f)
	}
	if f := find(fs, "network.duplicate_port_binding"); f.Status != report.StatusFinding || f.Evidence[0] != "0.0.0.0:22" {
		t.Errorf("duplicates = %+v", f)
	}
	if f := find(fs, "network.default_route"); f.Status != report.StatusPass {
		t.Errorf("route = %+v", f)
	}
	if f := find(fs, "network.dns_resolver"); f.Status != report.StatusPass {
		t.Errorf("dns = %+v", f)
	}
	if f := find(fs, "network.local_tcp_probe"); f.Status != report.StatusFinding || !strings.Contains(strings.Join(f.Evidence, ";"), badTarget) {
		t.Errorf("probe = %+v", f)
	}
	if f := find(fs, "network.public_ip_lookup"); f.Status != report.StatusSkipped {
		t.Errorf("public lookup = %+v", f)
	}
}

func TestNetworkingMissingInputsAreSkipped(t *testing.T) {
	fs := networking(context.Background(), Config{Root: t.TempDir(), Runner: fakeRunner{}})
	for _, id := range []string{"network.listening_ports", "network.duplicate_port_binding", "network.default_route", "network.dns_resolver", "network.local_tcp_probe", "network.public_ip_lookup"} {
		if f := find(fs, id); f.Status != report.StatusSkipped {
			t.Errorf("%s = %s, want skipped", id, f.Status)
		}
	}
}

func TestNetworkingNoRouteOrNameserverIsFinding(t *testing.T) {
	root := t.TempDir()
	writeRootFile(t, root, "/etc/resolv.conf", "# no nameserver\nsearch example.test\n")
	r := fakeRunner{"ss -ltnupH": {Stdout: ""}, "ip route show default": {Stdout: ""}}
	fs := networking(context.Background(), Config{Root: root, Runner: r})
	if f := find(fs, "network.default_route"); f.Status != report.StatusFinding {
		t.Errorf("route = %+v", f)
	}
	if f := find(fs, "network.dns_resolver"); f.Status != report.StatusFinding {
		t.Errorf("dns = %+v", f)
	}
	if f := find(fs, "network.listening_ports"); f.Status != report.StatusPass {
		t.Errorf("listeners = %+v", f)
	}
	if f := find(fs, "network.duplicate_port_binding"); f.Status != report.StatusPass {
		t.Errorf("duplicates = %+v", f)
	}
}
