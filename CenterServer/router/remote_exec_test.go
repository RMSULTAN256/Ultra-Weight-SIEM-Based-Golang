package router

import (
	"strings"
	"testing"
)

// nodeAddrFor mengembalikan Addr dari hasil resolve, atau "" kalau gagal.
func nodeAddrFor(id string) string {
	node, err := ResolveNode(id)
	if err != nil {
		return ""
	}
	return node.Addr
}

// TestResolveNodeDeterministik: lookup yang sama harus selalu memberi node yang
// sama. Dulu (strings.Contains + iterasi map) ID node-2 bisa jatuh ke node-1.
func TestResolveNodeDeterministik(t *testing.T) {
	const id = "ubuntu-163.52.135.170"
	want := NodeSSHMap["ubuntu-2"].Addr

	for i := 0; i < 1000; i++ {
		if got := nodeAddrFor(id); got != want {
			t.Fatalf("iterasi %d: ResolveNode(%q) = %q, mau %q", i, id, got, want)
		}
	}
}

// TestResolveNodeTidakNyasar: ID yang tidak terdaftar harus 404, bukan
// "ditebak" ke node lain karena substring-nya mirip.
func TestResolveNodeTidakNyasar(t *testing.T) {
	kasus := []string{
		"ubuntu-2-163.52.135.170", // dulu: 91% jatuh ke node-1
		"ip-172-31-45-67",         // hostname default cloud
		"prod-1-only",
		"ubunt", // prefix, bukan alias
		"",
	}
	for _, id := range kasus {
		if _, err := ResolveNode(id); err == nil {
			t.Errorf("ResolveNode(%q) seharusnya error, tapi dapat node %q", id, nodeAddrFor(id))
		}
	}
}

func TestResolveNodeAlias(t *testing.T) {
	want := NodeSSHMap["ubuntu-2"]
	for _, id := range []string{"ubuntu-2", "163.52.135.170", "ubuntu-163.52.135.170"} {
		node, err := ResolveNode(id)
		if err != nil {
			t.Fatalf("ResolveNode(%q) error: %v", id, err)
		}
		if node.Addr != want.Addr || node.ServiceName != want.ServiceName {
			t.Errorf("ResolveNode(%q) = %+v, mau addr %s service %s", id, node, want.Addr, want.ServiceName)
		}
	}

	// Case-insensitive, tapi tetap exact (tidak ada substring match).
	if nodeAddrFor("UBUNTU-2") != want.Addr {
		t.Errorf("lookup case-insensitive gagal")
	}
}

// TestBuildCommandIkutNode: ServiceName harus berasal dari node yang di-resolve,
// bukan dari node lain (dulu ResolveCommand melakukan lookup ulang sendiri).
func TestBuildCommandIkutNode(t *testing.T) {
	node2, err := ResolveNode("163.52.135.170")
	if err != nil {
		t.Fatalf("resolve node2: %v", err)
	}
	cmd, err := BuildCommand(node2, "agent_status")
	if err != nil {
		t.Fatalf("BuildCommand: %v", err)
	}
	if !strings.Contains(cmd, "agentGo.service") {
		t.Errorf("command = %q, harus memakai service milik node-2 (agentGo)", cmd)
	}
	if strings.Contains(cmd, NodeSSHMap["ubuntu"].ServiceName+".service") {
		t.Errorf("command = %q, tidak boleh memakai service node-1", cmd)
	}

	node1 := NodeSSHMap["ubuntu"]
	cmd1, err := BuildCommand(node1, "agent_status")
	if err != nil {
		t.Fatalf("BuildCommand node1: %v", err)
	}
	if !strings.Contains(cmd1, node1.ServiceName+".service") {
		t.Errorf("command = %q, harus memakai service node-1", cmd1)
	}
}

func TestBuildCommandMenolakKeyAsing(t *testing.T) {
	node := NodeSSHMap["ubuntu"]
	kasus := []string{"", "rm -rf /", "agent_status; reboot", "whoami", "AGENT_STATUS"}
	for _, key := range kasus {
		if _, err := BuildCommand(node, key); err == nil {
			t.Errorf("BuildCommand(%q) seharusnya ditolak", key)
		}
	}

	// Perintah whitelist tetap boleh, dan tidak diinterpolasi ke ServiceName.
	if cmd, err := BuildCommand(node, "ports"); err != nil || cmd != "ss -tuln" {
		t.Errorf("BuildCommand(ports) = %q, %v", cmd, err)
	}
}

// TestHostKeyFailClosed: known_hosts tidak ada -> error, bukan InsecureIgnoreHostKey.
func TestHostKeyFailClosed(t *testing.T) {
	t.Setenv("SSH_INSECURE_HOST_KEY", "")

	node := NodeSSHMap["ubuntu"]
	node.KnownHosts = "/nonexistent/known_hosts_dir/known_hosts"
	node.HostKeyPin = ""

	if _, err := hostKeyCallback(node); err == nil {
		t.Fatal("host key callback seharusnya error (fail-closed), tapi lolos")
	}
}

// TestHostKeyPinMode: kalau pin diisi, known_hosts tidak dibutuhkan.
func TestHostKeyPinMode(t *testing.T) {
	t.Setenv("SSH_INSECURE_HOST_KEY", "")

	node := NodeSSHMap["ubuntu"]
	node.KnownHosts = "/nonexistent/known_hosts_dir/known_hosts"
	node.HostKeyPin = "SHA256:abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"

	cb, err := hostKeyCallback(node)
	if err != nil || cb == nil {
		t.Fatalf("mode pinning seharusnya tidak butuh known_hosts: %v", err)
	}
}

// TestInsecureHanyaKalauEksplisit: fallback insecure tidak boleh aktif default.
func TestInsecureHanyaKalauEksplisit(t *testing.T) {
	for _, v := range []string{"", "0", "false", "no", "off", "nggak"} {
		t.Setenv("SSH_INSECURE_HOST_KEY", v)
		if insecureHostKeyAllowed() {
			t.Errorf("SSH_INSECURE_HOST_KEY=%q seharusnya tidak mengaktifkan insecure", v)
		}
	}
	for _, v := range []string{"1", "true", "TRUE", "yes", "on"} {
		t.Setenv("SSH_INSECURE_HOST_KEY", v)
		if !insecureHostKeyAllowed() {
			t.Errorf("SSH_INSECURE_HOST_KEY=%q seharusnya dianggap aktif", v)
		}
	}
}
