package services

import (
	"strings"
	"testing"
)

func TestHandleContainmentAction_Validation(t *testing.T) {
	// 1. IP kosong
	out, code := handleContainmentAction("block_ip", map[string]string{})
	if code == 0 || !strings.Contains(out, "tidak disertakan") {
		t.Errorf("Seharusnya menolak IP kosong, dapat: %s (code=%d)", out, code)
	}

	// 2. Format IP tidak valid (mencegah shell injection)
	out, code = handleContainmentAction("block_ip", map[string]string{"ip": "1.2.3.4; rm -rf /"})
	if code == 0 || !strings.Contains(out, "tidak valid") {
		t.Errorf("Seharusnya menolak IP dengan format berbahaya, dapat: %s (code=%d)", out, code)
	}

	// 3. Loopback IP dilarang diblokir (IPv4 & IPv6 via target_ip)
	out, code = handleContainmentAction("block_ip", map[string]string{"ip": "127.0.0.1"})
	if code == 0 || !strings.Contains(out, "loopback") {
		t.Errorf("Seharusnya menolak pemblokiran loopback IPv4, dapat: %s (code=%d)", out, code)
	}

	out, code = handleContainmentAction("block_ip", map[string]string{"target_ip": "::1"})
	if code == 0 || !strings.Contains(out, "loopback") {
		t.Errorf("Seharusnya menolak pemblokiran loopback IPv6, dapat: %s (code=%d)", out, code)
	}

	// 4. Aksi tidak dikenali
	out, code = handleContainmentAction("unknown_action", map[string]string{"ip": "192.168.1.50"})
	if code == 0 || !strings.Contains(out, "tidak dikenali") {
		t.Errorf("Seharusnya menolak aksi tidak dikenal, dapat: %s (code=%d)", out, code)
	}

	// 5. Containment status dan valid IP containment action tidak panic
	statusOut, _ := handleContainmentAction("containment_status", map[string]string{})
	if statusOut == "" {
		t.Error("containment_status seharusnya tidak menghasilkan output kosong")
	}

	actionOut, _ := handleContainmentAction("unblock_ip", map[string]string{"ip": "198.51.100.99"})
	if actionOut == "" {
		t.Error("unblock_ip seharusnya tidak menghasilkan output kosong")
	}
}
