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

	// 3. Loopback IP dilarang diblokir
	out, code = handleContainmentAction("block_ip", map[string]string{"ip": "127.0.0.1"})
	if code == 0 || !strings.Contains(out, "loopback") {
		t.Errorf("Seharusnya menolak pemblokiran loopback IP, dapat: %s (code=%d)", out, code)
	}

	// 4. Aksi tidak dikenali
	out, code = handleContainmentAction("unknown_action", map[string]string{"ip": "192.168.1.50"})
	if code == 0 || !strings.Contains(out, "tidak dikenali") {
		t.Errorf("Seharusnya menolak aksi tidak dikenal, dapat: %s (code=%d)", out, code)
	}
}
