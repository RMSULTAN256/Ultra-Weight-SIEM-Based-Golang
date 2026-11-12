package services

import (
	"strings"
	"testing"
	"time"
)

const testSecret = "kunci-uji-hmac-32-karakter-panjang"

// TestGenerateHMACDeterministik memastikan signature stabil untuk input yang
// sama. Kalau ini goyang, verifikasi di CenterServer akan menolak paket valid.
func TestGenerateHMACDeterministik(t *testing.T) {
	ts := time.Now().Unix()
	payload := []byte(`{"command_key":"ports"}`)

	want := GenerateHMAC(testSecret, payload, ts)
	if len(want) != 64 {
		t.Fatalf("signature harus 64 karakter hex (SHA-256), dapat %d", len(want))
	}
	for i := 0; i < 200; i++ {
		if got := GenerateHMAC(testSecret, payload, ts); got != want {
			t.Fatalf("iterasi %d: signature berubah, HMAC tidak deterministik", i)
		}
	}

	// Payload, secret, dan timestamp masing-masing harus mengubah hasil.
	if GenerateHMAC(testSecret, []byte(`{"command_key":"disk"}`), ts) == want {
		t.Error("payload berbeda seharusnya menghasilkan signature berbeda")
	}
	if GenerateHMAC("secret-lain", payload, ts) == want {
		t.Error("secret berbeda seharusnya menghasilkan signature berbeda")
	}
	if GenerateHMAC(testSecret, payload, ts+1) == want {
		t.Error("timestamp berbeda seharusnya menghasilkan signature berbeda")
	}
}

func TestVerifyHMACMenerimaTandaTanganSendiri(t *testing.T) {
	payload := []byte(`{"command_key":"uptime"}`)
	ts := time.Now().Unix()

	sig := GenerateHMAC(testSecret, payload, ts)
	if !VerifyHMAC(testSecret, payload, ts, sig) {
		t.Fatal("signature yang dibuat GenerateHMAC harus lolos VerifyHMAC")
	}
}

// TestVerifyHMACMenolak menutup jalur serangan dasar: payload dimodifikasi,
// signature palsu, dan paket replay di luar jendela toleransi.
func TestVerifyHMACMenolak(t *testing.T) {
	payload := []byte(`{"command_key":"restart_agent"}`)
	ts := time.Now().Unix()
	validSig := GenerateHMAC(testSecret, payload, ts)

	cases := []struct {
		name    string
		payload []byte
		ts      int64
		sig     string
	}{
		{"payload diubah", []byte(`{"command_key":"rm -rf /"}`), ts, validSig},
		{"signature palsu", payload, ts, strings.Repeat("a", 64)},
		{"signature kosong", payload, ts, ""},
		{"signature dipotong", payload, ts, validSig[:32]},
		{"replay 31 detik lalu", payload, ts - 31, GenerateHMAC(testSecret, payload, ts-31)},
		{"timestamp 31 detik ke depan", payload, ts + 31, GenerateHMAC(testSecret, payload, ts+31)},
		{"secret salah", payload, ts, GenerateHMAC("secret-penyerang", payload, ts)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if VerifyHMAC(testSecret, tc.payload, tc.ts, tc.sig) {
				t.Errorf("%s: seharusnya ditolak, tapi lolos verifikasi", tc.name)
			}
		})
	}
}

// TestVerifyHMACJendelaWaktu memastikan toleransi ±30 detik memang berlaku,
// supaya skew jam kecil antar host tidak membuat semua paket ditolak.
func TestVerifyHMACJendelaWaktu(t *testing.T) {
	payload := []byte(`{"ping":true}`)

	for _, delta := range []int64{-29, -10, 0, 10, 29} {
		ts := time.Now().Unix() + delta
		sig := GenerateHMAC(testSecret, payload, ts)
		if !VerifyHMAC(testSecret, payload, ts, sig) {
			t.Errorf("delta %d detik seharusnya masih diterima", delta)
		}
	}
}
