package services

import (
	"strings"
	"testing"
	"time"
)

const hmacSecretUji = "kunci-uji-hmac-32-karakter-panjang"

func TestGenerateHMACDeterministik(t *testing.T) {
	ts := time.Now().Unix()
	payload := []byte(`{"agent":"ubuntu","command_key":"ports"}`)

	want := GenerateHMAC(hmacSecretUji, payload, ts)
	if len(want) != 64 {
		t.Fatalf("signature harus 64 karakter hex (SHA-256), dapat %d", len(want))
	}
	for i := 0; i < 100; i++ {
		if got := GenerateHMAC(hmacSecretUji, payload, ts); got != want {
			t.Fatalf("iterasi %d: signature berubah, HMAC tidak deterministik", i)
		}
	}
	if GenerateHMAC(hmacSecretUji, []byte(`{"agent":"ubuntu","command_key":"disk"}`), ts) == want {
		t.Error("payload berbeda seharusnya menghasilkan signature berbeda")
	}
	if GenerateHMAC("secret-lain", payload, ts) == want {
		t.Error("secret berbeda seharusnya menghasilkan signature berbeda")
	}
}

func TestVerifyHMACMenerimaTandaTanganSendiri(t *testing.T) {
	payload := []byte(`{"agent":"ubuntu"}`)
	ts := time.Now().Unix()

	if !VerifyHMAC(hmacSecretUji, payload, ts, GenerateHMAC(hmacSecretUji, payload, ts)) {
		t.Fatal("signature hasil GenerateHMAC harus lolos VerifyHMAC")
	}
}

func TestVerifyHMACMenolak(t *testing.T) {
	payload := []byte(`{"command_key":"restart_agent"}`)
	ts := time.Now().Unix()
	valid := GenerateHMAC(hmacSecretUji, payload, ts)

	cases := []struct {
		name    string
		payload []byte
		ts      int64
		sig     string
	}{
		{"payload diubah", []byte(`{"command_key":"rm -rf /"}`), ts, valid},
		{"signature palsu", payload, ts, strings.Repeat("f", 64)},
		{"signature kosong", payload, ts, ""},
		{"replay 31 detik lalu", payload, ts - 31, GenerateHMAC(hmacSecretUji, payload, ts-31)},
		{"timestamp 31 detik ke depan", payload, ts + 31, GenerateHMAC(hmacSecretUji, payload, ts+31)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if VerifyHMAC(hmacSecretUji, tc.payload, tc.ts, tc.sig) {
				t.Errorf("%s: seharusnya ditolak", tc.name)
			}
		})
	}
}

func TestVerifyHMACJendelaWaktu(t *testing.T) {
	payload := []byte(`{"ping":true}`)

	for _, delta := range []int64{-29, -10, 0, 10, 29} {
		ts := time.Now().Unix() + delta
		if !VerifyHMAC(hmacSecretUji, payload, ts, GenerateHMAC(hmacSecretUji, payload, ts)) {
			t.Errorf("delta %d detik seharusnya masih diterima", delta)
		}
	}
}
