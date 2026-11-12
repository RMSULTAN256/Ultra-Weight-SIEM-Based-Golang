package auth

import (
	"strings"
	"testing"
)

func TestHashPasswordBukanPlaintext(t *testing.T) {
	const password = "rahasia-super-123"

	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword gagal: %v", err)
	}
	if hash == "" {
		t.Fatal("hash tidak boleh kosong")
	}
	if strings.Contains(hash, password) {
		t.Fatal("hash tidak boleh memuat password plaintext")
	}
	// bcrypt selalu diawali "$2a$", "$2b$", atau "$2y$".
	if !strings.HasPrefix(hash, "$2") {
		t.Errorf("hash tidak terlihat seperti bcrypt: %q", hash)
	}
}

func TestComparePasswordHash(t *testing.T) {
	const password = "rahasia-super-123"

	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword gagal: %v", err)
	}

	ok, err := ComparePasswordHash(hash, password)
	if err != nil {
		t.Fatalf("ComparePasswordHash(password benar) gagal: %v", err)
	}
	if !ok {
		t.Fatal("password benar seharusnya cocok")
	}

	ok, err = ComparePasswordHash(hash, "password-salah")
	if err == nil {
		t.Error("password salah seharusnya mengembalikan error bcrypt")
	}
	if ok {
		t.Fatal("password salah tidak boleh dianggap cocok")
	}
}

// TestHashPasswordSaltUnik: dua hash untuk password sama harus berbeda,
// kalau tidak berarti salt tidak dipakai.
func TestHashPasswordSaltUnik(t *testing.T) {
	const password = "password-sama"

	hashA, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword gagal: %v", err)
	}
	hashB, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword gagal: %v", err)
	}

	if hashA == hashB {
		t.Fatal("dua hash untuk password sama tidak boleh identik (salt tidak jalan)")
	}
	// Keduanya tetap harus valid untuk password yang sama.
	for i, h := range []string{hashA, hashB} {
		if ok, err := ComparePasswordHash(h, password); err != nil || !ok {
			t.Errorf("hash ke-%d tidak bisa diverifikasi: ok=%v err=%v", i, ok, err)
		}
	}
}

func TestComparePasswordHashHashRusak(t *testing.T) {
	cases := []string{"", "bukan-hash", "$2a$rusak"}

	for _, h := range cases {
		ok, err := ComparePasswordHash(h, "password")
		if ok {
			t.Errorf("hash rusak %q tidak boleh lolos", h)
		}
		if err == nil {
			t.Errorf("hash rusak %q seharusnya mengembalikan error", h)
		}
	}
}
