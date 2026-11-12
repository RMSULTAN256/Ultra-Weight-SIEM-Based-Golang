package databases

import (
	"path/filepath"
	"strings"
	"testing"
)

func bukaDB(t *testing.T) *DBService {
	t.Helper()

	// Sub-direktori sengaja dipakai untuk memastikan NewDBService membuat folder.
	path := filepath.Join(t.TempDir(), "data", "siem.db")

	db, err := NewDBService(path)
	if err != nil {
		t.Fatalf("NewDBService gagal: %v", err)
	}
	t.Cleanup(func() {
		if db.db != nil {
			db.db.Close()
		}
	})

	return db
}

func TestNewDBServiceSeedAdmin(t *testing.T) {
	const passwordAwal = "admin-uji-123"
	t.Setenv("ADMIN_INIT_PASSWORD", passwordAwal)

	db := bukaDB(t)

	n, err := db.CountUsers()
	if err != nil {
		t.Fatalf("CountUsers gagal: %v", err)
	}
	if n != 1 {
		t.Fatalf("database baru harus berisi 1 akun admin, dapat %d", n)
	}

	// Password harus disimpan sebagai hash bcrypt, bukan plaintext.
	var storedHash, role string
	if err := db.db.QueryRow("SELECT password_hash, role FROM users WHERE username = ?", "admin").
		Scan(&storedHash, &role); err != nil {
		t.Fatalf("gagal membaca baris admin: %v", err)
	}
	if storedHash == passwordAwal {
		t.Fatal("password admin tersimpan sebagai plaintext")
	}
	if !strings.HasPrefix(storedHash, "$2") {
		t.Errorf("password_hash bukan bcrypt: %q", storedHash)
	}
	if role != "admin" {
		t.Errorf("role admin: dapat %q, mau %q", role, "admin")
	}

	ok, gotRole, err := db.Authenticate("admin", passwordAwal)
	if err != nil || !ok {
		t.Fatalf("admin harus bisa login dengan password awal: ok=%v err=%v", ok, err)
	}
	if gotRole != "admin" {
		t.Errorf("role hasil Authenticate: dapat %q, mau admin", gotRole)
	}
}

// TestNewDBServiceTidakSeedUlang: membuka database yang sudah ada tidak boleh
// menambah akun admin baru (kalau iya, kredensial jadi tak terkontrol).
func TestNewDBServiceTidakSeedUlang(t *testing.T) {
	t.Setenv("ADMIN_INIT_PASSWORD", "admin-uji-123")

	path := filepath.Join(t.TempDir(), "siem.db")

	db1, err := NewDBService(path)
	if err != nil {
		t.Fatalf("NewDBService pertama gagal: %v", err)
	}
	defer db1.db.Close()

	db2, err := NewDBService(path)
	if err != nil {
		t.Fatalf("NewDBService kedua gagal: %v", err)
	}
	defer db2.db.Close()

	n, err := db2.CountUsers()
	if err != nil {
		t.Fatalf("CountUsers gagal: %v", err)
	}
	if n != 1 {
		t.Errorf("membuka database lama tidak boleh seed ulang, jumlah user %d", n)
	}
}

func TestRegisterUserDanAuthenticate(t *testing.T) {
	t.Setenv("ADMIN_INIT_PASSWORD", "admin-uji-123")
	db := bukaDB(t)

	if err := db.RegisterUser("operator1", "rahasia-operator", "operator"); err != nil {
		t.Fatalf("RegisterUser gagal: %v", err)
	}

	n, err := db.CountUsers()
	if err != nil {
		t.Fatalf("CountUsers gagal: %v", err)
	}
	if n != 2 {
		t.Errorf("jumlah user setelah register: dapat %d, mau 2", n)
	}

	ok, role, err := db.Authenticate("operator1", "rahasia-operator")
	if err != nil || !ok {
		t.Fatalf("user baru harus bisa login: ok=%v err=%v", ok, err)
	}
	if role != "operator" {
		t.Errorf("role: dapat %q, mau operator", role)
	}
}

func TestAuthenticatePasswordSalah(t *testing.T) {
	t.Setenv("ADMIN_INIT_PASSWORD", "admin-uji-123")
	db := bukaDB(t)

	ok, role, err := db.Authenticate("admin", "password-salah")
	if err == nil {
		t.Fatal("password salah seharusnya mengembalikan error")
	}
	if ok {
		t.Fatal("password salah tidak boleh menghasilkan ok=true")
	}
	if role != "" {
		t.Errorf("role harus kosong saat gagal, dapat %q", role)
	}
	if !strings.Contains(err.Error(), "password salah") {
		t.Errorf("pesan error tidak informatif: %v", err)
	}
}

func TestAuthenticateUserTidakAda(t *testing.T) {
	t.Setenv("ADMIN_INIT_PASSWORD", "admin-uji-123")
	db := bukaDB(t)

	ok, _, err := db.Authenticate("hantu", "apa-saja")
	if err == nil {
		t.Fatal("user tidak ada seharusnya mengembalikan error")
	}
	if ok {
		t.Fatal("user tidak ada tidak boleh lolos autentikasi")
	}
	if !strings.Contains(err.Error(), "tidak ditemukan") {
		t.Errorf("pesan error tidak informatif: %v", err)
	}
}

func TestRegisterUserDuplikat(t *testing.T) {
	t.Setenv("ADMIN_INIT_PASSWORD", "admin-uji-123")
	db := bukaDB(t)

	if err := db.RegisterUser("admin", "password-lain", "admin"); err == nil {
		t.Fatal("username duplikat seharusnya ditolak constraint UNIQUE")
	}
}

// TestRegisterUserUsernameCase: SQLite membandingkan username secara
// case-sensitive, jadi "Admin" dianggap user berbeda. Test ini mendokumentasikan
// perilaku tersebut supaya tidak berubah tanpa sadar.
func TestRegisterUserUsernameCase(t *testing.T) {
	t.Setenv("ADMIN_INIT_PASSWORD", "admin-uji-123")
	db := bukaDB(t)

	if err := db.RegisterUser("Admin", "password-baru", "viewer"); err != nil {
		t.Fatalf("username beda kapitalisasi seharusnya diterima: %v", err)
	}

	if _, _, err := db.Authenticate("admin", "admin-uji-123"); err != nil {
		t.Errorf("akun 'admin' asli harus tetap bisa login: %v", err)
	}
	if _, _, err := db.Authenticate("Admin", "password-baru"); err != nil {
		t.Errorf("akun 'Admin' harus bisa login dengan password sendiri: %v", err)
	}
}
