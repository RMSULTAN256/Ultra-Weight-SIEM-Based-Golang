package databases

import (
	"path/filepath"
	"server3/models"
	"strings"
	"testing"
	"time"
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

func TestIPTrafficUpsertDanGetAll(t *testing.T) {
	db := bukaDB(t)

	// Test Upsert IP pertama kali
	rec1 := &models.IPTrafficRecord{
		IP:           "203.83.39.23",
		Hostname:     "ubuntu-1",
		Category:     "HTTP Web",
		Country:      "Indonesia",
		CountryCode:  "ID",
		City:         "Medan, North Sumatra",
		ISP:          "PT Eka Mas Republik",
		RequestCount: 5,
		ThreatLevel:  "Normal",
		Status:       "Monitored",
	}

	if err := db.UpsertIP(rec1); err != nil {
		t.Fatalf("UpsertIP pertama gagal: %v", err)
	}

	ips, err := db.GetAllIPs()
	if err != nil {
		t.Fatalf("GetAllIPs gagal: %v", err)
	}
	if len(ips) != 1 {
		t.Fatalf("jumlah IP harus 1, dapat %d", len(ips))
	}
	if ips[0].IP != "203.83.39.23" || ips[0].Country != "Indonesia" || ips[0].CountryCode != "ID" {
		t.Errorf("data IP tidak cocok: %+v", ips[0])
	}

	// Test Upsert update request_count & threat_level
	rec1.RequestCount = 10
	rec1.ThreatLevel = "Critical"
	if err := db.UpsertIP(rec1); err != nil {
		t.Fatalf("UpsertIP update gagal: %v", err)
	}

	ips2, err := db.GetAllIPs()
	if err != nil {
		t.Fatalf("GetAllIPs kedua gagal: %v", err)
	}
	if len(ips2) != 1 {
		t.Fatalf("jumlah IP harus tetap 1 setelah upsert update, dapat %d", len(ips2))
	}
	if ips2[0].RequestCount != 10 || ips2[0].ThreatLevel != "Critical" {
		t.Errorf("data IP setelah update tidak sesuai: count=%d threat=%s", ips2[0].RequestCount, ips2[0].ThreatLevel)
	}
}

func TestSecurityLogsArchiveAndFilter(t *testing.T) {
	db := bukaDB(t)

	// Seed logs
	t1, _ := time.Parse("2006-01-02 15:04:05", "2026-09-16 08:12:01")
	t2, _ := time.Parse("2006-01-02 15:04:05", "2026-09-16 08:15:20")
	t3, _ := time.Parse("2006-01-02 15:04:05", "2026-09-17 10:00:00")

	logs := []models.SecurityLog{
		{
			Timestamp: t1,
			Hostname:  "node-auth",
			EventType: "auth_failure",
			RuleID:    "RULE-SSH-BRUTEFORCE",
			RuleDesc:  "SSH Brute Force Attack",
			MitreID:   "T1110.001 Brute Force",
			Severity:  12,
			SourceIP:  "159.65.132.84",
			Message:   "Failed password for invalid user admin",
			Status:    "failed",
			User:      "admin",
			Service:   "sshd",
		},
		{
			Timestamp: t2,
			Hostname:  "node-auth",
			EventType: "sudo",
			RuleID:    "RULE-SUDO-EXEC",
			RuleDesc:  "Privilege escalation attempt",
			MitreID:   "T1548 Abuse Elevation",
			Severity:  8,
			SourceIP:  "159.65.132.84",
			Message:   "User web-operator ran sudo /bin/bash",
			Status:    "success",
			User:      "web-operator",
			Command:   "/bin/bash",
		},
		{
			Timestamp: t3,
			Hostname:  "node-web",
			EventType: "web_access",
			Severity:  3,
			SourceIP:  "180.241.211.86",
			Message:   "GET /index.php 200",
			Status:    "success",
			Endpoint:  "/index.php",
			Method:    "GET",
			StatusCode: 200,
		},
	}

	if err := db.BatchInsertLogs(logs); err != nil {
		t.Fatalf("BatchInsertLogs gagal: %v", err)
	}

	total, err := db.CountLogs()
	if err != nil {
		t.Fatalf("CountLogs gagal: %v", err)
	}
	if total != 3 {
		t.Fatalf("CountLogs diharapkan 3, dapat %d", total)
	}

	// 1. Query All
	resAll, err := db.QueryLogsArchive(models.LogArchiveFilter{Page: 1, Limit: 10})
	if err != nil {
		t.Fatalf("QueryLogsArchive gagal: %v", err)
	}
	if resAll.Total != 3 || len(resAll.Logs) != 3 {
		t.Errorf("Query all: total=%d, logs=%d", resAll.Total, len(resAll.Logs))
	}
	if resAll.Stats.InfoCount != 1 || resAll.Stats.WarnCount != 1 || resAll.Stats.AttackCount != 1 {
		t.Errorf("Stats tidak cocok: info=%d warn=%d attack=%d", resAll.Stats.InfoCount, resAll.Stats.WarnCount, resAll.Stats.AttackCount)
	}

	// 2. Filter by Date (only 2026-09-16)
	resDate, err := db.QueryLogsArchive(models.LogArchiveFilter{
		StartDate: "2026-09-16",
		EndDate:   "2026-09-16",
		Page:      1,
		Limit:     10,
	})
	if err != nil {
		t.Fatalf("Query by date gagal: %v", err)
	}
	if resDate.Total != 2 {
		t.Errorf("Filter tanggal 2026-09-16: diharapkan 2, dapat %d", resDate.Total)
	}

	// 3. Filter by Level ATTACK
	resAttack, err := db.QueryLogsArchive(models.LogArchiveFilter{
		Level: "ATTACK",
		Page:  1,
		Limit: 10,
	})
	if err != nil {
		t.Fatalf("Query by level gagal: %v", err)
	}
	if resAttack.Total != 1 || resAttack.Logs[0].Severity != 12 {
		t.Errorf("Filter ATTACK level: total=%d, sev=%d", resAttack.Total, resAttack.Logs[0].Severity)
	}

	// 4. Filter by Attack (MITRE T1110)
	resMitre, err := db.QueryLogsArchive(models.LogArchiveFilter{
		Attack: "T1110",
		Page:   1,
		Limit:  10,
	})
	if err != nil {
		t.Fatalf("Query by attack gagal: %v", err)
	}
	if resMitre.Total != 1 || resMitre.Logs[0].MitreID != "T1110.001 Brute Force" {
		t.Errorf("Filter T1110 attack: total=%d, mitre=%s", resMitre.Total, resMitre.Logs[0].MitreID)
	}

	// 5. Filter by Node
	resNode, err := db.QueryLogsArchive(models.LogArchiveFilter{
		Node:  "node-web",
		Page:  1,
		Limit: 10,
	})
	if err != nil {
		t.Fatalf("Query by node gagal: %v", err)
	}
	if resNode.Total != 1 || resNode.Logs[0].Hostname != "node-web" {
		t.Errorf("Filter node-web: total=%d", resNode.Total)
	}

	// 6. Search keyword
	resSearch, err := db.QueryLogsArchive(models.LogArchiveFilter{
		Search: "sudo",
		Page:   1,
		Limit:  10,
	})
	if err != nil {
		t.Fatalf("Query by search gagal: %v", err)
	}
	if resSearch.Total != 1 || resSearch.Logs[0].User != "web-operator" {
		t.Errorf("Filter search sudo: total=%d", resSearch.Total)
	}

	// 7. Test Filter Options
	opts, err := db.GetLogFilterOptions()
	if err != nil {
		t.Fatalf("GetLogFilterOptions gagal: %v", err)
	}
	if len(opts.Nodes) < 2 {
		t.Errorf("Filter options nodes diharapkan >= 2, dapat %v", opts.Nodes)
	}
	if len(opts.Attacks) < 1 {
		t.Errorf("Filter options attacks diharapkan >= 1, dapat %v", opts.Attacks)
	}
}

