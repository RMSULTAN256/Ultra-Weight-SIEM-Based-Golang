package databases

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"server3/auth"
	"server3/models"
	"time"

	_ "modernc.org/sqlite"
)

type DBService struct {
	db *sql.DB
}

func NewDBService(dbPath string) (*DBService, error) {
	if dir := filepath.Dir(dbPath); dir != "" && dir != "." {
		_ = os.MkdirAll(dir, 0755)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	db.Exec("PRAGMA journal_mode=WAL;")

	query := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		role TEXT DEFAULT 'admin',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);`

	if _, err := db.Exec(query); err != nil {
		return nil, err
	}

	ipQuery := `
	CREATE TABLE IF NOT EXISTS ip_traffic (
		ip TEXT PRIMARY KEY,
		hostname TEXT DEFAULT '',
		category TEXT DEFAULT '',
		country TEXT DEFAULT 'Indonesia',
		country_code TEXT DEFAULT 'ID',
		city TEXT DEFAULT '',
		isp TEXT DEFAULT '',
		lat REAL DEFAULT 0,
		lon REAL DEFAULT 0,
		request_count INTEGER DEFAULT 1,
		first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
		last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
		threat_level TEXT DEFAULT 'Normal',
		status TEXT DEFAULT 'Monitored'
	);`

	if _, err := db.Exec(ipQuery); err != nil {
		return nil, err
	}

	// Schema migration: tambahkan kolom lat & lon jika belum ada pada tabel lama
	_, _ = db.Exec("ALTER TABLE ip_traffic ADD COLUMN lat REAL DEFAULT 0;")
	_, _ = db.Exec("ALTER TABLE ip_traffic ADD COLUMN lon REAL DEFAULT 0;")

	// Auto-seed: buat akun default jika tabel users masih kosong
	var userCount int
	db.QueryRow("SELECT COUNT(*) FROM users").Scan(&userCount)
	if userCount == 0 {
		defaultUser := "admin"
		defaultPass := os.Getenv("ADMIN_INIT_PASSWORD")
		if defaultPass == "" {
			b := make([]byte, 16)
			rand.Read(b)
			defaultPass = hex.EncodeToString(b)
		}
		if hash, err := auth.HashPassword(defaultPass); err == nil {
			db.Exec("INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'admin')", defaultUser, string(hash))
		}
	}

	return &DBService{db: db}, nil
}

func (s *DBService) RegisterUser(username, plainPassword, role string) error {
	hash, err := auth.HashPassword(plainPassword)
	if err != nil {
		return err
	}
	query := `INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)`
	_, err = s.db.Exec(query, username, string(hash), role)
	return err
}

func (s *DBService) Authenticate(username, plainPassword string) (bool, string, error) {
	var id int
	var passwordHash, role string

	query := `SELECT id, password_hash, role FROM users WHERE username = ?`
	row := s.db.QueryRow(query, username)
	err := row.Scan(&id, &passwordHash, &role)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, "", fmt.Errorf("user tidak ditemukan")
		}
		return false, "", err
	}
	_, err = auth.ComparePasswordHash(passwordHash, plainPassword)
	if err != nil {
		return false, "", fmt.Errorf("password salah")
	}
	return true, role, nil
}

func (s *DBService) CountUsers() (int, error) {
	var n int
	err := s.db.QueryRow("SELECT COUNT(*) FROM USERS").Scan(&n)
	return n, err
}

func (s *DBService) UpsertIP(rec *models.IPTrafficRecord) error {
	if rec == nil || rec.IP == "" {
		return nil
	}
	query := `
	INSERT INTO ip_traffic (ip, hostname, category, country, country_code, city, isp, lat, lon, request_count, first_seen, last_seen, threat_level, status)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(ip) DO UPDATE SET
		hostname = excluded.hostname,
		category = excluded.category,
		country = CASE WHEN excluded.country != '' THEN excluded.country ELSE ip_traffic.country END,
		country_code = CASE WHEN excluded.country_code != '' THEN excluded.country_code ELSE ip_traffic.country_code END,
		city = CASE WHEN excluded.city != '' THEN excluded.city ELSE ip_traffic.city END,
		isp = CASE WHEN excluded.isp != '' THEN excluded.isp ELSE ip_traffic.isp END,
		lat = CASE WHEN excluded.lat != 0 THEN excluded.lat ELSE ip_traffic.lat END,
		lon = CASE WHEN excluded.lon != 0 THEN excluded.lon ELSE ip_traffic.lon END,
		request_count = excluded.request_count,
		last_seen = excluded.last_seen,
		threat_level = excluded.threat_level,
		status = excluded.status;`
	_, err := s.db.Exec(query,
		rec.IP, rec.Hostname, rec.Category,
		rec.Country, rec.CountryCode, rec.City, rec.ISP,
		rec.Lat, rec.Lon,
		rec.RequestCount, rec.FirstSeen, rec.LastSeen,
		rec.ThreatLevel, rec.Status,
	)
	return err
}

// GetAllIPs membaca seluruh riwayat IP yang tersimpan di SQLite
func (s *DBService) GetAllIPs() ([]*models.IPTrafficRecord, error) {
	query := `SELECT ip, hostname, category, country, country_code, city, isp, lat, lon, request_count, first_seen, last_seen, threat_level, status FROM ip_traffic ORDER BY last_seen DESC`
	rows, err := s.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []*models.IPTrafficRecord
	for rows.Next() {
		var rec models.IPTrafficRecord
		var firstSeen, lastSeen time.Time
		if err := rows.Scan(
			&rec.IP, &rec.Hostname, &rec.Category,
			&rec.Country, &rec.CountryCode, &rec.City, &rec.ISP,
			&rec.Lat, &rec.Lon,
			&rec.RequestCount, &firstSeen, &lastSeen,
			&rec.ThreatLevel, &rec.Status,
		); err != nil {
			continue
		}
		rec.FirstSeen = firstSeen
		rec.LastSeen = lastSeen
		list = append(list, &rec)
	}
	return list, nil
}
