package databases

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"server3/auth"

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

	// Auto-seed: buat akun default jika tabel users masih kosong
	var userCount int
	db.QueryRow("SELECT COUNT(*) FROM users").Scan(&userCount)
	if userCount == 0 {
		defaultUser := "admin"
		defaultPass := "admin123"
		if hash, err := auth.HashPassword(defaultPass); err == nil {
			db.Exec("INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'admin')", defaultUser, string(hash))
			fmt.Printf("[AUTH SEED] Akun default dibuat: Username: %s | Password: %s (Role: admin)\n", defaultUser, defaultPass)
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
