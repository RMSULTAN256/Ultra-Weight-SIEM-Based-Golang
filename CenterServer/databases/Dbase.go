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
	"strconv"
	"strings"
	"time"

	"github.com/bytedance/sonic"
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

	logTableQuery := `
	CREATE TABLE IF NOT EXISTS security_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME NOT NULL,
		hostname TEXT DEFAULT '',
		event_type TEXT DEFAULT '',
		rule_id TEXT DEFAULT '',
		rule_desc TEXT DEFAULT '',
		mitre_id TEXT DEFAULT '',
		severity INTEGER DEFAULT 1,
		source_ip TEXT DEFAULT '',
		message TEXT DEFAULT '',
		status TEXT DEFAULT '',
		user TEXT DEFAULT '',
		service TEXT DEFAULT '',
		target_port INTEGER DEFAULT 0,
		endpoint TEXT DEFAULT '',
		command TEXT DEFAULT '',
		method TEXT DEFAULT '',
		status_code INTEGER DEFAULT 0,
		raw_json TEXT DEFAULT '',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON security_logs(timestamp);
	CREATE INDEX IF NOT EXISTS idx_logs_severity ON security_logs(severity);
	CREATE INDEX IF NOT EXISTS idx_logs_source_ip ON security_logs(source_ip);
	CREATE INDEX IF NOT EXISTS idx_logs_hostname ON security_logs(hostname);
	CREATE INDEX IF NOT EXISTS idx_logs_event_type ON security_logs(event_type);
	CREATE INDEX IF NOT EXISTS idx_logs_mitre_id ON security_logs(mitre_id);
	`
	if _, err := db.Exec(logTableQuery); err != nil {
		return nil, err
	}

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

func normalizeDateTime(s string, isEnd bool) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	s = strings.ReplaceAll(s, "T", " ")
	if idx := strings.Index(s, "Z"); idx != -1 {
		s = s[:idx]
	}
	if len(s) == 10 { // YYYY-MM-DD
		if isEnd {
			return s + " 23:59:59"
		}
		return s + " 00:00:00"
	}
	return s
}

func parseDBTimestamp(v interface{}) time.Time {
	switch val := v.(type) {
	case time.Time:
		return val
	case string:
		layouts := []string{
			"2006-01-02 15:04:05",
			time.RFC3339,
			"2006-01-02T15:04:05Z07:00",
			"2006-01-02T15:04:05",
			"2006-01-02",
		}
		for _, layout := range layouts {
			if t, err := time.Parse(layout, val); err == nil {
				return t
			}
		}
	}
	return time.Now()
}

// InsertLog memasukkan satu log security ke tabel security_logs
func (s *DBService) InsertLog(log *models.SecurityLog) error {
	if log == nil {
		return nil
	}
	return s.BatchInsertLogs([]models.SecurityLog{*log})
}

// BatchInsertLogs memasukkan sekumpulan log security dalam satu transaksi cepat
func (s *DBService) BatchInsertLogs(logs []models.SecurityLog) error {
	if len(logs) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(`
		INSERT INTO security_logs (
			timestamp, hostname, event_type, rule_id, rule_desc, mitre_id,
			severity, source_ip, message, status, user, service, target_port,
			endpoint, command, method, status_code, raw_json
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	defer stmt.Close()

	for _, l := range logs {
		var rawJson string
		if l.RawJSON != "" {
			rawJson = l.RawJSON
		} else {
			if b, err := sonic.Marshal(l); err == nil {
				rawJson = string(b)
			}
		}

		timeStr := l.Timestamp.UTC().Format("2006-01-02 15:04:05")
		_, err = stmt.Exec(
			timeStr, l.Hostname, l.EventType, l.RuleID, l.RuleDesc, l.MitreID,
			l.Severity, l.SourceIP, l.Message, l.Status, l.User, l.Service, l.TargetPort,
			l.Endpoint, l.Command, l.Method, l.StatusCode, rawJson,
		)
		if err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// CountLogs menghitung total log security di tabel
func (s *DBService) CountLogs() (int, error) {
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM security_logs").Scan(&count)
	return count, err
}

// QueryLogsArchive mengeksekusi pencarian arsip log security di SQLite dengan filter terindeks & paginasi
func (s *DBService) QueryLogsArchive(params models.LogArchiveFilter) (*models.LogArchiveResult, error) {
	var conditions []string
	var args []interface{}

	start := normalizeDateTime(params.StartDate, false)
	if start != "" {
		conditions = append(conditions, "timestamp >= ?")
		args = append(args, start)
	}

	end := normalizeDateTime(params.EndDate, true)
	if end != "" {
		conditions = append(conditions, "timestamp <= ?")
		args = append(args, end)
	}

	// Level filter
	lvl := strings.ToUpper(strings.TrimSpace(params.Level))
	switch lvl {
	case "", "ALL":
		// no filter
	case "INFO":
		conditions = append(conditions, "severity < 7")
	case "WARN", "WARNING":
		conditions = append(conditions, "severity >= 7 AND severity < 10")
	case "ATTACK", "CRITICAL":
		conditions = append(conditions, "severity >= 10")
	default:
		if num, err := strconv.Atoi(lvl); err == nil {
			conditions = append(conditions, "severity = ?")
			args = append(args, num)
		}
	}

	// Attack filter (MITRE technique, event type, or rule description/id)
	if atk := strings.TrimSpace(params.Attack); atk != "" && !strings.EqualFold(atk, "ALL") {
		conditions = append(conditions, "(mitre_id LIKE ? OR event_type LIKE ? OR rule_id LIKE ? OR rule_desc LIKE ?)")
		pat := "%" + atk + "%"
		args = append(args, pat, pat, pat, pat)
	}

	// Node / Hostname filter
	if node := strings.TrimSpace(params.Node); node != "" && !strings.EqualFold(node, "ALL") {
		conditions = append(conditions, "hostname = ?")
		args = append(args, node)
	}

	// Source IP filter
	if ip := strings.TrimSpace(params.SourceIP); ip != "" {
		conditions = append(conditions, "source_ip LIKE ?")
		args = append(args, "%"+ip+"%")
	}

	// Search keyword filter across multiple key text fields
	if q := strings.TrimSpace(params.Search); q != "" {
		conditions = append(conditions, "(message LIKE ? OR endpoint LIKE ? OR command LIKE ? OR user LIKE ? OR rule_desc LIKE ? OR source_ip LIKE ?)")
		pat := "%" + q + "%"
		args = append(args, pat, pat, pat, pat, pat, pat)
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	// Hitung aggregate statistik & total
	statsQuery := fmt.Sprintf(`
		SELECT
			COUNT(*) as total,
			COALESCE(SUM(CASE WHEN severity < 7 THEN 1 ELSE 0 END), 0) as info_count,
			COALESCE(SUM(CASE WHEN severity >= 7 AND severity < 10 THEN 1 ELSE 0 END), 0) as warn_count,
			COALESCE(SUM(CASE WHEN severity >= 10 THEN 1 ELSE 0 END), 0) as attack_count
		FROM security_logs %s`, whereClause)

	var total, infoCount, warnCount, attackCount int
	if err := s.db.QueryRow(statsQuery, args...).Scan(&total, &infoCount, &warnCount, &attackCount); err != nil {
		return nil, err
	}

	page := params.Page
	if page < 1 {
		page = 1
	}
	limit := params.Limit
	if limit <= 0 {
		limit = 50
	} else if limit > 500 {
		limit = 500
	}
	offset := (page - 1) * limit

	totalPages := 1
	if total > 0 {
		totalPages = (total + limit - 1) / limit
	}

	sortDir := "DESC"
	if strings.EqualFold(params.SortOrder, "ASC") {
		sortDir = "ASC"
	}

	dataQuery := fmt.Sprintf(`
		SELECT
			id, timestamp, hostname, event_type, rule_id, rule_desc, mitre_id,
			severity, source_ip, message, status, user, service, target_port,
			endpoint, command, method, status_code, raw_json
		FROM security_logs
		%s
		ORDER BY timestamp %s, id %s
		LIMIT ? OFFSET ?`, whereClause, sortDir, sortDir)

	dataArgs := append([]interface{}{}, args...)
	dataArgs = append(dataArgs, limit, offset)

	rows, err := s.db.Query(dataQuery, dataArgs...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	logs := make([]models.SecurityLog, 0, limit)
	for rows.Next() {
		var l models.SecurityLog
		var tsRaw interface{}
		if err := rows.Scan(
			&l.ID, &tsRaw, &l.Hostname, &l.EventType, &l.RuleID, &l.RuleDesc, &l.MitreID,
			&l.Severity, &l.SourceIP, &l.Message, &l.Status, &l.User, &l.Service, &l.TargetPort,
			&l.Endpoint, &l.Command, &l.Method, &l.StatusCode, &l.RawJSON,
		); err != nil {
			continue
		}
		l.Timestamp = parseDBTimestamp(tsRaw)
		logs = append(logs, l)
	}

	return &models.LogArchiveResult{
		Total:      total,
		Page:       page,
		Limit:      limit,
		TotalPages: totalPages,
		Filters:    params,
		Stats: models.LogArchiveStats{
			TotalMatched: total,
			InfoCount:    infoCount,
			WarnCount:    warnCount,
			AttackCount:  attackCount,
		},
		Logs: logs,
	}, nil
}

// GetLogFilterOptions mengambil daftar unik hostnames, attacks, dan range tanggal untuk opsi filter frontend
func (s *DBService) GetLogFilterOptions() (*models.LogFilterOptions, error) {
	opts := &models.LogFilterOptions{
		Nodes:      make([]string, 0),
		Attacks:    make([]string, 0),
		EventTypes: make([]string, 0),
	}

	rows, err := s.db.Query("SELECT DISTINCT hostname FROM security_logs WHERE hostname != '' ORDER BY hostname ASC")
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var n string
			if err := rows.Scan(&n); err == nil && n != "" {
				opts.Nodes = append(opts.Nodes, n)
			}
		}
	}

	rowsAttack, err := s.db.Query("SELECT DISTINCT mitre_id FROM security_logs WHERE mitre_id != '' ORDER BY mitre_id ASC")
	if err == nil {
		defer rowsAttack.Close()
		for rowsAttack.Next() {
			var a string
			if err := rowsAttack.Scan(&a); err == nil && a != "" {
				opts.Attacks = append(opts.Attacks, a)
			}
		}
	}

	rowsEvent, err := s.db.Query("SELECT DISTINCT event_type FROM security_logs WHERE event_type != '' ORDER BY event_type ASC")
	if err == nil {
		defer rowsEvent.Close()
		for rowsEvent.Next() {
			var e string
			if err := rowsEvent.Scan(&e); err == nil && e != "" {
				opts.EventTypes = append(opts.EventTypes, e)
			}
		}
	}

	var minDate, maxDate sql.NullString
	_ = s.db.QueryRow("SELECT MIN(timestamp), MAX(timestamp) FROM security_logs").Scan(&minDate, &maxDate)
	if minDate.Valid {
		opts.MinDate = minDate.String
	}
	if maxDate.Valid {
		opts.MaxDate = maxDate.String
	}

	return opts, nil
}
