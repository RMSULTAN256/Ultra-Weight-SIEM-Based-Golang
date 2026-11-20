package models

import "time"

type SecurityLog struct {
	ID         int64     `json:"id,omitempty"`
	Timestamp  time.Time `json:"timestamp"`
	Hostname   string    `json:"hostname"`
	EventType  string    `json:"event_type"`
	RuleID     string    `json:"rule_id,omitempty"`
	RuleDesc   string    `json:"rule_desc,omitempty"`
	MitreID    string    `json:"mitre_id,omitempty"`
	Severity   int       `json:"severity"`
	SourceIP   string    `json:"source_ip,omitempty"`
	Message    string    `json:"message,omitempty"`
	Status     string    `json:"status,omitempty"`
	User       string    `json:"user,omitempty"`
	Service    string    `json:"service,omitempty"`
	TargetPort int       `json:"target_port,omitempty"`
	Endpoint   string    `json:"endpoint,omitempty"`
	Command    string    `json:"command,omitempty"`
	Method     string    `json:"method,omitempty"`
	StatusCode int       `json:"status_code,omitempty"`
	RawJSON    string    `json:"raw_json,omitempty"`
}

type LogArchiveFilter struct {
	StartDate string `json:"start_date"` // YYYY-MM-DD or YYYY-MM-DD HH:MM:SS
	EndDate   string `json:"end_date"`
	Level     string `json:"level"`     // ALL, INFO, WARN, ATTACK / CRITICAL, or numeric string
	Attack    string `json:"attack"`    // MITRE ID, event_type, or rule keyword
	Node      string `json:"node"`      // Hostname filter
	SourceIP  string `json:"source_ip"` // IP address filter
	Search    string `json:"search"`    // Keyword search across messages/endpoints
	Page      int    `json:"page"`      // 1-based pagination
	Limit     int    `json:"limit"`     // items per page
	SortOrder string `json:"sort_order"`// DESC or ASC
}

type LogArchiveStats struct {
	TotalMatched int `json:"total_matched"`
	InfoCount    int `json:"info_count"`
	WarnCount    int `json:"warn_count"`
	AttackCount  int `json:"attack_count"`
}

type LogArchiveResult struct {
	Total      int           `json:"total"`
	Page       int           `json:"page"`
	Limit      int           `json:"limit"`
	TotalPages int           `json:"total_pages"`
	Filters    LogArchiveFilter `json:"filters"`
	Stats      LogArchiveStats  `json:"stats"`
	Logs       []SecurityLog    `json:"logs"`
}

type LogFilterOptions struct {
	Nodes      []string `json:"nodes"`
	Attacks    []string `json:"attacks"`
	EventTypes []string `json:"event_types"`
	MinDate    string   `json:"min_date"`
	MaxDate    string   `json:"max_date"`
}

type IPTrafficRecord struct {
	IP           string    `json:"ip"`
	Hostname     string    `json:"hostname"`
	Category     string    `json:"category"`
	Country      string    `json:"country,omitempty"`
	CountryCode  string    `json:"country_code,omitempty"`
	City         string    `json:"city,omitempty"`
	ISP          string    `json:"isp,omitempty"`
	Lat          float64   `json:"lat,omitempty"`
	Lon          float64   `json:"lon,omitempty"`
	RequestCount uint64    `json:"request_count"`
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`
	ThreatLevel  string    `json:"threat_level"` // "Normal", "Suspicious", "Critical"
	Status       string    `json:"status"`       // "Monitored", "Blocked (iptables)"
}

type ProbeResult struct {
	TargetURL  string    `json:"target_url"`
	IsUp       bool      `json:"is_up"`
	StatusCode int       `json:"status_code"`
	LatencyMs  float64   `json:"latency_ms"`
	CheckedAt  time.Time `json:"checked_at"`
	ErrorMsg   string    `json:"error_msg"`
}
