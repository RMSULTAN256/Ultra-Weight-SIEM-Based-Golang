package models

import "time"

type SecurityLog struct {
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
}

type IPTrafficRecord struct {
	IP           string    `json:"ip"`
	Hostname     string    `json:"hostname"`
	Category     string    `json:"category"`
	RequestCount uint64    `json:"request_count"`
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`
	ThreatLevel  string    `json:"threat_level"` // "Normal", "Suspicious", "Critical"
	Status       string    `json:"status"`       // "Monitored", "Blocked (iptables)"
}
