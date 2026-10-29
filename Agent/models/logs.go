package models

import "time"

type LogConfig struct {
	ScanIntervalSec int            `json:"scan_interval_sec"`
	Targets         []TargetConfig `json:"targets"`
}

type TargetConfig struct {
	AppName  string   `json:"app_name"`
	FilePath string   `json:"file_path"`
	Keywords []string `json:"keywords"`
}

type SecurityLog struct {
	Timestamp time.Time `json:"timestamp"`
	Hostname  string    `json:"hostname"`
	EventType string    `json:"event_type"`
	Severity  int       `json:"severity"`
	SourceIP  string    `json:"source_ip,omitempty"`
	Message   string    `json:"message,omitempty"`
	Status    string    `json:"status,omitempty"`
	Service   string    `json:"service,omitempty"`
}
