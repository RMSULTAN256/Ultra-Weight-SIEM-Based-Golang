package models

import "time"

type DeviceStatus struct {
	AgentID     string    `json:"agent_id,omitempty"`
	Hostname    string    `json:"hostname"`
	SourceIP    string    `json:"source_ip"`
	Platform    string    `json:"platform"`
	UptimeSec   uint64    `json:"uptime_sec"`
	CPUUsage    float64   `json:"cpu_usage"`
	RAMTotalMB  uint64    `json:"ram_total_mb"`
	RAMUsedMB   uint64    `json:"ram_used_mb"`
	RAMUsedPct  float64   `json:"ram_used_pct"`
	DiskUsedPct float64   `json:"disk_used_pct"`
	ReceivedAt  time.Time `json:"received_at"`
}
