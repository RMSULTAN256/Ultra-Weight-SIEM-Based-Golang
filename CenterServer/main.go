package main

import (
	"bufio"
	"embed"
	"fmt"
	"io/fs"
	"log"
	"os"
	"sync"
	"time"

	"github.com/bytedance/sonic"
	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/static"
)

//go:embed frontend/*
var frontendFS embed.FS

// Struktur data payload yang diterima dari agent (Heartbeat)
type DeviceStatus struct {
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

// Struktur data payload log / security alert
type SecurityLog struct {
	Timestamp time.Time `json:"timestamp"`
	Hostname  string    `json:"hostname"`
	EventType string    `json:"event_type"`
	RuleID    string    `json:"rule_id,omitempty"`
	RuleDesc  string    `json:"rule_desc,omitempty"`
	MitreID   string    `json:"mitre_id,omitempty"`
	Severity  int       `json:"severity"`
	SourceIP  string    `json:"source_ip,omitempty"`
	Message   string    `json:"message"`
	Status    string    `json:"status,omitempty"`
}

// Struktur pelacak pengirim request IP (IP Traffic Tracker)
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

// Global Hub SSE Client (Thread-safe)
var (
	clientsMu sync.Mutex
	clients   = make(map[chan string]bool)

	ipMu      sync.RWMutex
	ipRecords = make(map[string]*IPTrafficRecord)
)

func recordIP(ip string, hostname string, category string, threat string) *IPTrafficRecord {
	if ip == "" {
		ip = "127.0.0.1"
	}
	ipMu.Lock()
	defer ipMu.Unlock()

	rec, exists := ipRecords[ip]
	now := time.Now()
	if !exists {
		rec = &IPTrafficRecord{
			IP:           ip,
			Hostname:     hostname,
			Category:     category,
			RequestCount: 1,
			FirstSeen:    now,
			LastSeen:     now,
			ThreatLevel:  threat,
			Status:       "Monitored",
		}
		ipRecords[ip] = rec
	} else {
		rec.RequestCount++
		rec.LastSeen = now
		if hostname != "" {
			rec.Hostname = hostname
		}
		if threat == "Critical" || (threat == "Suspicious" && rec.ThreatLevel == "Normal") {
			rec.ThreatLevel = threat
		}
	}

	// Copy untuk return aman
	copyRec := *rec
	return &copyRec
}

func broadcastEvent(data string) {
	clientsMu.Lock()
	defer clientsMu.Unlock()
	for ch := range clients {
		select {
		case ch <- data:
		default:
		}
	}
}

func handleHeartbeat(c fiber.Ctx) error {
	var status DeviceStatus
	if err := sonic.Unmarshal(c.Body(), &status); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid JSON format"})
	}

	clientIP := c.IP()
	if clientIP == "" {
		clientIP = "127.0.0.1"
	}
	status.SourceIP = clientIP
	status.ReceivedAt = time.Now()

	// Catat IP pengirim request
	ipRec := recordIP(clientIP, status.Hostname, "Agent Heartbeat", "Normal")

	fmt.Printf("[%s] %s (%s) | CPU: %.2f%% | RAM: %d/%d MB (%.2f%%) | Disk: %.2f%%\n",
		status.ReceivedAt.Format("15:04:05"),
		status.Hostname,
		clientIP,
		status.CPUUsage,
		status.RAMUsedMB,
		status.RAMTotalMB,
		status.RAMUsedPct,
		status.DiskUsedPct,
	)

	jsonBytes, err := sonic.Marshal(status)
	if err == nil {
		f, err := os.OpenFile("heartbeat.ndjson", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err == nil {
			f.Write(jsonBytes)
			f.WriteString("\n")
			f.Close()
		}
		broadcastEvent(string(jsonBytes))

		// Broadcast update record IP
		if ipBytes, err := sonic.Marshal(fiber.Map{"event_type": "IP_UPDATE", "data": ipRec}); err == nil {
			broadcastEvent(string(ipBytes))
		}
	}

	return c.JSON(fiber.Map{"status": "success", "message": "heartbeat recorded"})
}

func handleIncomingLog(c fiber.Ctx) error {
	var secLog SecurityLog
	if err := sonic.Unmarshal(c.Body(), &secLog); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid JSON format"})
	}

	if secLog.Timestamp.IsZero() {
		secLog.Timestamp = time.Now()
	}
	if secLog.SourceIP == "" {
		secLog.SourceIP = c.IP()
		if secLog.SourceIP == "" {
			secLog.SourceIP = "127.0.0.1"
		}
	}

	threat := "Normal"
	if secLog.Severity >= 12 {
		threat = "Critical"
	} else if secLog.Severity >= 7 {
		threat = "Suspicious"
	}

	ipRec := recordIP(secLog.SourceIP, secLog.Hostname, "Security/Access Log", threat)

	jsonBytes, err := sonic.Marshal(secLog)
	if err == nil {
		f, err := os.OpenFile("events.ndjson", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err == nil {
			f.Write(jsonBytes)
			f.WriteString("\n")
			f.Close()
		}
		broadcastEvent(string(jsonBytes))

		if ipBytes, err := sonic.Marshal(fiber.Map{"event_type": "IP_UPDATE", "data": ipRec}); err == nil {
			broadcastEvent(string(ipBytes))
		}
	}

	return c.JSON(fiber.Map{"status": "success", "message": "log event recorded"})
}

func handleGetIPs(c fiber.Ctx) error {
	ipMu.RLock()
	defer ipMu.RUnlock()

	list := make([]*IPTrafficRecord, 0, len(ipRecords))
	for _, rec := range ipRecords {
		list = append(list, rec)
	}
	return c.JSON(list)
}

func handleBlockIP(c fiber.Ctx) error {
	type BlockReq struct {
		IP string `json:"ip"`
	}
	var req BlockReq
	if err := sonic.Unmarshal(c.Body(), &req); err != nil || req.IP == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid IP specified"})
	}

	ipMu.Lock()
	rec, exists := ipRecords[req.IP]
	if exists {
		if rec.Status == "Blocked (iptables)" {
			rec.Status = "Monitored"
		} else {
			rec.Status = "Blocked (iptables)"
		}
	}
	ipMu.Unlock()

	if exists {
		if ipBytes, err := sonic.Marshal(fiber.Map{"event_type": "IP_UPDATE", "data": rec}); err == nil {
			broadcastEvent(string(ipBytes))
		}
	}

	return c.JSON(fiber.Map{"status": "success", "ip": req.IP, "current_status": rec.Status})
}

func handleStream(c fiber.Ctx) error {
	c.Set("Content-Type", "text/event-stream")
	c.Set("Cache-Control", "no-cache")
	c.Set("Connection", "keep-alive")
	c.Set("Transfer-Encoding", "chunked")

	return c.SendStreamWriter(func(w *bufio.Writer) {
		msgChan := make(chan string, 20)

		clientsMu.Lock()
		clients[msgChan] = true
		clientsMu.Unlock()

		defer func() {
			clientsMu.Lock()
			delete(clients, msgChan)
			close(msgChan)
			clientsMu.Unlock()
		}()

		for msg := range msgChan {
			fmt.Fprintf(w, "data: %s\n\n", msg)
			if err := w.Flush(); err != nil {
				return
			}
		}
	})
}

func main() {
	app := fiber.New()

	// 1. Static Files dari embedded frontend/ folder
	subFS, err := fs.Sub(frontendFS, "frontend")
	if err != nil {
		log.Fatalf("Failed to initialize frontend filesystem: %v", err)
	}

	app.Use("/", static.New("", static.Config{
		FS:         subFS,
		IndexNames: []string{"index.html"},
	}))

	// 2. SSE Stream Endpoint
	app.Get("/api/v1/stream", handleStream)

	// 3. API Penerima Ingest dari Agent
	app.Post("/api/v1/agent/heartbeat", handleHeartbeat)
	app.Post("/api/v1/agent/logs", handleIncomingLog)

	// 4. API Pelacak IP & Containment Zero Trust
	app.Get("/api/v1/ips", handleGetIPs)
	app.Post("/api/v1/containment/block", handleBlockIP)

	port := ":8080"
	fmt.Printf("WAZUH-Lightweight SIEM Dashboard: http://localhost%s\n", port)
	log.Fatal(app.Listen(port))
}
