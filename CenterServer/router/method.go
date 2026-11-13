package router

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"server3/models"
	"server3/services"
	"strconv"
	"strings"
	"time"

	"github.com/bytedance/sonic"
	"github.com/gofiber/fiber/v3"
)

type HandleService struct {
	siemService *services.SIEMService
}

func NewHandleSiem(svc *services.SIEMService) *HandleService {
	return &HandleService{siemService: svc}
}

func getClientIP(c fiber.Ctx) string {
	// 1. Nginx / Reverse Proxy Real IP (sudah diekstrak oleh Nginx via real_ip_header)
	if xReal := strings.TrimSpace(c.Get("X-Real-IP")); xReal != "" && net.ParseIP(xReal) != nil {
		return xReal
	}
	// 2. Cloudflare True Client IP langsung (jika tanpa Nginx)
	if cfIP := strings.TrimSpace(c.Get("CF-Connecting-IP")); cfIP != "" && net.ParseIP(cfIP) != nil {
		return cfIP
	}
	// 3. X-Forwarded-For
	if xff := strings.TrimSpace(c.Get("X-Forwarded-For")); xff != "" {
		parts := strings.Split(xff, ",")
		for i := len(parts) - 1; i >= 0; i-- {
			ip := strings.TrimSpace(parts[i])
			if net.ParseIP(ip) != nil && !strings.HasPrefix(ip, "172.") && !strings.HasPrefix(ip, "127.") {
				return ip
			}
		}
		for _, p := range parts {
			ip := strings.TrimSpace(p)
			if net.ParseIP(ip) != nil {
				return ip
			}
		}
	}
	// 4. Fallback ke IP soket koneksi Fiber
	ip := strings.TrimSpace(c.IP())
	if net.ParseIP(ip) != nil {
		return ip
	}
	return "127.0.0.1"
}

func getEventsFilePath() string {
	if p := os.Getenv("EVENTS_FILE"); p != "" {
		return p
	}
	if _, err := os.Stat("CenterServer/events.ndjson"); err == nil {
		return "CenterServer/events.ndjson"
	}
	return "events.ndjson"
}

func getHeartbeatFilePath() string {
	if p := os.Getenv("HEARTBEAT_FILE"); p != "" {
		return p
	}
	if _, err := os.Stat("CenterServer/heartbeat.ndjson"); err == nil {
		return "CenterServer/heartbeat.ndjson"
	}
	return "heartbeat.ndjson"
}

func (sc *HandleService) HandleHeartbeat(c fiber.Ctx) error {
	var status models.DeviceStatus
	if err := sonic.Unmarshal(c.Body(), &status); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid JSON format"})
	}

	clientIP := getClientIP(c)
	status.SourceIP = clientIP
	status.ReceivedAt = time.Now()

	if status.AgentID == "" {
		if status.SourceIP != "" && status.SourceIP != "127.0.0.1" {
			status.AgentID = fmt.Sprintf("%s-%s", status.Hostname, status.SourceIP)
		} else {
			status.AgentID = status.Hostname
		}
	}

	// Update active agent record
	sc.siemService.RecordAgent(&status)

	// Catat IP pengirim request
	ipRec := sc.siemService.RecordIP(clientIP, status.Hostname, "Agent Heartbeat", "Normal")

	jsonBytes, err := sonic.Marshal(status)
	if err == nil {
		f, err := os.OpenFile(getHeartbeatFilePath(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err == nil {
			f.Write(jsonBytes)
			f.WriteString("\n")
			f.Close()
		}
		sc.siemService.Broadcast(string(jsonBytes))

		// Broadcast update record IP
		if ipRec != nil {
			if ipBytes, err := sonic.Marshal(fiber.Map{"event_type": "IP_UPDATE", "data": ipRec}); err == nil {
				sc.siemService.Broadcast(string(ipBytes))
			}
		}
	}

	return c.JSON(fiber.Map{"status": "success", "message": "heartbeat recorded"})
}

func (sc *HandleService) HandleIncomingLog(c fiber.Ctx) error {
	var secLog models.SecurityLog
	if err := sonic.Unmarshal(c.Body(), &secLog); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid JSON format"})
	}

	if secLog.Timestamp.IsZero() {
		secLog.Timestamp = time.Now()
	}
	if secLog.SourceIP == "" {
		secLog.SourceIP = getClientIP(c)
	}
	if secLog.Hostname == "" {
		secLog.Hostname = "node"
	}
	if secLog.Severity == 0 {
		if secLog.EventType == "auth_failure" {
			secLog.Severity = 7
		} else {
			secLog.Severity = 3
		}
	}

	secLog = sc.siemService.CorrelateLog(secLog)

	threat := "Normal"
	if secLog.Severity >= 12 {
		threat = "Critical"
	} else if secLog.Severity >= 7 {
		threat = "Suspicious"
	}

	ipRec := sc.siemService.RecordIP(secLog.SourceIP, secLog.Hostname, "Security/Access Log", threat)

	// Ingest to in-memory ring buffer (up to 1,000 logs)
	sc.siemService.AddLog(secLog)

	jsonBytes, err := sonic.Marshal(secLog)
	if err == nil {
		f, err := os.OpenFile(getEventsFilePath(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err == nil {
			f.Write(jsonBytes)
			f.WriteString("\n")
			f.Close()
		}
		sc.siemService.Broadcast(string(jsonBytes))

		if ipRec != nil {
			if ipBytes, err := sonic.Marshal(fiber.Map{"event_type": "IP_UPDATE", "data": ipRec}); err == nil {
				sc.siemService.Broadcast(string(ipBytes))
			}
		}
	}

	return c.JSON(fiber.Map{"status": "success", "message": "log event recorded"})
}

func (sc *HandleService) HandleGetLogs(c fiber.Ctx) error {
	c.Set("X-total-Ingested", strconv.FormatUint(sc.siemService.GetTotalLogsCount(), 10))
	limitStr := c.Query("limit")
	limit := 1000
	if limitStr != "" {
		if val, err := strconv.Atoi(limitStr); err == nil && val > 0 {
			limit = val
		}
	}

	pageStr := c.Query("page")
	if pageStr != "" {
		if page, err := strconv.Atoi(pageStr); err == nil && page > 0 {
			logs, total := sc.siemService.GetLogsPaged(page, limit)
			return c.JSON(fiber.Map{
				"total": total,
				"page":  page,
				"limit": limit,
				"logs":  logs,
			})
		}
	}

	return c.JSON(sc.siemService.GetLogs(limit))
}

func (sc *HandleService) HandleDeleteAgent(c fiber.Ctx) error {
	agentID := c.Params("id")
	if agentID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"Error": "Agent ID Required"})
	}
	if sc.siemService.DeleteAgent(agentID) {
		if msgBytes, err := sonic.Marshal(fiber.Map{"event_type": "AGENT_DELETED", "agent_id": agentID}); err == nil {
			sc.siemService.Broadcast(string(msgBytes))
		}
	}
	return c.JSON(fiber.Map{"status": "success", "message": "Agent deleted"})
}

func (sc *HandleService) HandleGetAgents(c fiber.Ctx) error {
	return c.JSON(sc.siemService.GetAgents())
}

func (sc *HandleService) HandleGetIPs(c fiber.Ctx) error {
	return c.JSON(sc.siemService.GetAllIPs())
}

func (sc *HandleService) HandleBlockIP(c fiber.Ctx) error {
	type BlockReq struct {
		IP string `json:"ip"`
	}
	var req BlockReq
	if err := sonic.Unmarshal(c.Body(), &req); err != nil || req.IP == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid IP specified"})
	}

	rec, exists := sc.siemService.ToggleBlockIP(req.IP)
	if !exists {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "IP not found in tracking records"})
	}

	if ipBytes, err := sonic.Marshal(fiber.Map{"event_type": "IP_UPDATE", "data": rec}); err == nil {
		sc.siemService.Broadcast(string(ipBytes))
	}

	return c.JSON(fiber.Map{"status": "success", "ip": req.IP, "current_status": rec.Status})
}

func (sc *HandleService) HandleStream(c fiber.Ctx) error {
	c.Set("Content-Type", "text/event-stream")
	c.Set("Cache-Control", "no-cache")
	c.Set("Connection", "keep-alive")
	c.Set("Transfer-Encoding", "chunked")

	return c.SendStreamWriter(func(w *bufio.Writer) {
		msgChan := make(chan string, 20)
		sc.siemService.AddClient(msgChan)
		defer sc.siemService.RemoveClient(msgChan)

		for msg := range msgChan {
			fmt.Fprintf(w, "data: %s\n\n", msg)
			if err := w.Flush(); err != nil {
				return
			}
		}
	})
}

func isSafeProbeURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("format URL tidak valid: %w", err)
	}

	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("skema %q tidak diizinkan, hanya http dan https", u.Scheme)
	}

	hostname := strings.ToLower(u.Hostname())
	if hostname == "" {
		return errors.New("hostname URL kosong")
	}

	// Blokir host lokal, cloud metadata, dan service internal container
	blockedHosts := map[string]bool{
		"localhost":       true,
		"127.0.0.1":       true,
		"::1":             true,
		"169.254.169.254": true,
		"metadata":        true,
		"center-siem":     true,
		"local-jenkins":   true,
		"jte_mysql":       true,
		"jte_nginx":       true,
		"jte_app":         true,
		"jte_phpmyadmin":  true,
		"web-nginx":       true,
		"tunnel-cf":       true,
	}
	if blockedHosts[hostname] {
		return fmt.Errorf("akses ke host internal %q diblokir oleh kebijakan keamanan (SSRF Protection)", hostname)
	}

	// Resolve alamat IP dan pastikan bukan loopback / private IP / link-local
	ips, err := net.LookupIP(hostname)
	if err != nil {
		return fmt.Errorf("gagal me-resolve host %q: %w", hostname, err)
	}

	for _, ip := range ips {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
			return fmt.Errorf("akses ke alamat IP internal %s diblokir oleh kebijakan keamanan (SSRF Protection)", ip.String())
		}
	}

	return nil
}

func (sc *HandleService) HandleProbe(c fiber.Ctx) error {
	type ProbeReq struct {
		URL string `json:"url"`
	}

	var req ProbeReq

	if err := sonic.Unmarshal(c.Body(), &req); err != nil || strings.TrimSpace(req.URL) == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "URL target wajib diisi"})
	}

	if err := isSafeProbeURL(req.URL); err != nil {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"error":  err.Error(),
			"status": "blocked_by_security_policy",
		})
	}

	client := &http.Client{
		Timeout: 3 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	start := time.Now()

	resp, err := client.Get(req.URL)
	latency := time.Since(start)
	latencyMs := float64(latency.Microseconds()) / 1000.0

	if err != nil {
		return c.JSON(models.ProbeResult{
			TargetURL: req.URL,
			IsUp:      false,
			LatencyMs: latencyMs,
			CheckedAt: time.Now(),
			ErrorMsg:  err.Error(),
		})
	}

	defer resp.Body.Close()

	return c.JSON(models.ProbeResult{
		TargetURL:  req.URL,
		IsUp:       resp.StatusCode < 500,
		StatusCode: resp.StatusCode,
		LatencyMs:  latencyMs,
		CheckedAt:  time.Now(),
	})
}
