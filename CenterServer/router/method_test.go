package router

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"server3/models"
	"server3/services"
	"testing"
	"time"

	"github.com/bytedance/sonic"
	"github.com/gofiber/fiber/v3"
)

func setupTestApp() (*fiber.App, *services.SIEMService) {
	app := fiber.New()
	svc := services.NewSIEMService()
	h := NewHandleSiem(svc)

	app.Get("/api/v1/stream", h.HandleStream)
	app.Post("/api/v1/agent/heartbeat", h.HandleHeartbeat)
	app.Post("/api/v1/agent/logs", h.HandleIncomingLog)
	app.Get("/api/v1/ips", h.HandleGetIPs)
	app.Get("/api/v1/logs", h.HandleGetLogs)
	app.Get("/api/v1/agents", h.HandleGetAgents)
	app.Post("/api/v1/containment/block", h.HandleBlockIP)

	return app, svc
}

func TestRouter_LogsAndAgentsEndpoints(t *testing.T) {
	t.Cleanup(func() {
		os.Remove("events.ndjson")
		os.Remove("heartbeat.ndjson")
	})

	app, svc := setupTestApp()

	svc.AddLog(models.SecurityLog{
		Timestamp: time.Now(),
		Hostname:  "node-1",
		EventType: "brute_force",
		Severity:  12,
		SourceIP:  "192.168.1.50",
		Message:   "Brute force attempt detected",
	})
	svc.AddLog(models.SecurityLog{
		Timestamp: time.Now(),
		Hostname:  "node-2",
		EventType: "port_scan",
		Severity:  7,
		SourceIP:  "192.168.1.51",
		Message:   "Port scan detected",
	})

	// 1. Test GET /api/v1/logs
	req := httptest.NewRequest(http.MethodGet, "/api/v1/logs?limit=10", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("Failed to execute request: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	var logs []map[string]interface{}
	if err := sonic.Unmarshal(body, &logs); err != nil {
		t.Fatalf("Failed to parse logs JSON: %v", err)
	}
	if len(logs) < 2 {
		t.Fatalf("Expected at least 2 logs, got %d", len(logs))
	}

	// 1b. Test GET /api/v1/logs?page=1&limit=1
	pagedReq := httptest.NewRequest(http.MethodGet, "/api/v1/logs?page=1&limit=1", nil)
	pagedResp, err := app.Test(pagedReq)
	if err != nil || pagedResp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200 for paged logs, got %d", pagedResp.StatusCode)
	}
	var pagedResult map[string]interface{}
	pagedBody, _ := io.ReadAll(pagedResp.Body)
	if err := sonic.Unmarshal(pagedBody, &pagedResult); err != nil {
		t.Fatalf("Failed to unmarshal paged result: %v", err)
	}
	if pagedResult["page"].(float64) != 1 {
		t.Errorf("Expected page 1, got %v", pagedResult["page"])
	}

	// 2. Test POST /api/v1/agent/logs
	newLogPayload := []byte(`{"hostname":"node-test","event_type":"web_attack","severity":12,"source_ip":"203.0.113.5","message":"SQLi detected"}`)
	postReq := httptest.NewRequest(http.MethodPost, "/api/v1/agent/logs", bytes.NewReader(newLogPayload))
	postReq.Header.Set("Content-Type", "application/json")
	postResp, err := app.Test(postReq)
	if err != nil {
		t.Fatalf("Failed to post log: %v", err)
	}
	if postResp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", postResp.StatusCode)
	}

	// 3. Test GET /api/v1/ips
	ipReq := httptest.NewRequest(http.MethodGet, "/api/v1/ips", nil)
	ipResp, err := app.Test(ipReq)
	if err != nil || ipResp.StatusCode != http.StatusOK {
		t.Fatalf("Failed to get IPs: %v", err)
	}

	// 4. Test GET /api/v1/agents
	agentReq := httptest.NewRequest(http.MethodGet, "/api/v1/agents", nil)
	agentResp, err := app.Test(agentReq)
	if err != nil || agentResp.StatusCode != http.StatusOK {
		t.Fatalf("Failed to get agents: %v", err)
	}
}
