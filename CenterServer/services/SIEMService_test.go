package services

import (
	"fmt"
	"server3/models"
	"testing"
	"time"
)

func TestSIEMService_LogBufferCap(t *testing.T) {
	svc := NewSIEMService()

	// Clear logs for isolated test
	svc.logsMu.Lock()
	svc.logs = make([]models.SecurityLog, 0, MaxLogsInMemory)
	svc.logsMu.Unlock()

	// Ingest 1500 logs
	for i := 1; i <= 1500; i++ {
		svc.AddLog(models.SecurityLog{
			Timestamp: time.Now(),
			Hostname:  "test-node",
			EventType: "auth_test",
			Message:   fmt.Sprintf("Event #%d", i),
			Severity:  3,
		})
	}

	// Verify buffer length is strictly capped at MaxLogsInMemory (1000)
	logs := svc.GetLogs(1000)
	if len(logs) != MaxLogsInMemory {
		t.Fatalf("Expected %d logs, got %d", MaxLogsInMemory, len(logs))
	}

	// Verify newest first ordering: first log should be Event #1500
	if logs[0].Message != "Event #1500" {
		t.Errorf("Expected newest log to be 'Event #1500', got '%s'", logs[0].Message)
	}

	// Verify last log is Event #501 (oldest kept)
	if logs[len(logs)-1].Message != "Event #501" {
		t.Errorf("Expected oldest retained log to be 'Event #501', got '%s'", logs[len(logs)-1].Message)
	}

	// Test limit parameter
	top10 := svc.GetLogs(10)
	if len(top10) != 10 {
		t.Fatalf("Expected 10 logs, got %d", len(top10))
	}
	if top10[0].Message != "Event #1500" || top10[9].Message != "Event #1491" {
		t.Errorf("Unexpected top 10 logs ordering: first='%s', last='%s'", top10[0].Message, top10[9].Message)
	}

	// Verify buffer capacity does not leak or explode
	svc.logsMu.RLock()
	actualCap := cap(svc.logs)
	svc.logsMu.RUnlock()
	if actualCap > MaxLogsInMemory {
		t.Errorf("Buffer capacity leaked beyond MaxLogsInMemory: got %d, expected <= %d", actualCap, MaxLogsInMemory)
	}

	// Test GetLogsPaged
	pagedLogs, total := svc.GetLogsPaged(1, 25)
	if total != MaxLogsInMemory {
		t.Errorf("Expected total %d, got %d", MaxLogsInMemory, total)
	}
	if len(pagedLogs) != 25 {
		t.Fatalf("Expected 25 logs on page 1, got %d", len(pagedLogs))
	}
	if pagedLogs[0].Message != "Event #1500" {
		t.Errorf("Expected first paged log to be 'Event #1500', got '%s'", pagedLogs[0].Message)
	}

	pagedPage2, _ := svc.GetLogsPaged(2, 25)
	if len(pagedPage2) != 25 {
		t.Fatalf("Expected 25 logs on page 2, got %d", len(pagedPage2))
	}
	if pagedPage2[0].Message != "Event #1475" {
		t.Errorf("Expected first log of page 2 to be 'Event #1475', got '%s'", pagedPage2[0].Message)
	}

	// Test out of bounds page
	emptyLogs, _ := svc.GetLogsPaged(999, 25)
	if len(emptyLogs) != 0 {
		t.Errorf("Expected 0 logs on out-of-bounds page, got %d", len(emptyLogs))
	}
}

func TestSIEMService_AgentAndIPTracking(t *testing.T) {
	svc := NewSIEMService()

	// Test agent recording
	svc.RecordAgent(&models.DeviceStatus{
		Hostname:   "web-auth-01",
		SourceIP:   "10.0.0.1",
		Platform:   "Linux",
		CPUUsage:   12.5,
		RAMUsedPct: 45.0,
	})

	agents := svc.GetAgents()
	if len(agents) == 0 {
		t.Fatal("Expected at least 1 agent, got 0")
	}

	found := false
	for _, a := range agents {
		if a.Hostname == "web-auth-01" {
			found = true
			if a.CPUUsage != 12.5 {
				t.Errorf("Expected CPU 12.5, got %f", a.CPUUsage)
			}
		}
	}
	if !found {
		t.Error("Recorded agent web-auth-01 not found in GetAgents()")
	}

	// Test IP recording and blocking
	svc.RecordIP("192.168.1.100", "attacker-host", "Brute Force", "Critical")
	rec, exists := svc.ToggleBlockIP("192.168.1.100")
	if !exists {
		t.Fatal("Expected IP 192.168.1.100 to exist")
	}
	if rec.Status != "Blocked (iptables)" {
		t.Errorf("Expected status 'Blocked (iptables)', got '%s'", rec.Status)
	}

	// Toggle back
	rec2, _ := svc.ToggleBlockIP("192.168.1.100")
	if rec2.Status != "Monitored" {
		t.Errorf("Expected status 'Monitored', got '%s'", rec2.Status)
	}
}
