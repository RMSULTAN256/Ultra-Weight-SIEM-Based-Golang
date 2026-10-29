package services

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"os"
	"server3/models"
	"sync"
	"time"

	"github.com/bytedance/sonic"
)

const MaxLogsInMemory = 1000

type SIEMService struct {
	clientsMu sync.Mutex
	clients   map[chan string]bool

	ipMu      sync.RWMutex
	ipRecords map[string]*models.IPTrafficRecord

	agentMu sync.RWMutex
	agents  map[string]*models.DeviceStatus

	logsMu sync.RWMutex
	logs   []models.SecurityLog
}

func NewSIEMService() *SIEMService {
	svc := &SIEMService{
		clients:   make(map[chan string]bool),
		ipRecords: make(map[string]*models.IPTrafficRecord),
		agents:    make(map[string]*models.DeviceStatus),
		logs:      make([]models.SecurityLog, 0, MaxLogsInMemory),
	}
	svc.loadInitialData()
	return svc
}

func (s *SIEMService) loadInitialData() {
	// 1. Load historical events from events.ndjson or seed file
	eventFiles := []string{
		"events.ndjson",
		"CenterServer/events.ndjson",
		"../data/logs/siem_events_ndjson.json",
		"data/logs/siem_events_ndjson.json",
	}

	for _, path := range eventFiles {
		file, err := os.Open(path)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(file)
		buf := make([]byte, 0, 64*1024)
		scanner.Buffer(buf, 1024*1024)

		for scanner.Scan() {
			line := bytes.TrimSpace(scanner.Bytes())
			if len(line) == 0 {
				continue
			}
			var log models.SecurityLog
			if err := sonic.Unmarshal(line, &log); err == nil {
				if log.Timestamp.IsZero() {
					log.Timestamp = time.Now()
				}
				if log.SourceIP == "" {
					log.SourceIP = "127.0.0.1"
				}
				if log.Hostname == "" {
					log.Hostname = "node"
				}
				if log.Severity == 0 {
					if log.EventType == "auth_failure" {
						log.Severity = 7
					} else {
						log.Severity = 3
					}
				}
				threat := "Normal"
				if log.Severity >= 12 {
					threat = "Critical"
				} else if log.Severity >= 7 {
					threat = "Suspicious"
				}
				s.RecordIP(log.SourceIP, log.Hostname, "Security/Access Log", threat)
				s.AddLog(log)
			}
		}
		file.Close()
		if len(s.logs) > 0 {
			break
		}
	}

	// 2. Load historical agent telemetry from heartbeat.ndjson
	hbFiles := []string{
		"heartbeat.ndjson",
		"CenterServer/heartbeat.ndjson",
		"../CenterServer/heartbeat.ndjson",
	}
	for _, path := range hbFiles {
		file, err := os.Open(path)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(file)
		buf := make([]byte, 0, 64*1024)
		scanner.Buffer(buf, 1024*1024)

		for scanner.Scan() {
			line := bytes.TrimSpace(scanner.Bytes())
			if len(line) == 0 {
				continue
			}
			var hb models.DeviceStatus
			if err := sonic.Unmarshal(line, &hb); err == nil {
				if hb.SourceIP == "" {
					hb.SourceIP = "127.0.0.1"
				}
				s.RecordAgent(&hb)
				s.RecordIP(hb.SourceIP, hb.Hostname, "Agent Heartbeat", "Normal")
			}
		}
		file.Close()
		if len(s.agents) > 0 {
			break
		}
	}
}

func (s *SIEMService) RecordAgent(status *models.DeviceStatus) {
	if status == nil {
		return
	}
	s.agentMu.Lock()
	defer s.agentMu.Unlock()

	key := status.AgentID
	if key == "" {
		if status.SourceIP != "" && status.SourceIP != "127.0.0.1" {
			key = fmt.Sprintf("%s-%s", status.Hostname, status.SourceIP)
		} else {
			key = status.Hostname
		}
	}
	if key == "" {
		return
	}

	copyStatus := *status
	if copyStatus.AgentID == "" {
		copyStatus.AgentID = key
	}
	s.agents[key] = &copyStatus
}

func (s *SIEMService) GetAgents() []*models.DeviceStatus {
	s.agentMu.RLock()
	defer s.agentMu.RUnlock()

	list := make([]*models.DeviceStatus, 0, len(s.agents))
	for _, status := range s.agents {
		copyStatus := *status
		list = append(list, &copyStatus)
	}
	return list
}

func (s *SIEMService) AddLog(log models.SecurityLog) {
	s.logsMu.Lock()
	defer s.logsMu.Unlock()

	if len(s.logs) >= MaxLogsInMemory {
		// Zero-allocation ring buffer: shift left and overwrite oldest
		copy(s.logs, s.logs[1:])
		s.logs[len(s.logs)-1] = log
	} else {
		s.logs = append(s.logs, log)
	}
}

func (s *SIEMService) GetLogs(limit int) []models.SecurityLog {
	s.logsMu.RLock()
	defer s.logsMu.RUnlock()

	if limit <= 0 || limit > MaxLogsInMemory {
		limit = MaxLogsInMemory
	}

	n := len(s.logs)
	if n == 0 {
		return []models.SecurityLog{}
	}

	if limit > n {
		limit = n
	}

	res := make([]models.SecurityLog, limit)
	// Return newest first (reverse chronological order)
	for i := 0; i < limit; i++ {
		res[i] = s.logs[n-1-i]
	}
	return res
}

func (s *SIEMService) GetLogsPaged(page, pageSize int) ([]models.SecurityLog, int) {
	s.logsMu.RLock()
	defer s.logsMu.RUnlock()

	total := len(s.logs)
	if total == 0 {
		return []models.SecurityLog{}, 0
	}

	if pageSize <= 0 {
		pageSize = 25
	}
	if pageSize > MaxLogsInMemory {
		pageSize = MaxLogsInMemory
	}
	if page < 1 {
		page = 1
	}

	start := (page - 1) * pageSize
	if start >= total {
		return []models.SecurityLog{}, total
	}

	end := start + pageSize
	if end > total {
		end = total
	}

	count := end - start
	res := make([]models.SecurityLog, count)
	for i := 0; i < count; i++ {
		// Newest first mapping: index 0 is s.logs[total - 1 - start]
		res[i] = s.logs[total-1-(start+i)]
	}
	return res, total
}

func (s *SIEMService) RecordIP(ip string, hostname string, category string, threat string) *models.IPTrafficRecord {
	if ip == "" || net.ParseIP(ip) == nil {
		return nil
	}
	s.ipMu.Lock()
	defer s.ipMu.Unlock()

	rec, exists := s.ipRecords[ip]
	now := time.Now()
	if !exists {
		rec = &models.IPTrafficRecord{
			IP:           ip,
			Hostname:     hostname,
			Category:     category,
			RequestCount: 1,
			FirstSeen:    now,
			LastSeen:     now,
			ThreatLevel:  threat,
			Status:       "Monitored",
		}
		s.ipRecords[ip] = rec
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

	copyRec := *rec
	return &copyRec
}

func (s *SIEMService) GetAllIPs() []*models.IPTrafficRecord {
	s.ipMu.RLock()
	defer s.ipMu.RUnlock()

	list := make([]*models.IPTrafficRecord, 0, len(s.ipRecords))
	for _, rec := range s.ipRecords {
		copyRec := *rec
		list = append(list, &copyRec)
	}
	return list
}

func (s *SIEMService) ToggleBlockIP(ip string) (*models.IPTrafficRecord, bool) {
	s.ipMu.Lock()
	defer s.ipMu.Unlock()

	rec, exists := s.ipRecords[ip]
	if !exists {
		return nil, false
	}

	if rec.Status == "Blocked (iptables)" {
		rec.Status = "Monitored"
	} else {
		rec.Status = "Blocked (iptables)"
	}

	copyRec := *rec
	return &copyRec, true
}

func (s *SIEMService) AddClient(ch chan string) {
	s.clientsMu.Lock()
	defer s.clientsMu.Unlock()
	s.clients[ch] = true
}

func (s *SIEMService) RemoveClient(ch chan string) {
	s.clientsMu.Lock()
	defer s.clientsMu.Unlock()
	delete(s.clients, ch)
	close(ch)
}

func (s *SIEMService) Broadcast(data string) {
	s.clientsMu.Lock()
	defer s.clientsMu.Unlock()
	for ch := range s.clients {
		select {
		case ch <- data:
		default:
		}
	}
}
