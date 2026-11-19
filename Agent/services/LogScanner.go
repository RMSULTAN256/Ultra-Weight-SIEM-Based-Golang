package services

import (
	"Agent/models"
	"Agent/proto"
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/bytedance/sonic"
)

const InMemoryQueueCapacity = 1000

type LogCollector struct {
	ServerUrl, AgentName, AgentKey string
	Client                         *http.Client
	grpcMu                         sync.RWMutex
	GRPCClient                     *GRPCClient
	stateMu                        sync.Mutex
	state                          map[string]fileState
	bufferQueue                    chan models.SecurityLog
	stopCh                         chan struct{}
	wg                             sync.WaitGroup
	closeOnce                      sync.Once
	closeMu                        sync.RWMutex
	isClosed                       bool
}

type fileState struct {
	Inode  uint64 `json:"inode"`
	Offset int64  `json:"offset"`
}

func inodeOff(fi os.FileInfo) uint64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return st.Ino
	}
	return 0
}

var rules = []struct {
	kw, typ string
	sev     int
}{
	// Web Application & SQL Injection Attacks
	{"union select", "web_attack", 10},
	{"union all select", "web_attack", 10},
	{"' or '1'='1", "web_attack", 10},
	{"' or 1=1", "web_attack", 10},
	{"information_schema", "web_attack", 10},
	{"sleep(", "web_attack", 10},
	{"benchmark(", "web_attack", 10},
	{"drop table", "web_attack", 11},
	{"insert into", "web_attack", 9},
	{"eval(", "web_attack", 10},
	{"base64_decode", "web_attack", 9},
	{"/etc/passwd", "web_attack", 10},
	{"<script", "web_attack", 10},
	{"cmd.exe", "web_attack", 10},
	{"/bin/sh", "web_attack", 10},
	{"/bin/bash", "web_attack", 10},

	// Authentication & Database Brute Force
	{"failed password", "auth_failure", 6},
	{"invalid user", "auth_failure", 6},
	{"authentication failure", "auth_failure", 6},
	{"access denied for user", "db_auth_failure", 7},
	{"password authentication failed for user", "db_auth_failure", 7},
	{"aborted connection", "db_anomaly", 6},
	{"sqlstate[", "sql_error", 7},

	// Network, Firewall & Port Scans
	{"ufw block", "port_scan", 5},
	{"connection refused", "port_scan", 4},

	// Privilege Escalation
	{"sudo:", "privilege_activity", 5},
	{"pam_unix(sudo:session): session opened", "privilege_activity", 5},

	// System & Kernel Errors
	{"oom-killer", "system_error", 8},
	{"out of memory", "system_error", 8},
	{"segfault", "system_error", 8},
}

func NewLogCollector(serverUrl, agentName, agentKey string) *LogCollector {
	lc := &LogCollector{
		ServerUrl: serverUrl,
		AgentName: agentName,
		AgentKey:  agentKey,
		Client: &http.Client{
			Timeout: 5 * time.Second,
		},
		state:       make(map[string]fileState),
		bufferQueue: make(chan models.SecurityLog, InMemoryQueueCapacity),
		stopCh:      make(chan struct{}),
	}
	lc.wg.Add(1)
	go lc.startQueueWorker()
	return lc
}

// Close menghentikan worker queue secara bersih dan menutup bufferQueue untuk mencegah kebocoran goroutine.
func (ls *LogCollector) Close() {
	ls.closeOnce.Do(func() {
		ls.closeMu.Lock()
		ls.isClosed = true
		close(ls.stopCh)
		close(ls.bufferQueue)
		ls.closeMu.Unlock()

		ls.wg.Wait()
	})
}

func (lg *LogCollector) ScanTarget(target models.TargetConfig) {
	files, err := filepath.Glob(target.FilePath)
	if err != nil {
		return
	}

	matchedFiles := make(map[string]struct{}, len(files))
	for _, file := range files {
		matchedFiles[file] = struct{}{}
		lg.processFile(file, target)
	}

	// Prune stale / deleted file entries from state to prevent unbounded memory growth
	lg.stateMu.Lock()
	for recordedPath := range lg.state {
		if _, exists := matchedFiles[recordedPath]; !exists {
			if _, statErr := os.Stat(recordedPath); os.IsNotExist(statErr) {
				delete(lg.state, recordedPath)
			}
		}
	}
	lg.stateMu.Unlock()
}

func (ls *LogCollector) processFile(path string, target models.TargetConfig) {
	ls.stateMu.Lock()
	st, ok := ls.state[path]
	ls.stateMu.Unlock()

	fi, err := os.Stat(path)
	if err != nil {
		return
	}
	ino := inodeOff(fi)

	switch {
	case !ok:
		ls.stateMu.Lock()
		ls.state[path] = fileState{Inode: ino, Offset: fi.Size()}
		ls.stateMu.Unlock()
		return
	case st.Inode != ino || fi.Size() < st.Offset:
		st = fileState{Inode: ino, Offset: 0}
	}

	// Jika tidak ada data baru, hindari alokasi buffer 64KB dan pembukaan file yang sia-sia
	if fi.Size() <= st.Offset {
		ls.stateMu.Lock()
		ls.state[path] = st
		ls.stateMu.Unlock()
		return
	}

	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	if _, err := f.Seek(st.Offset, io.SeekStart); err != nil {
		return
	}

	remaining := fi.Size() - st.Offset
	bufSize := int(remaining)
	if bufSize > 64*1024 {
		bufSize = 64 * 1024
	} else if bufSize < 4096 {
		bufSize = 4096
	}

	r := bufio.NewReaderSize(f, bufSize)
	for {
		line, err := r.ReadString('\n')
		if !strings.HasSuffix(line, "\n") {
			break
		}
		clean := strings.TrimRight(line, "\r\n")
		if sendErr := ls.handleLine(clean, target); sendErr != nil {
			break
		}
		st.Offset += int64(len(line))
		if err != nil {
			break // EOF
		}
	}

	ls.stateMu.Lock()
	ls.state[path] = st
	ls.stateMu.Unlock()
}

func (ls *LogCollector) handleLine(rawLine string, target models.TargetConfig) error {
	extractedIP := "127.0.0.1"
	tokens := strings.Fields(rawLine)
	for _, t := range tokens {
		if ip := net.ParseIP(t); ip != nil {
			extractedIP = ip.String()
			break
		}
	}
	severity := 1
	eventType := "event_log"
	status := "raw_log"

	lower := strings.ToLower(rawLine)
	for _, r := range rules {
		if strings.Contains(lower, r.kw) {
			eventType = r.typ
			severity = r.sev
			status = r.kw
			break
		}
	}

	if status == "raw_log" && len(target.Keywords) > 0 {
		for _, kw := range target.Keywords {
			if strings.Contains(lower, strings.ToLower(kw)) {
				status = kw
				break
			}
		}
	}

	secLog := models.SecurityLog{
		Timestamp: time.Now(),
		Hostname:  ls.AgentName,
		EventType: eventType,
		Severity:  severity,
		SourceIP:  extractedIP,
		Message:   rawLine,
		Status:    status,
		Service:   target.AppName,
	}

	ls.closeMu.RLock()
	if ls.isClosed {
		ls.closeMu.RUnlock()
		return fmt.Errorf("log collector closed")
	}
	defer ls.closeMu.RUnlock()

	select {
	case ls.bufferQueue <- secLog:
		return nil
	default:
		return fmt.Errorf("in-memory ring buffer penuh (kapasitas %d)", InMemoryQueueCapacity)
	}
}

func (ls *LogCollector) sendLogToCenter(log models.SecurityLog) error {
	select {
	case <-ls.stopCh:
		return fmt.Errorf("log collector closed")
	default:
	}

	jsonData, err := sonic.Marshal(log)
	if err != nil {
		return err
	}

	grpcClient := ls.GetGRPCClient()
	if grpcClient != nil {
		err = grpcClient.SendLog(&proto.LogPacket{
			AgentName:   ls.AgentName,
			PayloadJson: jsonData,
		})
		if err == nil {
			return nil
		}
	}

	if ls.Client == nil {
		ls.Client = &http.Client{Timeout: 5 * time.Second}
	}

	endPoint := ls.ServerUrl + "/api/v1/agent/logs"
	req, err := http.NewRequest(http.MethodPost, endPoint, bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	// CenterServer mewajibkan header ini pada /api/v1/agent/* (RequireAgentKey).
	if ls.AgentKey != "" {
		req.Header.Set("X-Agent-Key", ls.AgentKey)
	}

	resp, err := ls.Client.Do(req)
	if err != nil {
		return fmt.Errorf("gRPC & HTTP fallback gagal: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP fallback server error response status: %d", resp.StatusCode)
	}

	return nil
}

// GetGRPCClient mengambil referensi GRPCClient secara thread-safe
func (ls *LogCollector) GetGRPCClient() *GRPCClient {
	ls.grpcMu.RLock()
	defer ls.grpcMu.RUnlock()
	return ls.GRPCClient
}

func (ls *LogCollector) SetGRPCClient(client *GRPCClient) {
	ls.grpcMu.Lock()
	defer ls.grpcMu.Unlock()
	ls.GRPCClient = client
}

func (ls *LogCollector) startQueueWorker() {
	defer ls.wg.Done()
	for secLog := range ls.bufferQueue {
		select {
		case <-ls.stopCh:
			return
		default:
		}
		if err := ls.sendLogToCenter(secLog); err != nil {
			select {
			case <-ls.stopCh:
				return
			case <-time.After(200 * time.Millisecond):
			}
		}
	}
}

func (ls *LogCollector) GetQueueLen() int {
	if ls.bufferQueue == nil {
		return 0
	}
	return len(ls.bufferQueue)
}
