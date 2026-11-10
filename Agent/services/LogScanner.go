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
	"syscall"
	"time"

	"github.com/bytedance/sonic"
)

type LogCollector struct {
	ServerUrl, AgentName, AgentKey string
	Client                         *http.Client
	GRPCClient                     *GRPCClient
	fileOffsets                    map[string]int64
	state                          map[string]fileState
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
	{"union select", "web_attack", 10},
	{"eval(", "web_attack", 10},
	{"failed password", "auth_failure", 6},
	{"invalid user", "auth_failure", 6},
}

func NewLogCollector(serverUrl, agentName, agentKey string) *LogCollector {
	return &LogCollector{
		ServerUrl: serverUrl,
		AgentName: agentName,
		AgentKey:  agentKey,
		Client: &http.Client{
			Timeout: 5 * time.Second,
		},
		state: make(map[string]fileState),
	}
}

func (lg *LogCollector) ScanTarget(target models.TargetConfig) {
	files, err := filepath.Glob(target.FilePath)
	if err != nil {
		return
	}

	for _, file := range files {
		lg.processFile(file, target)
	}
}

func (ls *LogCollector) processFile(path string, target models.TargetConfig) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return
	}
	ino := inodeOff(fi)
	st, ok := ls.state[path]
	switch {
	case !ok:
		ls.state[path] = fileState{Inode: ino, Offset: fi.Size()}
		return
	case st.Inode != ino || fi.Size() < st.Offset:
		st = fileState{Inode: ino, Offset: 0}
	}
	if fi.Size() == st.Offset {
		ls.state[path] = st
		return
	}
	if _, err := f.Seek(st.Offset, io.SeekStart); err != nil {
		return
	}
	r := bufio.NewReaderSize(f, 64*1024)
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
	ls.state[path] = st
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
	return ls.sendLogToCenter(secLog)
}

func (ls *LogCollector) sendLogToCenter(log models.SecurityLog) error {
	jsonData, err := sonic.Marshal(log)
	if err != nil {
		return err
	}
	if ls.GRPCClient != nil && ls.GRPCClient.logStream != nil {
		err = ls.GRPCClient.logStream.Send(&proto.LogPacket{
			AgentName:   ls.AgentName,
			PayloadJson: jsonData,
		})
		if err == nil {
			return nil
		}
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
	defer resp.Body.Close()
	return nil
}
func (ls *LogCollector) SetGRPCClient(client *GRPCClient) {
	ls.GRPCClient = client
}
