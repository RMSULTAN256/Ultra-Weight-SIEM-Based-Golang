package services

import (
	"Agent/models"
	"bufio"
	"bytes"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bytedance/sonic"
)

type LogCollector struct {
	ServerUrl   string
	AgentName   string
	Client      *http.Client
	fileOffsets map[string]int64
}

func NewLogCollector(serverUrl, agentName string) *LogCollector {
	return &LogCollector{
		ServerUrl: serverUrl,
		AgentName: agentName,
		Client: &http.Client{
			Timeout: 5 * time.Second,
		},
		fileOffsets: make(map[string]int64),
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

func (ls *LogCollector) processFile(file string, target models.TargetConfig) {
	f, err := os.Open(file)
	if err != nil {
		return
	}

	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		return
	}

	offset := ls.fileOffsets[file]
	if stat.Size() < offset {
		offset = 0
	}

	if stat.Size() == offset {
		return
	}

	if _, err := f.Seek(offset, 0); err != nil {
		return
	}

	reader := bufio.NewReader(f)
	for {
		line, err := reader.ReadString('\n')
		if len(line) > 0 {
			offset += int64(len(line))
			lineClean := strings.TrimRight(line, "\r\n")
			if len(target.Keywords) == 0 {
				ls.handleThreatFound(lineClean, "raw_log", target.AppName)
			} else {
				for _, keyword := range target.Keywords {
					if strings.Contains(strings.ToLower(lineClean), strings.ToLower(keyword)) {
						ls.handleThreatFound(lineClean, keyword, target.AppName)
						break
					}
				}
			}
		}
		if err != nil {
			break // Mencapai akhir file (EOF)
		}
	}
	ls.fileOffsets[file] = offset
}

func (ls *LogCollector) handleThreatFound(rawLine, keyword, appName string) {
	extractedIP := "127.0.0.1"
	tokens := strings.Fields(rawLine)
	for _, t := range tokens {
		if ip := net.ParseIP(t); ip != nil {
			extractedIP = ip.String()
			break
		}
	}

	severity := 1
	evenType := "event_log"

	switch strings.ToLower(keyword) {
	case "unioun select, eval(":
		evenType = "web_attack"
		severity = 10
	case "failed password", "invalid user":
		evenType = "auth_failure"
		severity = 6
	case "403":
		severity = 4
	case "404":
		severity = 2
	}

	secLog := models.SecurityLog{
		Timestamp: time.Now(),
		Hostname:  ls.AgentName,
		EventType: "event_log",
		Severity:  severity,
		SourceIP:  extractedIP,
		Message:   rawLine,
		Status:    keyword,
		Service:   appName,
	}

	ls.sendLogToCenter(secLog)
}

func (ls *LogCollector) sendLogToCenter(log models.SecurityLog) error {
	jsonData, err := sonic.Marshal(log)
	if err != nil {
		return err
	}

	endPoint := ls.ServerUrl + "/api/v1/agent/logs"
	resp, err := ls.Client.Post(endPoint, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}
