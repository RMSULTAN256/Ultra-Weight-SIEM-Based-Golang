package services

import (
	"agent/models"
	"bufio"
	"bytes"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bytedance/sonic"
)

type LogCollector struct {
	ServerUrl string
	AgentName string
	Client    *http.Client
}

func NewLogCollector(serverUrl, agentName string) *LogCollector {
	return &LogCollector{
		ServerUrl: serverUrl,
		AgentName: agentName,
		Client: &http.Client{
			Timeout: 5 * time.Second,
		},
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

	scanner := bufio.NewScanner(f) //ignore
	for scanner.Scan() {
		line := scanner.Text()

		for _, keyword := range target.Keywords {
			if strings.Contains(strings.ToLower(line), strings.ToLower(keyword)) {
				ls.handleThreatFound(line, keyword, target.AppName)
				break
			}
		}
	}
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

	secLog := models.SecurityLog{
		Timestamp: time.Now(),
		Hostname:  ls.AgentName,
		EventType: "threat_detected",
		Severity:  8,
		SourceIP:  extractedIP,
		Message:   fmt.Sprintf("[%s] Terdeteksi '%s' pada: %s", appName, keyword, rawLine),
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
