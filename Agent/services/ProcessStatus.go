package services

import (
	"Agent/models"
	"bytes"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/bytedance/sonic"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/mem"
)

type MetricCollector struct {
	AgentName     string
	ServerUrl     string
	RamLimitMB    uint64
	AgentKey      string
	Client        *http.Client
	lastLatencyMs float64
}

func NewMetricCollector(agent, serverUrl string, ramLimit uint64, agentKey string) *MetricCollector {
	return &MetricCollector{
		AgentName:  agent,
		ServerUrl:  serverUrl,
		RamLimitMB: ramLimit,
		AgentKey:   agentKey,
		Client: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

func (mc *MetricCollector) CollectMetrics() (*models.DeviceStatus, error) {
	hInfo, err := host.Info()
	if err != nil {
		return nil, fmt.Errorf("host info error: %w", err)
	}

	hostname := hInfo.Hostname
	if envName := os.Getenv("AGENT_NAME"); envName != "" {
		hostname = envName
	}

	agentID := hInfo.HostID
	if envID := os.Getenv("AGENT_ID"); envID != "" {
		agentID = envID
	}

	cpuPercents, err := cpu.Percent(200*time.Millisecond, false)
	cpuVal := 0.0
	if err == nil && len(cpuPercents) > 0 {
		cpuVal = cpuPercents[0]
	}

	vMem, err := mem.VirtualMemory()
	if err != nil {
		return nil, fmt.Errorf("mem info error: %w", err)
	}

	totalRAMMB := vMem.Total / 1024 / 1024
	usedRAMMB := vMem.Used / 1024 / 1024
	usedPct := vMem.UsedPercent

	if mc.RamLimitMB > 0 {
		totalRAMMB = mc.RamLimitMB
	}

	dUsage, err := disk.Usage("/")
	diskVal := 0.0
	if err == nil {
		diskVal = dUsage.UsedPercent
	}

	if limitStr := os.Getenv("RAM_LIMIT_MB"); limitStr != "" {
		var limitVal uint64
		if _, err := fmt.Sscanf(limitStr, "%d", &limitVal); err == nil && limitVal > 0 {
			totalRAMMB = limitVal
			usedRAMMB = (totalRAMMB * uint64(vMem.UsedPercent)) / 100
			usedPct = float64(usedRAMMB) / float64(totalRAMMB) * 100.0
		}
	}

	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	agentAllocmb := float64(m.Alloc) / 1024.0 / 1024.0

	return &models.DeviceStatus{
		AgentID:     agentID,
		Hostname:    hostname,
		Platform:    fmt.Sprintf("%s %s", hInfo.Platform, hInfo.PlatformVersion),
		UptimeSec:   hInfo.Uptime,
		CPUUsage:    cpuVal,
		RAMTotalMB:  totalRAMMB,
		RAMUsedMB:   usedRAMMB,
		RAMUsedPct:  usedPct,
		DiskUsedPct: diskVal,
		AgentMemMB:  agentAllocmb,
		LatencyMs:   mc.lastLatencyMs,
	}, nil
}

func (mc *MetricCollector) Send(status *models.DeviceStatus) error {
	jsonData, err := sonic.Marshal(status)
	if err != nil {
		return err
	}
	start := time.Now()
	req, err := http.NewRequest(http.MethodPost, mc.ServerUrl, bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	// CenterServer mewajibkan header ini pada /api/v1/agent/* (RequireAgentKey).
	if mc.AgentKey != "" {
		req.Header.Set("X-Agent-Key", mc.AgentKey)
	}

	resp, err := mc.Client.Do(req)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	mc.lastLatencyMs = float64(time.Since(start).Microseconds()) / 1000.0

	return nil
}

func (mc *MetricCollector) TestConnection() (time.Duration, error) {
	start := time.Now()

	resp, err := mc.Client.Get(mc.ServerUrl + "/api/v1/agents")
	if err != nil {
		return 0, fmt.Errorf("Server unreachable: %w", err)
	}

	defer resp.Body.Close()

	rtt := time.Since(start)
	return rtt, nil
}
