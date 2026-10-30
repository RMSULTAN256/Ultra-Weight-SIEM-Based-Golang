package services

import (
	"Agent/models"
	"bytes"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/bytedance/sonic"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/mem"
)

type MetricCollector struct {
	AgentName  string
	ServerUrl  string
	RamLimitMB uint64
	Client     *http.Client
}

func NewMetricCollector(agent, serverUrl string, ramLimit uint64) *MetricCollector {
	return &MetricCollector{
		AgentName:  agent,
		ServerUrl:  serverUrl,
		RamLimitMB: ramLimit,
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
	}, nil
}

func (mc *MetricCollector) Send(status *models.DeviceStatus) error {
	jsonData, err := sonic.Marshal(status)
	if err != nil {
		return err
	}

	resp, err := mc.Client.Post(mc.ServerUrl, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	return nil
}
