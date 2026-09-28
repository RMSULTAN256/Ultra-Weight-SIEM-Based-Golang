package main

import (
	"fmt"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/mem"
)

type DeviceStatus struct {
	Hostname    string  `json:"hostname"`
	Platform    string  `json:"platform"`
	UptimeSec   uint64  `json:"uptime_sec"`
	CPUUsage    float64 `json:"cpu_usage"`
	RAMTotalMB  uint64  `json:"ram_total_mb"`
	RAMUsedMB   uint64  `json:"ram_used_mb"`
	RAMUsedPct  float64 `json:"ram_used_pct"`
	DiskUsedPct float64 `json:"disk_used_pct"`
}

func CollectMetrics() (*DeviceStatus, error) {
	// Host info
	hInfo, err := host.Info()
	if err != nil {
		return nil, err
	}

	// CPU percent (interval 0: delta sejak pemanggilan terakhir atau non-blocking)
	cpuPercents, err := cpu.Percent(200*time.Millisecond, false)
	cpuVal := 0.0
	if err == nil && len(cpuPercents) > 0 {
		cpuVal = cpuPercents[0]
	}

	// Virtual Memory
	vMem, err := mem.VirtualMemory()
	if err != nil {
		return nil, err
	}

	// Disk usage root "/"
	dUsage, err := disk.Usage("/")
	diskVal := 0.0
	if err == nil {
		diskVal = dUsage.UsedPercent
	}

	return &DeviceStatus{
		Hostname:    hInfo.Hostname,
		Platform:    fmt.Sprintf("%s %s", hInfo.Platform, hInfo.PlatformVersion),
		UptimeSec:   hInfo.Uptime,
		CPUUsage:    cpuVal,
		RAMTotalMB:  vMem.Total / 1024 / 1024,
		RAMUsedMB:   vMem.Used / 1024 / 1024,
		RAMUsedPct:  vMem.UsedPercent,
		DiskUsedPct: diskVal,
	}, nil
}
