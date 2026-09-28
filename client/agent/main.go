package main

import (
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

// Struktur data yang sama dengan yang diharapkan server
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

// Fungsi mengambil data hardware/OS menggunakan gopsutil
func CollectMetrics() (*DeviceStatus, error) {
	// 1. Info Host (Hostname, OS, Uptime)
	hInfo, err := host.Info()
	if err != nil {
		return nil, fmt.Errorf("host info error: %w", err)
	}

	// 2. Info CPU (mengukur sampling selama 200 milidetik)
	cpuPercents, err := cpu.Percent(200*time.Millisecond, false)
	cpuVal := 0.0
	if err == nil && len(cpuPercents) > 0 {
		cpuVal = cpuPercents[0]
	}

	// 3. Info RAM / Virtual Memory
	vMem, err := mem.VirtualMemory()
	if err != nil {
		return nil, fmt.Errorf("mem info error: %w", err)
	}

	// 4. Info Disk partisi root ("/" di Linux atau "C:" di Windows)
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
		RAMTotalMB:  vMem.Total / 1024 / 1024, // Byte ke Megabyte
		RAMUsedMB:   vMem.Used / 1024 / 1024,
		RAMUsedPct:  vMem.UsedPercent,
		DiskUsedPct: diskVal,
	}, nil
}

// Fungsi mengirim JSON data via HTTP POST
func SendHeartbeat(client *http.Client, url string, status *DeviceStatus) error {
	// Encode struct ke JSON
	jsonData, err := sonic.Marshal(status)
	if err != nil {
		return err
	}

	// Siapkan request POST
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	// Eksekusi request
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server merespons error status: %d", resp.StatusCode)
	}

	return nil
}

func main() {
	serverEndpoint := os.Getenv("AUTH_SERVER_URL")
	if serverEndpoint == "" {
		serverEndpoint = "http://center-siem:8080/api/v1/agent/heartbeat"
	}

	// HTTP client dengan timeout 5 detik agar tidak menggantung jika server mati
	httpClient := &http.Client{
		Timeout: 5 * time.Second,
	}

	// Timer berkala tiap 5 detik
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	fmt.Println("Agent pengawas aktif. Mengirim status setiap 5 detik...")

	// Loop ticker berjalan terus-menerus
	for range ticker.C {
		metrics, err := CollectMetrics()
		if err != nil {
			fmt.Printf("[ERROR] Gagal membaca metrik: %v\n", err)
			continue
		}

		err = SendHeartbeat(httpClient, serverEndpoint, metrics)
		if err != nil {
			fmt.Printf("[GAGAL] Tidak bisa kirim data ke server: %v\n", err)
		}
	}
}
