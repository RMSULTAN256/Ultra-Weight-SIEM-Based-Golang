package main

import (
	"Agent/config"
	"Agent/services"
	"fmt"
	"os"
	"time"
)

func main() {

	agentClient := os.Getenv("HOSTNAME_NAME")
	if agentClient == "" {
		agentClient = "ubuntu"
	}
	baseURL := os.Getenv("SERVER_URL")
	if baseURL == "" {
		baseURL = "https://gowaz.vulnstack.xyz"
	}

	heartBeatUrl := baseURL + "/api/v1/agent/heartbeat"

	// Kunci API untuk endpoint /api/v1/agent/* di CenterServer.
	// Tanpa ini, heartbeat dan fallback log via HTTP akan ditolak (401).
	agentKey := os.Getenv("AGENT_API_KEY")
	if agentKey == "" {
		fmt.Println("[WARN] AGENT_API_KEY kosong: heartbeat & fallback log HTTP akan ditolak (401)")
	}

	collector := services.NewMetricCollector(agentClient, heartBeatUrl, 0, agentKey)
	logCfg, err := config.LoadConfig("config/log_collector.json")
	if err != nil {
		fmt.Println("Failed to load, logs config not found")
	}

	logScanner := services.NewLogCollector(baseURL, agentClient, agentKey)

	grpcAddr := os.Getenv("GRPC_SERVER")
	if grpcAddr == "" {
		grpcAddr = "gowaz.vulnstack.xyz:443"
	}

	grpcClient, err := services.NewGRPCClient(grpcAddr, agentClient, agentKey)
	if err != nil {
		fmt.Printf("[ERROR] Gagal membuat klien gRPC: %v\n", err)
	} else {
		logScanner.SetGRPCClient(grpcClient)
	}
	if logCfg != nil {
		scanInterval := logCfg.ScanIntervalSec
		interval := 5 * time.Second

		if logCfg.ScanIntervalMs > 0 {
			interval = time.Duration(logCfg.ScanIntervalMs) * time.Millisecond
		} else if logCfg.ScanIntervalSec > 0 {
			interval = time.Duration(logCfg.ScanIntervalSec) * time.Second
		}

		go func() {
			logTicker := time.NewTicker(interval)
			defer logTicker.Stop()
			fmt.Printf("[LOG] Active, Monitoring %d target log every %d second", len(logCfg.Targets), scanInterval)

			for range logTicker.C {
				for _, target := range logCfg.Targets {
					logScanner.ScanTarget(target)
				}
			}
		}()
	}
	heartbeatTicker := time.NewTicker(2 * time.Second)
	defer heartbeatTicker.Stop()

	fmt.Println("Agent pengawas aktif. Mengirim status setiap detik...")

	for range heartbeatTicker.C {
		metrics, err := collector.CollectMetrics()
		if err != nil {
			fmt.Printf("[ERROR] Gagal membaca metrik: %v\n", err)
			continue
		}

		err = collector.Send(metrics)
		if err != nil {
			fmt.Printf("[GAGAL] Tidak bisa kirim data ke server: %v\n", err)
		}
	}
}
