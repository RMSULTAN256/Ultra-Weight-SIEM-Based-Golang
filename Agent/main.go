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

	collector := services.NewMetricCollector(agentClient, heartBeatUrl, 0)
	logCfg, err := config.LoadConfig("config/log_collector.json")
	if err != nil {
		fmt.Println("Failed to load, logs config not found")
	}

	logScanner := services.NewLogCollector(baseURL, agentClient)

	if logCfg != nil {
		scanInterval := logCfg.ScanIntervalSec
		if scanInterval <= 0 {
			scanInterval = 5
		}

		go func() {
			logTicker := time.NewTicker(time.Duration(scanInterval) * time.Second)
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
