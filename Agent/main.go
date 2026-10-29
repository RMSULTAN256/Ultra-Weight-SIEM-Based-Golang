package main

import (
	"agent/services"
	"fmt"
	"os"
	"time"
)

func main() {

	agentClient := os.Getenv("HOSTNAME_NAME")
	serverEndpoint := os.Getenv("AUTH_SERVER_URL")

	collector := services.NewMetricCollector(agentClient, serverEndpoint, 0)

	if serverEndpoint == "" {
		serverEndpoint = "https://gowaz.vulnstack.xyz/api/v1/agent/heartbeat"
	}

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	fmt.Println("Agent pengawas aktif. Mengirim status setiap detik...")

	for range ticker.C {
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
