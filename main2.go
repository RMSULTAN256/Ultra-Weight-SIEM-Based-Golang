package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"MiniSiem/services"
)

func mai2n() {
	inputFile, err := os.Open("ip_logs.txt")
	if err != nil {
		log.Fatalf("Gagal membuka file input: %v", err)
	}
	defer inputFile.Close()

	outputPath := "ip_details_log.json"
	outputFile, err := os.Create(outputPath)
	if err != nil {
		log.Fatalf("Gagal membuat file output: %v", err)
	}
	defer outputFile.Close()

	writer := bufio.NewWriter(outputFile)
	ipService := services.NewIPService()
	scanner := bufio.NewScanner(inputFile)

	count := 0
	fmt.Println("=== MEMULAI SCAN & SIMPAN DETAIL LENGKAP IP KE LOG ===")

	for scanner.Scan() {
		ip := strings.TrimSpace(scanner.Text())
		if ip == "" {
			continue
		}

		count++
		fmt.Printf("[%d] Sedang scan IP: %s...\n", count, ip)

		info, err := ipService.GetIPInfo(ip)
		if err != nil {
			log.Printf("Gagal scan %s: %v\n", ip, err)
			continue
		}

		jsonData, err := json.Marshal(info)
		if err != nil {
			log.Printf("Gagal serialize json untuk IP %s: %v\n", ip, err)
			continue
		}

		writer.WriteString(string(jsonData) + "\n")

		time.Sleep(200 * time.Millisecond)
	}

	writer.Flush()

	if err := scanner.Err(); err != nil {
		log.Fatalf("Gagal membaca file scanner: %v", err)
	}

	fmt.Printf("\nSelesai! Seluruh detail %d IP berhasil disimpan ke: %s\n", count, outputPath)
}
