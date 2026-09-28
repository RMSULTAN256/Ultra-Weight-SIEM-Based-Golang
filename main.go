package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
)

func mai22n() {
	seenIP := make(map[string]bool)
	var uniqueIPs []string

	inputPath := "sql/ac_login_activities.sql"
	inputFile, err := os.Open(inputPath)
	if err != nil {
		log.Fatalf("Gagal membuka file input: %v", err)
	}
	defer inputFile.Close()

	outputPath := "ip_logs.txt"
	outputFile, err := os.Create(outputPath)
	if err != nil {
		log.Fatalf("Gagal membuat file output: %v", err)
	}
	defer outputFile.Close()

	writer := bufio.NewWriter(outputFile)
	reHex := regexp.MustCompile(`0x([0-9a-fA-F]+)`)
	scanner := bufio.NewScanner(inputFile)

	fmt.Println("=== PROSES EKSTRAK DAN MENYIMPAN IP ===")

	for scanner.Scan() {
		line := scanner.Text()

		if strings.HasPrefix(line, "(") {
			match := reHex.FindStringSubmatch(line)
			if len(match) > 1 {
				hexCode := match[1]

				ipBytes, err := hex.DecodeString(hexCode)
				if err == nil {
					ipStr := string(ipBytes)

					if !seenIP[ipStr] {
						seenIP[ipStr] = true
						uniqueIPs = append(uniqueIPs, ipStr)

						writer.WriteString(ipStr + "\n")
						fmt.Printf("IP Unik [%d]: %s tersimpan\n", len(uniqueIPs), ipStr)
					}
				}
			}
		}
	}

	writer.Flush()

	if err := scanner.Err(); err != nil {
		log.Fatalf("Gagal membaca file: %v", err)
	}

	fmt.Printf("\nSelesai! Total %d IP unik tersimpan di: %s\n", len(uniqueIPs), outputPath)
}
