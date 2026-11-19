package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

type GatherEnvelope struct {
	Type      string      `json:"type"`
	Timestamp string      `json:"timestamp"`
	Data      interface{} `json:"data"`
}

func sendEvent(url, secret, eventType string, data interface{}) error {
	cleanSecret := strings.TrimPrefix(secret, "whsec_")
	keyBytes, err := base64.StdEncoding.DecodeString(cleanSecret)
	if err != nil {
		return fmt.Errorf("invalid secret: %w", err)
	}

	payload := GatherEnvelope{
		Type:      eventType,
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Data:      data,
	}
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	randomBytes := make([]byte, 8)
	_, _ = rand.Read(randomBytes)
	webhookID := "msg_" + hex.EncodeToString(randomBytes)
	nowSec := fmt.Sprintf("%d", time.Now().Unix())

	signedContent := fmt.Sprintf("%s.%s.%s", webhookID, nowSec, string(bodyBytes))
	mac := hmac.New(sha256.New, keyBytes)
	mac.Write([]byte(signedContent))
	sigBase64 := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	sigHeader := "v1," + sigBase64

	req, err := http.NewRequest("POST", url, bytes.NewReader(bodyBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("webhook-id", webhookID)
	req.Header.Set("webhook-timestamp", nowSec)
	req.Header.Set("webhook-signature", sigHeader)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("status %d: %s", resp.StatusCode, string(b))
	}
	return nil
}

func main() {
	stateFlag := flag.String("state", "", "status state: off, on, alert, working")
	msgFlag := flag.String("msg", "", "activity message text")
	urlFlag := flag.String("url", "", "activity link URL")
	countFlag := flag.Int("count", -1, "counter value (for inbox/counter objects)")
	colorFlag := flag.String("color", "", "variant color (black, blue, green, red, yellow, etc)")
	flag.Parse()

	gatherURL := os.Getenv("GATHER_WEBHOOK_URL")
	if gatherURL == "" {
		gatherURL = "https://api.v2.gather.town/api/v2/hooks/spaces/be1dc8bc-ace6-482a-9e5b-24490f32d50b/objects/87d2a4c0-137d-46d2-8afc-1830e1253e98"
	}
	gatherSecret := os.Getenv("GATHER_WEBHOOK_SECRET")
	if gatherSecret == "" {
		gatherSecret = "whsec_Z2F00oMyO2+A2xPiYJYZy+jVE/jBLf8vAYTzS9pv7xE="
	}

	// 1. Tangani State / Warna (mendukung objek status dan objek inbox/variant)
	if *stateFlag != "" {
		// Coba set status.set (untuk preset status)
		_ = sendEvent(gatherURL, gatherSecret, "status.set", map[string]string{"state": *stateFlag})

		// Map state ke warna variant (untuk preset inbox/counter)
		variantColor := *colorFlag
		if variantColor == "" {
			switch *stateFlag {
			case "on", "success":
				variantColor = "green"
			case "alert", "failure", "failed":
				variantColor = "red"
			case "working", "building":
				variantColor = "yellow"
			case "off":
				variantColor = "black"
			}
		}
		if variantColor != "" {
			_ = sendEvent(gatherURL, gatherSecret, "variant.set", map[string]string{"color": variantColor})
		}
		fmt.Printf("[Gather] State '%s' (variant color: '%s') processed\n", *stateFlag, variantColor)
	} else if *colorFlag != "" {
		_ = sendEvent(gatherURL, gatherSecret, "variant.set", map[string]string{"color": *colorFlag})
	}

	// 2. Tangani Counter (bila ditentukan eksplisit)
	if *countFlag >= 0 {
		if err := sendEvent(gatherURL, gatherSecret, "counter.set", map[string]int{"count": *countFlag}); err != nil {
			fmt.Printf("[Gather] Error setting counter: %v\n", err)
		} else {
			fmt.Printf("[Gather] Counter set to %d\n", *countFlag)
		}
	}

	// 3. Tangani Pesan Aktivitas / Inbox Feed
	if *msgFlag != "" {
		link := *urlFlag
		if link == "" {
			link = "https://gowaz.vulnstack.xyz/analytics"
		}
		data := map[string]string{
			"id":   fmt.Sprintf("ci-%d", time.Now().UnixNano()),
			"text": *msgFlag,
			"url":  link,
		}
		if err := sendEvent(gatherURL, gatherSecret, "activity.add", data); err != nil {
			fmt.Printf("[Gather] Error adding activity: %v\n", err)
		} else {
			fmt.Printf("[Gather] Activity added: %s\n", *msgFlag)
		}

		// Tambahkan 1 tumpukan lembar kertas di inbox secara otomatis jika count tidak diset manual
		if *countFlag < 0 {
			_ = sendEvent(gatherURL, gatherSecret, "counter.increment", map[string]int{"by": 1})
		}
	}
}
