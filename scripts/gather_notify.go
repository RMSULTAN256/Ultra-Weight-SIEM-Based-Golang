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
	flag.Parse()

	gatherURL := os.Getenv("GATHER_WEBHOOK_URL")
	if gatherURL == "" {
		gatherURL = "https://api.v2.gather.town/api/v2/hooks/spaces/be1dc8bc-ace6-482a-9e5b-24490f32d50b/objects/87d2a4c0-137d-46d2-8afc-1830e1253e98"
	}
	gatherSecret := os.Getenv("GATHER_WEBHOOK_SECRET")
	if gatherSecret == "" {
		gatherSecret = "whsec_Z2F00oMyO2+A2xPiYJYZy+jVE/jBLf8vAYTzS9pv7xE="
	}

	if *stateFlag != "" {
		if err := sendEvent(gatherURL, gatherSecret, "status.set", map[string]string{"state": *stateFlag}); err != nil {
			fmt.Printf("[Gather] Error setting state: %v\n", err)
		} else {
			fmt.Printf("[Gather] State updated to '%s'\n", *stateFlag)
		}
	}

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
	}
}
