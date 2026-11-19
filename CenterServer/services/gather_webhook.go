package services

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"server3/models"
	"strings"
	"time"
)

var gatherHTTPClient = &http.Client{
	Timeout: 5 * time.Second,
}

type GatherPayload struct {
	Type      string      `json:"type"`
	Timestamp string      `json:"timestamp"`
	Data      interface{} `json:"data"`
}

// SendGatherEvent mengirimkan event tertanda HMAC-SHA256 ke Gather Smart Object
func SendGatherEvent(webhookURL, secretKey, eventType string, data interface{}) error {
	cleanSecret := strings.TrimPrefix(secretKey, "whsec_")
	keyBytes, err := base64.StdEncoding.DecodeString(cleanSecret)
	if err != nil {
		return fmt.Errorf("invalid gather secret base64: %w", err)
	}

	payload := GatherPayload{
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

	req, err := http.NewRequest("POST", webhookURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("webhook-id", webhookID)
	req.Header.Set("webhook-timestamp", nowSec)
	req.Header.Set("webhook-signature", sigHeader)

	resp, err := gatherHTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("gather webhook error status: %d", resp.StatusCode)
	}
	return nil
}

// NotifyGatherAlert menyiarkan alert kritis ke Gather.town Smart Object
func NotifyGatherAlert(log models.SecurityLog) {
	if log.Status != "ESCALATED_ALERT" && log.Severity < 12 {
		return
	}

	go func() {
		gatherURL := os.Getenv("GATHER_WEBHOOK_URL")
		if gatherURL == "" {
			gatherURL = "https://api.v2.gather.town/api/v2/hooks/spaces/be1dc8bc-ace6-482a-9e5b-24490f32d50b/objects/786fd71b-ad8f-472f-9a28-78ae96dba4ba"
		}

		gatherSecret := os.Getenv("GATHER_WEBHOOK_SECRET")
		if gatherSecret == "" {
			gatherSecret = "whsec_Z2F0gGZIZv6qnUiqwZPx0bMU2v2d4aWzP/qrN2vndBw="
		}

		// 1. Ubah status lampu indikator di Gather menjadi 'alert'
		// Catatan: Preset objek adalah 'status', gunakan event 'status.set'
		_ = SendGatherEvent(gatherURL, gatherSecret, "status.set", map[string]string{
			"state": "alert",
		})

		// 2. Kirim detail insiden ke activity feed
		desc := log.RuleDesc
		if desc == "" {
			desc = log.Message
		}
		mitre := log.MitreID
		if mitre == "" {
			mitre = "Security Alert"
		}

		dashboardURL := os.Getenv("SIEM_DASHBOARD_URL")
		if dashboardURL == "" {
			dashboardURL = "https://gowaz.vulnstack.xyz/analytics"
		}

		_ = SendGatherEvent(gatherURL, gatherSecret, "activity.add", map[string]string{
			"id":   fmt.Sprintf("alert-%d", time.Now().UnixNano()),
			"text": fmt.Sprintf("🚨 [%s] %s (IP: %s, Host: %s)", mitre, desc, log.SourceIP, log.Hostname),
			"url":  dashboardURL,
		})
	}()
}

