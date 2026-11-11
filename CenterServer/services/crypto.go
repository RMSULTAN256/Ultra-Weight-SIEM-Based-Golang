package services

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"time"
)

func GenerateHMAC(secretKey string, payload []byte, timestamp int64) string {
	mac := hmac.New(sha256.New, []byte(secretKey))
	mac.Write(payload)

	tsBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(tsBytes, uint64(timestamp))
	mac.Write(tsBytes)

	return hex.EncodeToString(mac.Sum(nil))
}

func VerifyHMAC(secretKey string, payload []byte, timestamp int64, signature string) bool {
	now := time.Now().Unix()
	if now-timestamp > 30 || timestamp-now > 30 {
		return false
	}

	expectedSig := GenerateHMAC(secretKey, payload, timestamp)
	return subtle.ConstantTimeCompare([]byte(expectedSig), []byte(signature)) == 1
}
