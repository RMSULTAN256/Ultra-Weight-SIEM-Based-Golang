package routes

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"Agent/models"
)

type heartbeatSink struct {
	mu       sync.Mutex
	statuses []models.DeviceStatus
	headers  http.Header
	methods  []string
}

func (s *heartbeatSink) snapshot() []models.DeviceStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]models.DeviceStatus, len(s.statuses))
	copy(out, s.statuses)
	return out
}

func newHeartbeatServer(t *testing.T) (*httptest.Server, *heartbeatSink) {
	t.Helper()

	sink := &heartbeatSink{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in models.DeviceStatus
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			t.Errorf("body heartbeat bukan DeviceStatus valid: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		sink.mu.Lock()
		sink.statuses = append(sink.statuses, in)
		sink.headers = r.Header.Clone()
		sink.methods = append(sink.methods, r.Method)
		sink.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	return srv, sink
}

func TestSendHeartbeatSukses(t *testing.T) {
	srv, sink := newHeartbeatServer(t)
	client := &http.Client{Timeout: 2 * time.Second}

	status := &models.DeviceStatus{
		AgentID:    "agent-uji",
		Hostname:   "ubuntu-uji",
		Platform:   "ubuntu 24.04",
		CPUUsage:   12.5,
		RAMUsedMB:  512,
		RAMTotalMB: 2048,
		LatencyMs:  3.25,
	}

	if err := SendHeartbeat(client, srv.URL, status); err != nil {
		t.Fatalf("SendHeartbeat seharusnya sukses: %v", err)
	}

	got := sink.snapshot()
	if len(got) != 1 {
		t.Fatalf("server menerima %d heartbeat, mau 1", len(got))
	}
	if got[0].AgentID != "agent-uji" || got[0].Hostname != "ubuntu-uji" {
		t.Errorf("identitas agent tidak terkirim utuh: %+v", got[0])
	}
	if got[0].CPUUsage != 12.5 || got[0].RAMUsedMB != 512 {
		t.Errorf("metrik tidak terkirim utuh: %+v", got[0])
	}
	if sink.methods[0] != http.MethodPost {
		t.Errorf("method: dapat %s, mau POST", sink.methods[0])
	}
	if ct := sink.headers.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type: dapat %q, mau application/json", ct)
	}
}

// TestSendHeartbeatStatusNon200 mengunci kontrak: server yang membalas non-200
// harus muncul sebagai error, bukan sukses senyap.
func TestSendHeartbeatStatusNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)

	client := &http.Client{Timeout: 2 * time.Second}
	err := SendHeartbeat(client, srv.URL, &models.DeviceStatus{Hostname: "uji"})
	if err == nil {
		t.Fatal("status 401 seharusnya dikembalikan sebagai error")
	}
}

func TestSendHeartbeatURLTidakValid(t *testing.T) {
	client := &http.Client{Timeout: time.Second}

	if err := SendHeartbeat(client, "://bukan-url", &models.DeviceStatus{Hostname: "uji"}); err == nil {
		t.Fatal("URL tidak valid seharusnya mengembalikan error")
	}
}

func TestSendHeartbeatServerMati(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close() // server dimatikan sebelum dipakai

	client := &http.Client{Timeout: time.Second}
	if err := SendHeartbeat(client, url, &models.DeviceStatus{Hostname: "uji"}); err == nil {
		t.Fatal("server mati seharusnya mengembalikan error koneksi")
	}
}
