package services

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"Agent/models"
)

type metricSink struct {
	mu      sync.Mutex
	status  []models.DeviceStatus
	headers []http.Header
	paths   []string
	methods []string
}

func (s *metricSink) last() (models.DeviceStatus, http.Header, string, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.status) == 0 {
		return models.DeviceStatus{}, nil, "", ""
	}
	i := len(s.status) - 1
	return s.status[i], s.headers[i], s.paths[i], s.methods[i]
}

func (s *metricSink) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.status)
}

func newMetricServer(t *testing.T) (*httptest.Server, *metricSink) {
	t.Helper()

	sink := &metricSink{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			// TestConnection memakai GET tanpa body.
			sink.mu.Lock()
			sink.headers = append(sink.headers, r.Header.Clone())
			sink.paths = append(sink.paths, r.URL.Path)
			sink.methods = append(sink.methods, r.Method)
			sink.status = append(sink.status, models.DeviceStatus{})
			sink.mu.Unlock()
			w.WriteHeader(http.StatusOK)
			return
		}

		var in models.DeviceStatus
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			t.Errorf("body bukan DeviceStatus valid: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		sink.mu.Lock()
		sink.status = append(sink.status, in)
		sink.headers = append(sink.headers, r.Header.Clone())
		sink.paths = append(sink.paths, r.URL.Path)
		sink.methods = append(sink.methods, r.Method)
		sink.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	return srv, sink
}

func TestNewMetricCollector(t *testing.T) {
	mc := NewMetricCollector("agent-uji", "http://server:8080/heartbeat", 1024, "kunci")

	if mc.AgentName != "agent-uji" || mc.ServerUrl != "http://server:8080/heartbeat" ||
		mc.RamLimitMB != 1024 || mc.AgentKey != "kunci" {
		t.Errorf("field collector tidak terisi: %+v", mc)
	}
	if mc.Client == nil {
		t.Fatal("http.Client harus dibuat supaya tidak nil saat Send dipanggil")
	}
}

func TestMetricCollectorSendSukses(t *testing.T) {
	srv, sink := newMetricServer(t)
	mc := NewMetricCollector("agent-uji", srv.URL+"/api/v1/agent/heartbeat", 0, "kunci-uji")

	status := &models.DeviceStatus{
		AgentID:    "agent-id-1",
		Hostname:   "ubuntu-uji",
		Platform:   "ubuntu 24.04",
		CPUUsage:   7.5,
		RAMUsedMB:  256,
		RAMTotalMB: 1024,
	}

	if err := mc.Send(status); err != nil {
		t.Fatalf("Send seharusnya sukses: %v", err)
	}

	got, hdr, path, method := sink.last()
	if sink.count() != 1 {
		t.Fatalf("server menerima %d request, mau 1", sink.count())
	}
	if path != "/api/v1/agent/heartbeat" {
		t.Errorf("path: dapat %q", path)
	}
	if method != http.MethodPost {
		t.Errorf("method: dapat %s, mau POST", method)
	}
	if got.AgentID != "agent-id-1" || got.CPUUsage != 7.5 || got.RAMUsedMB != 256 {
		t.Errorf("metrik tidak terkirim utuh: %+v", got)
	}
	if v := hdr.Get("X-Agent-Key"); v != "kunci-uji" {
		t.Errorf("X-Agent-Key: dapat %q, mau kunci-uji", v)
	}
	if v := hdr.Get("Content-Type"); v != "application/json" {
		t.Errorf("Content-Type: dapat %q", v)
	}
	if mc.lastLatencyMs < 0 {
		t.Errorf("latency tidak boleh negatif, dapat %f", mc.lastLatencyMs)
	}
}

// TestMetricCollectorSendTanpaKey: agent tanpa AGENT_API_KEY tetap harus bisa
// mencoba kirim (server yang memutuskan 401), bukan gagal di sisi agent.
func TestMetricCollectorSendTanpaKey(t *testing.T) {
	srv, sink := newMetricServer(t)
	mc := NewMetricCollector("agent-uji", srv.URL+"/heartbeat", 0, "")

	if err := mc.Send(&models.DeviceStatus{Hostname: "uji"}); err != nil {
		t.Fatalf("Send tanpa key seharusnya tetap jalan: %v", err)
	}

	_, hdr, _, _ := sink.last()
	if v, ok := hdr["X-Agent-Key"]; ok && len(v) > 0 && v[0] != "" {
		t.Errorf("header X-Agent-Key tidak boleh dikirim saat key kosong, dapat %v", v)
	}
}

func TestMetricCollectorSendURLTidakValid(t *testing.T) {
	mc := NewMetricCollector("agent-uji", "://bukan-url", 0, "kunci")

	if err := mc.Send(&models.DeviceStatus{Hostname: "uji"}); err == nil {
		t.Fatal("URL tidak valid seharusnya mengembalikan error")
	}
}

func TestMetricCollectorSendServerMati(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close()

	mc := NewMetricCollector("agent-uji", url, 0, "kunci")

	if err := mc.Send(&models.DeviceStatus{Hostname: "uji"}); err == nil {
		t.Fatal("server mati seharusnya mengembalikan error koneksi")
	}
}

func TestMetricCollectorTestConnection(t *testing.T) {
	srv, sink := newMetricServer(t)
	mc := NewMetricCollector("agent-uji", srv.URL, 0, "kunci")

	rtt, err := mc.TestConnection()
	if err != nil {
		t.Fatalf("TestConnection seharusnya sukses: %v", err)
	}
	if rtt <= 0 {
		t.Errorf("RTT harus > 0, dapat %v", rtt)
	}

	_, _, path, method := sink.last()
	if path != "/api/v1/agents" {
		t.Errorf("TestConnection harus memanggil /api/v1/agents, dapat %q", path)
	}
	if method != http.MethodGet {
		t.Errorf("method: dapat %s, mau GET", method)
	}
}

func TestMetricCollectorTestConnectionGagal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close()

	mc := NewMetricCollector("agent-uji", url, 0, "kunci")
	mc.Client = &http.Client{Timeout: 500 * time.Millisecond}

	if _, err := mc.TestConnection(); err == nil {
		t.Fatal("server mati seharusnya mengembalikan error")
	}
}

// TestCollectMetrics: memastikan nilai environment benar-benar meng-override
// identitas & batas RAM, karena di produksi agent dijalankan per-container.
func TestCollectMetrics(t *testing.T) {
	t.Setenv("AGENT_NAME", "nama-dari-env")
	t.Setenv("AGENT_ID", "id-dari-env")
	t.Setenv("RAM_LIMIT_MB", "")

	mc := NewMetricCollector("agent-uji", "http://contoh", 2048, "kunci")

	status, err := mc.CollectMetrics()
	if err != nil {
		t.Fatalf("CollectMetrics gagal: %v", err)
	}
	if status == nil {
		t.Fatal("status tidak boleh nil saat error nil")
	}
	if status.Hostname != "nama-dari-env" {
		t.Errorf("Hostname harus dari AGENT_NAME, dapat %q", status.Hostname)
	}
	if status.AgentID != "id-dari-env" {
		t.Errorf("AgentID harus dari AGENT_ID, dapat %q", status.AgentID)
	}
	if status.RAMTotalMB != 2048 {
		t.Errorf("RAMTotalMB harus ikut RamLimitMB, dapat %d", status.RAMTotalMB)
	}
	if status.Platform == "" {
		t.Error("Platform tidak boleh kosong")
	}
	if status.RAMUsedPct < 0 || status.RAMUsedPct > 100 {
		t.Errorf("RAMUsedPct di luar 0..100: %f", status.RAMUsedPct)
	}
	if status.DiskUsedPct < 0 || status.DiskUsedPct > 100 {
		t.Errorf("DiskUsedPct di luar 0..100: %f", status.DiskUsedPct)
	}
}

func TestCollectMetricsOverrideRamLimitDariEnv(t *testing.T) {
	t.Setenv("RAM_LIMIT_MB", "512")

	mc := NewMetricCollector("agent-uji", "http://contoh", 2048, "kunci")

	status, err := mc.CollectMetrics()
	if err != nil {
		t.Fatalf("CollectMetrics gagal: %v", err)
	}
	if status.RAMTotalMB != 512 {
		t.Errorf("RAM_LIMIT_MB harus menang atas RamLimitMB, dapat %d", status.RAMTotalMB)
	}
	if status.RAMUsedMB > 512 {
		t.Errorf("RAMUsedMB (%d) tidak boleh melebihi batas RAM (%d)", status.RAMUsedMB, status.RAMTotalMB)
	}
}
