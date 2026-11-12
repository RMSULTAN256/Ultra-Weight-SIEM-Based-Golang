package services

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"Agent/models"
)

// logSink menampung SecurityLog yang diterima CenterServer tiruan, supaya test
// bisa memeriksa apa yang benar-benar dikirim lewat jalur HTTP fallback.
type logSink struct {
	mu      sync.Mutex
	logs    []models.SecurityLog
	paths   []string
	headers []http.Header
}

func (s *logSink) snapshot() []models.SecurityLog {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]models.SecurityLog, len(s.logs))
	copy(out, s.logs)
	return out
}

func (s *logSink) waitCount(expected int) []models.SecurityLog {
	for i := 0; i < 150; i++ {
		s.mu.Lock()
		n := len(s.logs)
		s.mu.Unlock()
		if n >= expected {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	return s.snapshot()
}

func (s *logSink) lastHeader() http.Header {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.headers) == 0 {
		return nil
	}
	return s.headers[len(s.headers)-1]
}

func newLogSink(t *testing.T) (*httptest.Server, *logSink) {
	t.Helper()

	sink := &logSink{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in models.SecurityLog
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			t.Errorf("payload log bukan SecurityLog valid: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		sink.mu.Lock()
		sink.logs = append(sink.logs, in)
		sink.paths = append(sink.paths, r.URL.Path)
		sink.headers = append(sink.headers, r.Header.Clone())
		sink.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	return srv, sink
}

func appendTo(t *testing.T, path, content string) {
	t.Helper()

	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatalf("gagal membuka file untuk append: %v", err)
	}
	defer f.Close()
	if _, err := f.WriteString(content); err != nil {
		t.Fatalf("gagal append ke file: %v", err)
	}
}

// TestHandleLineKlasifikasiRule memastikan tabel `rules` di LogScanner benar
// memetakan keyword ke event_type + severity. Severity inilah yang menentukan
// bobot deteksi di CenterServer, jadi tidak boleh bergeser diam-diam.
func TestHandleLineKlasifikasiRule(t *testing.T) {
	srv, sink := newLogSink(t)
	lc := NewLogCollector(srv.URL, "agent-uji", "kunci-uji")
	target := models.TargetConfig{AppName: "nginx-access"}

	cases := []struct {
		name      string
		line      string
		wantEvent string
		wantStat  string
		wantSev   int
		wantIP    string
	}{
		{
			name:      "sql injection",
			line:      `10.0.0.9 - - "GET /?id=1 UNION SELECT password FROM users" 200`,
			wantEvent: "web_attack", wantStat: "union select", wantSev: 10, wantIP: "10.0.0.9",
		},
		{
			name:      "eval injection",
			line:      `203.0.113.5 - - "GET /?c=eval(base64_decode) " 200`,
			wantEvent: "web_attack", wantStat: "eval(", wantSev: 10, wantIP: "203.0.113.5",
		},
		{
			name:      "ssh failed password",
			line:      `Failed password for root from 203.0.113.7 port 22 ssh2`,
			wantEvent: "auth_failure", wantStat: "failed password", wantSev: 6, wantIP: "203.0.113.7",
		},
		{
			name:      "ssh invalid user",
			line:      `Invalid user admin from 198.51.100.4 port 40022`,
			wantEvent: "auth_failure", wantStat: "invalid user", wantSev: 6, wantIP: "198.51.100.4",
		},
		{
			name:      "log biasa tanpa IP",
			line:      `systemd[1]: Started Daily apt upgrade`,
			wantEvent: "event_log", wantStat: "raw_log", wantSev: 1, wantIP: "127.0.0.1",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := len(sink.snapshot())

			if err := lc.handleLine(tc.line, target); err != nil {
				t.Fatalf("handleLine gagal: %v", err)
			}

			logs := sink.waitCount(before + 1)
			if len(logs) != before+1 {
				t.Fatalf("harus mengirim tepat 1 log, terkirim %d", len(logs)-before)
			}
			got := logs[len(logs)-1]

			if got.EventType != tc.wantEvent {
				t.Errorf("EventType: dapat %q, mau %q", got.EventType, tc.wantEvent)
			}
			if got.Status != tc.wantStat {
				t.Errorf("Status: dapat %q, mau %q", got.Status, tc.wantStat)
			}
			if got.Severity != tc.wantSev {
				t.Errorf("Severity: dapat %d, mau %d", got.Severity, tc.wantSev)
			}
			if got.SourceIP != tc.wantIP {
				t.Errorf("SourceIP: dapat %q, mau %q", got.SourceIP, tc.wantIP)
			}
			if got.Hostname != "agent-uji" {
				t.Errorf("Hostname harus nama agent, dapat %q", got.Hostname)
			}
			if got.Service != "nginx-access" {
				t.Errorf("Service harus AppName target, dapat %q", got.Service)
			}
			if got.Message != tc.line {
				t.Errorf("Message harus baris asli, dapat %q", got.Message)
			}
		})
	}
}

// TestHandleLineKeywordTarget memastikan keywords per-target hanya dipakai
// sebagai pelengkap ketika rules global tidak cocok.
func TestHandleLineKeywordTarget(t *testing.T) {
	srv, sink := newLogSink(t)
	lc := NewLogCollector(srv.URL, "agent-uji", "")
	target := models.TargetConfig{AppName: "backup", Keywords: []string{"Backup-Completed"}}

	if err := lc.handleLine("cronjob: daily backup-completed successfully", target); err != nil {
		t.Fatalf("handleLine gagal: %v", err)
	}

	logs := sink.waitCount(1)
	if len(logs) != 1 {
		t.Fatalf("harus mengirim 1 log, dapat %d", len(logs))
	}
	if logs[0].Status != "Backup-Completed" {
		t.Errorf("Status dari keywords target: dapat %q, mau %q", logs[0].Status, "Backup-Completed")
	}
	if logs[0].EventType != "event_log" || logs[0].Severity != 1 {
		t.Errorf("keyword target tidak boleh mengubah event/severity: %+v", logs[0])
	}
}

// TestHandleLineKirimHeader memastikan header wajib CenterServer ikut terkirim.
func TestHandleLineKirimHeader(t *testing.T) {
	srv, sink := newLogSink(t)
	lc := NewLogCollector(srv.URL+"/base", "agent-uji", "kunci-rahasia")

	if err := lc.handleLine("baris uji", models.TargetConfig{AppName: "app"}); err != nil {
		t.Fatalf("handleLine gagal: %v", err)
	}

	sink.waitCount(1)
	hdr := sink.lastHeader()
	if hdr == nil {
		t.Fatal("tidak ada request yang diterima server")
	}
	if got := hdr.Get("X-Agent-Key"); got != "kunci-rahasia" {
		t.Errorf("X-Agent-Key: dapat %q, mau %q", got, "kunci-rahasia")
	}
	if got := hdr.Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type: dapat %q, mau application/json", got)
	}
}

// TestProcessFileOffsetIdempotent mengunci sifat paling penting dari tailing:
// satu baris hanya boleh terkirim sekali, dan putaran kosong tidak mengirim apa pun.
func TestProcessFileOffsetIdempotent(t *testing.T) {
	srv, sink := newLogSink(t)
	lc := NewLogCollector(srv.URL, "agent-uji", "")
	target := models.TargetConfig{AppName: "syslog"}
	path := filepath.Join(t.TempDir(), "syslog.log")

	if err := os.WriteFile(path, []byte("line-1\n"), 0o644); err != nil {
		t.Fatalf("gagal menulis fixture: %v", err)
	}

	// Putaran pertama hanya menyimpan offset (baris lama tidak dikirim ulang).
	lc.processFile(path, target)
	if got := len(sink.snapshot()); got != 0 {
		t.Fatalf("putaran pertama tidak boleh mengirim log, terkirim %d", got)
	}
	st, ok := lc.state[path]
	if !ok {
		t.Fatal("state file harus tercatat setelah putaran pertama")
	}
	if st.Offset != int64(len("line-1\n")) {
		t.Errorf("offset awal: dapat %d, mau %d", st.Offset, len("line-1\n"))
	}
	if runtime.GOOS == "linux" && st.Inode == 0 {
		t.Error("inode harus terbaca di Linux (dipakai untuk deteksi rotasi)")
	}

	// Tidak ada data baru -> tidak ada yang dikirim.
	lc.processFile(path, target)
	if got := len(sink.snapshot()); got != 0 {
		t.Fatalf("tidak ada baris baru, tapi terkirim %d log", got)
	}

	appendTo(t, path, "line-2\n")

	lc.processFile(path, target)
	lc.processFile(path, target) // putaran kedua tidak boleh mengulang line-2
	logs := sink.waitCount(1)
	if len(logs) != 1 {
		t.Fatalf("line-2 harus terkirim tepat sekali, terkirim %d", len(logs))
	}
	if logs[0].Message != "line-2" {
		t.Errorf("Message: dapat %q, mau %q", logs[0].Message, "line-2")
	}
	if st := lc.state[path]; st.Offset != int64(len("line-1\nline-2\n")) {
		t.Errorf("offset akhir: dapat %d, mau %d", st.Offset, len("line-1\nline-2\n"))
	}
}

// TestProcessFileBarisTerpotong menutup bug klasik tailing: penulis log yang
// belum menutup baris dengan "\n" tidak boleh membuat baris hilang atau dobel.
func TestProcessFileBarisTerpotong(t *testing.T) {
	srv, sink := newLogSink(t)
	lc := NewLogCollector(srv.URL, "agent-uji", "")
	target := models.TargetConfig{AppName: "app"}
	path := filepath.Join(t.TempDir(), "app.log")

	if err := os.WriteFile(path, []byte("lama\n"), 0o644); err != nil {
		t.Fatalf("gagal menulis fixture: %v", err)
	}
	lc.processFile(path, target) // seed

	// "baru2" belum punya newline -> hanya "baru1" yang boleh dikirim.
	appendTo(t, path, "baru1\nbaru2")
	lc.processFile(path, target)

	logs := sink.waitCount(1)
	if len(logs) != 1 {
		t.Fatalf("hanya baris lengkap yang boleh dikirim, terkirim %d", len(logs))
	}
	if logs[0].Message != "baru1" {
		t.Errorf("Message: dapat %q, mau %q", logs[0].Message, "baru1")
	}
	if st := lc.state[path]; st.Offset != int64(len("lama\nbaru1\n")) {
		t.Errorf("offset harus berhenti sebelum baris terpotong: dapat %d, mau %d",
			st.Offset, len("lama\nbaru1\n"))
	}

	// Newline terakhir datang -> "baru2" baru dikirim sekarang, sekali saja.
	appendTo(t, path, "\n")
	lc.processFile(path, target)

	logs = sink.waitCount(2)
	if len(logs) != 2 {
		t.Fatalf("baru2 harus terkirim setelah newline lengkap, total %d", len(logs))
	}
	if logs[1].Message != "baru2" {
		t.Errorf("Message terakhir: dapat %q, mau %q", logs[1].Message, "baru2")
	}
}

// TestProcessFileDeteksiTruncate: file yang mengecil (logrotate copytruncate)
// harus dibaca ulang dari awal, bukan dilewati karena offset sudah melewati EOF.
func TestProcessFileDeteksiTruncate(t *testing.T) {
	srv, sink := newLogSink(t)
	lc := NewLogCollector(srv.URL, "agent-uji", "")
	target := models.TargetConfig{AppName: "app"}
	path := filepath.Join(t.TempDir(), "app.log")

	if err := os.WriteFile(path, []byte("satu\ndua\n"), 0o644); err != nil {
		t.Fatalf("gagal menulis fixture: %v", err)
	}
	lc.processFile(path, target) // seed, offset = 10

	appendTo(t, path, "tiga\n")
	lc.processFile(path, target)

	// Truncate: ukuran file jadi lebih kecil dari offset tersimpan.
	if err := os.WriteFile(path, []byte("nol\n"), 0o644); err != nil {
		t.Fatalf("gagal truncate fixture: %v", err)
	}
	lc.processFile(path, target)

	logs := sink.waitCount(2)
	if len(logs) != 2 {
		t.Fatalf("setelah truncate baris baru harus terkirim, total %d", len(logs))
	}
	if logs[1].Message != "nol" {
		t.Errorf("Message setelah truncate: dapat %q, mau %q", logs[1].Message, "nol")
	}
	if st := lc.state[path]; st.Offset != int64(len("nol\n")) {
		t.Errorf("offset setelah truncate: dapat %d, mau %d", st.Offset, len("nol\n"))
	}
}

// TestProcessFileInodeBerubah: kalau inode berubah (file diganti logrotate),
// isi file harus dibaca ulang dari awal. Inode dimanipulasi langsung karena OS
// boleh memakai ulang nomor inode yang baru dihapus, sehingga skenario
// "hapus lalu buat lagi" tidak deterministik di filesystem seperti tmpfs.
func TestProcessFileInodeBerubah(t *testing.T) {
	srv, sink := newLogSink(t)
	lc := NewLogCollector(srv.URL, "agent-uji", "")
	target := models.TargetConfig{AppName: "app"}
	path := filepath.Join(t.TempDir(), "app.log")

	if err := os.WriteFile(path, []byte("lama\n"), 0o644); err != nil {
		t.Fatalf("gagal menulis fixture: %v", err)
	}
	lc.processFile(path, target) // seed, offset = 5

	st := lc.state[path]
	st.Inode++ // inode "berbeda" -> offset lama tidak boleh dipercaya
	lc.state[path] = st

	lc.processFile(path, target)

	logs := sink.waitCount(1)
	if len(logs) != 1 {
		t.Fatalf("inode berubah harus membaca ulang dari awal, terkirim %d log", len(logs))
	}
	if logs[0].Message != "lama" {
		t.Errorf("Message: dapat %q, mau %q", logs[0].Message, "lama")
	}
	if st := lc.state[path]; st.Inode == 0 || st.Offset != int64(len("lama\n")) {
		t.Errorf("state harus diperbaiki ke inode nyata dan offset EOF, dapat %+v", st)
	}
}

func TestScanTargetGlob(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"a.log", "b.log"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("isi\n"), 0o644); err != nil {
			t.Fatalf("gagal menulis fixture: %v", err)
		}
	}

	lc := NewLogCollector("http://127.0.0.1:0", "agent-uji", "")
	lc.ScanTarget(models.TargetConfig{AppName: "app", FilePath: filepath.Join(dir, "*.log")})

	if len(lc.state) != 2 {
		t.Errorf("glob harus mencatat 2 file, tercatat %d", len(lc.state))
	}

	// Pola tanpa hasil dan pola rusak tidak boleh membuat panic.
	lc.ScanTarget(models.TargetConfig{AppName: "app", FilePath: filepath.Join(dir, "tidak-ada-*.log")})
	lc.ScanTarget(models.TargetConfig{AppName: "app", FilePath: "["})

	if len(lc.state) != 2 {
		t.Errorf("state tidak boleh bertambah untuk pola kosong, sekarang %d", len(lc.state))
	}
}

func TestProcessFileFileHilang(t *testing.T) {
	lc := NewLogCollector("http://127.0.0.1:0", "agent-uji", "")
	path := filepath.Join(t.TempDir(), "hilang.log")

	lc.processFile(path, models.TargetConfig{AppName: "app"})

	if _, ok := lc.state[path]; ok {
		t.Error("file yang gagal dibuka tidak boleh dicatat di state")
	}
}

func TestNewLogCollectorDefault(t *testing.T) {
	lc := NewLogCollector("http://contoh:8080", "agent-uji", "kunci")

	if lc.ServerUrl != "http://contoh:8080" || lc.AgentName != "agent-uji" || lc.AgentKey != "kunci" {
		t.Errorf("field collector tidak terisi: %+v", lc)
	}
	if lc.Client == nil {
		t.Fatal("http.Client harus dibuat supaya tidak nil saat dipakai")
	}
	if lc.state == nil {
		t.Fatal("map state harus diinisialisasi di konstruktor")
	}
	if lc.GRPCClient != nil {
		t.Error("GRPCClient harus nil sampai SetGRPCClient dipanggil")
	}
}

func TestSetGRPCClient(t *testing.T) {
	lc := NewLogCollector("http://x", "agent-uji", "")
	client := &GRPCClient{agentName: "agent-uji"}

	lc.SetGRPCClient(client)
	if lc.GRPCClient != client {
		t.Error("SetGRPCClient tidak menyimpan client")
	}

	lc.SetGRPCClient(nil)
	if lc.GRPCClient != nil {
		t.Error("SetGRPCClient(nil) harus mengosongkan client")
	}
}
