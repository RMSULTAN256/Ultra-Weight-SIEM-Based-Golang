package router

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
)

func appRemoteExec() *fiber.App {
	app := fiber.New()

	// siemService sengaja nil: seluruh kasus di bawah sudah diputuskan sebelum
	// SSH/audit, jadi test tidak butuh database maupun koneksi jaringan.
	h := NewHandleSiem(nil)
	app.Post("/api/v1/agents/:id/exec", h.HandleRemoteExec)

	return app
}

func postJSON(t *testing.T, app *fiber.App, path, body string) (int, map[string]any) {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req, fiber.TestConfig{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("app.Test gagal untuk %s: %v", path, err)
	}
	defer resp.Body.Close()

	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		// Body error bisa kosong pada status tertentu; itu bukan kegagalan test.
		out = map[string]any{}
	}

	return resp.StatusCode, out
}

// TestRemoteExecValidasiPayload: request cacat harus ditolak 400 tanpa pernah
// menyentuh SSH.
func TestRemoteExecValidasiPayload(t *testing.T) {
	app := appRemoteExec()

	cases := []struct {
		name string
		body string
	}{
		{"body kosong", ""},
		{"body bukan json", "bukan json"},
		{"json tanpa command_key", `{}`},
		{"command_key kosong", `{"command_key":""}`},
		{"command_key spasi", `{"command_key":"   "}`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, out := postJSON(t, app, "/api/v1/agents/ubuntu/exec", tc.body)
			if code != http.StatusBadRequest {
				t.Fatalf("status: dapat %d, mau 400 (body: %v)", code, out)
			}
			if _, ok := out["error"]; !ok {
				t.Errorf("respons 400 harus memuat field error: %v", out)
			}
		})
	}
}

func TestRemoteExecNodeTidakDikenal(t *testing.T) {
	app := appRemoteExec()

	code, out := postJSON(t, app, "/api/v1/agents/node-yang-tidak-ada/exec", `{"command_key":"ports"}`)
	if code != http.StatusNotFound {
		t.Fatalf("status: dapat %d, mau 404 (body: %v)", code, out)
	}
	if _, ok := out["error"]; !ok {
		t.Errorf("respons 404 harus memuat field error: %v", out)
	}
}

// TestRemoteExecPerintahAsing: whitelist harus menolak perintah arbitrer, dan
// penolakan terjadi sebelum eksekusi apa pun.
func TestRemoteExecPerintahAsing(t *testing.T) {
	app := appRemoteExec()

	for _, key := range []string{"rm -rf /", "cat /etc/shadow", "sh", "uptime; id"} {
		t.Run(key, func(t *testing.T) {
			code, out := postJSON(t, app, "/api/v1/agents/ubuntu/exec",
				`{"command_key":`+strconvQuote(key)+`}`)
			if code != http.StatusForbidden {
				t.Fatalf("status: dapat %d, mau 403 (body: %v)", code, out)
			}
			if _, ok := out["error"]; !ok {
				t.Errorf("respons 403 harus memuat field error: %v", out)
			}
		})
	}
}

func TestRemoteExecMethodSalah(t *testing.T) {
	app := appRemoteExec()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/agents/ubuntu/exec", nil)
	resp, err := app.Test(req, fiber.TestConfig{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("app.Test gagal: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed && resp.StatusCode != http.StatusNotFound {
		t.Errorf("status: dapat %d, mau 405/404 untuk GET", resp.StatusCode)
	}
}

// strconvQuote meng-escape string jadi literal JSON tanpa menambah dependency.
func strconvQuote(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		return `""`
	}
	return string(b)
}
