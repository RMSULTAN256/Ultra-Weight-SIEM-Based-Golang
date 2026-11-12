package router

import (
	"net/http/httptest"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/golang-jwt/jwt/v5"
)

const secretUji = "secret-uji-jwt-minimal-32-karakter"

// pakaiSecretUji mengganti SecretKey global selama test lalu mengembalikannya.
func pakaiSecretUji(t *testing.T) []byte {
	t.Helper()

	asli := SecretKey
	SecretKey = []byte(secretUji)
	t.Cleanup(func() { SecretKey = asli })

	return SecretKey
}

func tokenHS256(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()

	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(SecretKey)
	if err != nil {
		t.Fatalf("gagal membuat token uji: %v", err)
	}
	return signed
}

func claimsValid() jwt.MapClaims {
	return jwt.MapClaims{
		"username": "analis1",
		"role":     "admin",
		"exp":      time.Now().Add(time.Hour).Unix(),
	}
}

func appMiddleware() *fiber.App {
	app := fiber.New()

	app.Get("/protected", RequireAuth(), func(c fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"username": c.Locals("username"),
			"role":     c.Locals("role"),
		})
	})

	app.Get("/admin", RequireAuth(), RequireRole("admin"), func(c fiber.Ctx) error {
		return c.SendString("admin-ok")
	})

	app.Get("/stream", RequireStreamAuth(), func(c fiber.Ctx) error {
		return c.SendString("stream-ok")
	})

	app.Get("/agent", RequireAgentKey(), func(c fiber.Ctx) error {
		return c.SendString("agent-ok")
	})

	return app
}

func get(t *testing.T, app *fiber.App, path string, header map[string]string) (int, string) {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, path, nil)
	for k, v := range header {
		req.Header.Set(k, v)
	}

	resp, err := app.Test(req, fiber.TestConfig{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("app.Test gagal untuk %s: %v", path, err)
	}
	defer resp.Body.Close()

	var sb strings.Builder
	buf := make([]byte, 1024)
	for {
		n, err := resp.Body.Read(buf)
		sb.Write(buf[:n])
		if err != nil {
			break
		}
	}
	return resp.StatusCode, sb.String()
}

func TestRequireAuthMenolakTanpaToken(t *testing.T) {
	pakaiSecretUji(t)
	app := appMiddleware()

	code, body := get(t, app, "/protected", nil)
	if code != http.StatusUnauthorized {
		t.Fatalf("status: dapat %d, mau 401 (body: %s)", code, body)
	}
	if !strings.Contains(body, "token tidak ada") {
		t.Errorf("pesan error tidak sesuai: %s", body)
	}
}

func TestRequireAuthMenolakFormatSalah(t *testing.T) {
	pakaiSecretUji(t)
	app := appMiddleware()

	cases := map[string]string{
		"tanpa skema bearer": tokenHS256(t, claimsValid()),
		"skema lain":         "Basic " + tokenHS256(t, claimsValid()),
		"bearer tanpa token": "Bearer",
	}

	for name, header := range cases {
		t.Run(name, func(t *testing.T) {
			code, body := get(t, app, "/protected", map[string]string{"Authorization": header})
			if code != http.StatusUnauthorized {
				t.Errorf("status: dapat %d, mau 401 (body: %s)", code, body)
			}
		})
	}
}

func TestRequireAuthMenerimaTokenValid(t *testing.T) {
	pakaiSecretUji(t)
	app := appMiddleware()

	code, body := get(t, app, "/protected", map[string]string{
		"Authorization": "Bearer " + tokenHS256(t, claimsValid()),
	})
	if code != http.StatusOK {
		t.Fatalf("status: dapat %d, mau 200 (body: %s)", code, body)
	}

	var out map[string]any
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("body bukan JSON: %v (%s)", err, body)
	}
	if out["username"] != "analis1" {
		t.Errorf("username di Locals: dapat %v, mau analis1", out["username"])
	}
	if out["role"] != "admin" {
		t.Errorf("role di Locals: dapat %v, mau admin", out["role"])
	}
}

// TestRequireAuthMenolakTokenCacat menutup jalur bypass yang paling sering:
// token kedaluwarsa, token tanpa exp, alg=none, dan tanda tangan secret lain.
func TestRequireAuthMenolakTokenCacat(t *testing.T) {
	pakaiSecretUji(t)
	app := appMiddleware()

	algNone := jwt.NewWithClaims(jwt.SigningMethodNone, claimsValid())
	algNoneToken, err := algNone.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("gagal membuat token alg=none: %v", err)
	}

	secretLain, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claimsValid()).
		SignedString([]byte("secret-penyerang-yang-juga-32-char!!"))
	if err != nil {
		t.Fatalf("gagal membuat token secret lain: %v", err)
	}

	tanpaExp := jwt.MapClaims{"username": "analis1", "role": "admin"}
	expired := jwt.MapClaims{
		"username": "analis1",
		"role":     "admin",
		"exp":      time.Now().Add(-time.Hour).Unix(),
	}

	cases := map[string]string{
		"kedaluwarsa":      tokenHS256(t, expired),
		"tanpa exp":        tokenHS256(t, tanpaExp),
		"alg none":         algNoneToken,
		"secret lain":      secretLain,
		"string sampah":    "ini.bukan.jwt",
		"token kosong":     "",
		"hanya dua bagian": "a.b",
	}

	for name, token := range cases {
		t.Run(name, func(t *testing.T) {
			code, body := get(t, app, "/protected", map[string]string{"Authorization": "Bearer " + token})
			if code != http.StatusUnauthorized {
				t.Errorf("%s: status dapat %d, mau 401 (body: %s)", name, code, body)
			}
		})
	}
}

func TestRequireRole(t *testing.T) {
	pakaiSecretUji(t)
	app := appMiddleware()

	t.Run("role cocok", func(t *testing.T) {
		code, body := get(t, app, "/admin", map[string]string{
			"Authorization": "Bearer " + tokenHS256(t, claimsValid()),
		})
		if code != http.StatusOK {
			t.Fatalf("status: dapat %d, mau 200 (body: %s)", code, body)
		}
	})

	t.Run("role tidak cocok", func(t *testing.T) {
		token := tokenHS256(t, jwt.MapClaims{
			"username": "viewer1",
			"role":     "viewer",
			"exp":      time.Now().Add(time.Hour).Unix(),
		})
		code, body := get(t, app, "/admin", map[string]string{"Authorization": "Bearer " + token})
		if code != http.StatusForbidden {
			t.Fatalf("status: dapat %d, mau 403 (body: %s)", code, body)
		}
	})

	t.Run("tanpa role", func(t *testing.T) {
		token := tokenHS256(t, jwt.MapClaims{
			"username": "tanpa-role",
			"exp":      time.Now().Add(time.Hour).Unix(),
		})
		code, _ := get(t, app, "/admin", map[string]string{"Authorization": "Bearer " + token})
		if code != http.StatusForbidden {
			t.Fatalf("status: dapat %d, mau 403", code)
		}
	})
}

// TestRequireStreamAuth: EventSource tidak bisa set header, jadi token lewat
// query wajib diterima, dan header Bearer tetap jalan untuk klien lain.
func TestRequireStreamAuth(t *testing.T) {
	pakaiSecretUji(t)
	app := appMiddleware()
	token := tokenHS256(t, claimsValid())

	t.Run("lewat query token", func(t *testing.T) {
		code, body := get(t, app, "/stream?token="+token, nil)
		if code != http.StatusOK {
			t.Fatalf("status: dapat %d, mau 200 (body: %s)", code, body)
		}
	})

	t.Run("lewat header bearer", func(t *testing.T) {
		code, body := get(t, app, "/stream", map[string]string{"Authorization": "Bearer " + token})
		if code != http.StatusOK {
			t.Fatalf("status: dapat %d, mau 200 (body: %s)", code, body)
		}
	})

	t.Run("tanpa token", func(t *testing.T) {
		code, body := get(t, app, "/stream", nil)
		if code != http.StatusUnauthorized {
			t.Fatalf("status: dapat %d, mau 401 (body: %s)", code, body)
		}
	})

	t.Run("token query tidak valid", func(t *testing.T) {
		code, body := get(t, app, "/stream?token=sampah", nil)
		if code != http.StatusUnauthorized {
			t.Fatalf("status: dapat %d, mau 401 (body: %s)", code, body)
		}
	})
}

// TestRequireAgentKey: server tanpa AGENT_API_KEY harus menolak semua agent
// (fail-closed) dengan 500, bukan meloloskan request tanpa verifikasi.
func TestRequireAgentKey(t *testing.T) {
	app := appMiddleware()

	t.Run("env kosong fail-closed", func(t *testing.T) {
		t.Setenv("AGENT_API_KEY", "")

		code, body := get(t, app, "/agent", map[string]string{"X-Agent-Key": "apa-saja"})
		if code != http.StatusInternalServerError {
			t.Fatalf("status: dapat %d, mau 500 (body: %s)", code, body)
		}
	})

	t.Run("key salah", func(t *testing.T) {
		t.Setenv("AGENT_API_KEY", "kunci-agent-uji")

		code, body := get(t, app, "/agent", map[string]string{"X-Agent-Key": "kunci-palsu"})
		if code != http.StatusUnauthorized {
			t.Fatalf("status: dapat %d, mau 401 (body: %s)", code, body)
		}
	})

	t.Run("tanpa header", func(t *testing.T) {
		t.Setenv("AGENT_API_KEY", "kunci-agent-uji")

		code, body := get(t, app, "/agent", nil)
		if code != http.StatusUnauthorized {
			t.Fatalf("status: dapat %d, mau 401 (body: %s)", code, body)
		}
	})

	t.Run("key benar", func(t *testing.T) {
		t.Setenv("AGENT_API_KEY", "kunci-agent-uji")

		code, body := get(t, app, "/agent", map[string]string{"X-Agent-Key": "kunci-agent-uji"})
		if code != http.StatusOK {
			t.Fatalf("status: dapat %d, mau 200 (body: %s)", code, body)
		}
	})
}
