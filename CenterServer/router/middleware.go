package router

import (
	"crypto/subtle"
	"os"
	"strings"

	"github.com/gofiber/fiber/v3"
	"github.com/golang-jwt/jwt/v5"
)

// verifyToken memvalidasi JWT HS256, mengisi Locals(username, role),
// lalu meneruskan request ke handler berikutnya.
func verifyToken(c fiber.Ctx, raw string) error {
	tok, err := jwt.Parse(raw, func(t *jwt.Token) (any, error) {
		return SecretKey, nil
	},
		jwt.WithValidMethods([]string{"HS256"}), // cegah serangan alg=none
		jwt.WithExpirationRequired(),            // token tanpa exp ditolak
	)
	if err != nil || !tok.Valid {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "token tidak valid atau kedaluwarsa"})
	}

	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "claims tidak valid"})
	}

	// Simpan sebagai string agar RequireRole bisa melakukan type assertion.
	if u, ok := claims["username"].(string); ok {
		c.Locals("username", u)
	}
	if r, ok := claims["role"].(string); ok {
		c.Locals("role", r)
	}
	return c.Next()
}

// RequireAuth memvalidasi JWT di header Authorization dengan skema Bearer.
func RequireAuth() fiber.Handler {
	return func(c fiber.Ctx) error {
		raw := c.Get("Authorization")
		if raw == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "token tidak ada"})
		}

		parts := strings.SplitN(raw, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "format Authorization salah"})
		}

		return verifyToken(c, parts[1])
	}
}

// RequireStreamAuth khusus untuk endpoint SSE (/api/v1/stream), karena
// EventSource tidak bisa mengirim header Authorization. Token diambil dari
// query ?token=, dengan fallback header Bearer untuk klien non-browser.
func RequireStreamAuth() fiber.Handler {
	return func(c fiber.Ctx) error {
		token := c.Query("token")
		if token == "" {
			if raw := c.Get("Authorization"); raw != "" {
				if parts := strings.SplitN(raw, " ", 2); len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
					token = parts[1]
				}
			}
		}
		if token == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "token tidak ada"})
		}
		return verifyToken(c, token)
	}
}

// RequireRole membatasi berdasarkan role di dalam token
func RequireRole(roles ...string) fiber.Handler {
	return func(c fiber.Ctx) error {
		role, _ := c.Locals("role").(string)
		for _, r := range roles {
			if role == r {
				return c.Next()
			}
		}
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "role tidak diizinkan"})
	}
}

func RequireAgentKey() fiber.Handler {
	return func(c fiber.Ctx) error {
		want := os.Getenv("AGENT_API_KEY")
		if want == "" {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Internal Error from server"})
		}
		got := c.Get("X-Agent-Key")
		if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid agent key"})
		}
		return c.Next()
	}
}
