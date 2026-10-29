package routes

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"server1/handlers"

	"github.com/gofiber/fiber/v2"
)

func Setup(app *fiber.App, h *handlers.Handler) {
	api := app.Group("/api")

	api.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "ok", "server": "server 1 port 3000"})
	})

	// Endpoint ini yang dipanggil oleh Server 2 via HTTP Client
	api.Get("/profile", func(c *fiber.Ctx) error {
		authHeader := c.Get("Authorization")
		if authHeader == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Authorization header is required",
			})
		}

		// Kirim data user mock (ID harus float/int agar terbaca oleh Server 2)
		return c.JSON(fiber.Map{
			"id":    101,
			"name":  "John Doe",
			"email": "Cihuy@gmail.com",
		})
	})

	api.Post("/send-event", func(c *fiber.Ctx) error {
		var payload map[string]interface{}
		if err := c.BodyParser(&payload); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid JSON"})
		}
		return c.JSON(fiber.Map{"status": "event received by server 1"})
	})

	api.Get("/trigger-send-to-server2", func(c *fiber.Ctx) error {
		// 1. Data yang mau dikirim dari Server 1
		payload := map[string]string{
			"event":   "USER_SUSPICIOUS_LOGIN",
			"ip":      "182.2.7.212",
			"message": "Halo Server 2, tolong blokir IP ini!",
		}
		jsonBytes, _ := json.Marshal(payload)
		// 2. Server 1 menembak HTTP POST ke Server 2 (Port 3001)
		server2URL := "http://localhost:3001"
		if envURL := os.Getenv("SERVER2_URL"); envURL != "" {
			server2URL = envURL
		}
		targetURL := server2URL + "/receive-from-server1"
		resp, err := http.Post(targetURL, "application/json", bytes.NewBuffer(jsonBytes))
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "Gagal kirim ke Server 2: " + err.Error()})
		}
		defer resp.Body.Close()
		// 3. Baca balasan dari Server 2
		body, _ := io.ReadAll(resp.Body)
		return c.SendString("Respon dari Server 2: " + string(body))
	})
}
