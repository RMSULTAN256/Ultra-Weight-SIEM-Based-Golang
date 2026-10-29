package main

import (
	"embed"
	"fmt"
	"io/fs"
	"log"
	"os"
	"server3/databases"
	"server3/router"
	"server3/services"
	"strings"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/static"
)

//go:embed frontend/*
var frontendFS embed.FS

func main() {
	app := fiber.New()
	// 1. Inisialisasi Database SQLite & AuthHandler
	dbPath := os.Getenv("DB_PATH")
	if dbPath == "" {
		dbPath = "siem.db"
	}
	dbService, err := databases.NewDBService(dbPath)
	if err != nil {
		log.Fatalf("Gagal inisialisasi database SQLite: %v", err)
	}
	authHandler := router.NewAuthHandler(dbService)

	// 2. Static Files dari embedded frontend/ folder
	subFS, err := fs.Sub(frontendFS, "frontend")
	if err != nil {
		log.Fatalf("Failed to initialize frontend filesystem: %v", err)
	}

	app.Use("/", static.New("", static.Config{
		FS:         subFS,
		IndexNames: []string{"index.html"},
	}))

	// 3. Inisialisasi SIEM Service & Router
	siemService := services.NewSIEMService()
	h := router.NewHandleSiem(siemService)

	// 4. Daftarkan Routes Auth & Login
	app.Get("/login", func(c fiber.Ctx) error {
		return c.Redirect().To("/login.html")
	})
	app.Post("/api/v1/auth/register", authHandler.HandleRegister)
	app.Post("/api/v1/auth/login", authHandler.HandleLogin)

	// 5. Daftarkan Routes SIEM Telemetri
	app.Get("/api/v1/stream", h.HandleStream)
	app.Post("/api/v1/agent/heartbeat", h.HandleHeartbeat)
	app.Post("/api/v1/agent/logs", h.HandleIncomingLog)
	app.Get("/api/v1/ips", h.HandleGetIPs)
	app.Get("/api/v1/logs", h.HandleGetLogs)
	app.Get("/api/v1/agents", h.HandleGetAgents)
	app.Post("/api/v1/containment/block", h.HandleBlockIP)

	port := os.Getenv("PORT")
	if port == "" {
		port = ":8082"
	}
	if !strings.HasPrefix(port, ":") {
		port = ":" + port
	}
	fmt.Printf("WAZUH-Lightweight SIEM Dashboard: http://localhost%s\n", port)
	log.Fatal(app.Listen(port))
}
