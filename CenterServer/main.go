package main

import (
	"embed"
	"fmt"
	"io/fs"
	"log"
	"net"
	"os"
	"runtime"
	"server3/databases"
	"server3/proto"
	"server3/router"
	"server3/services"
	"strings"
	"time"

	"google.golang.org/grpc"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/limiter"
	"github.com/gofiber/fiber/v3/middleware/static"
)

//go:embed frontend/*
var frontendFS embed.FS

func main() {
	// 0. Muat JWT secret dari environment (fail-fast bila kosong / kurang dari 32 karakter)
	router.InitSecret()

	app := fiber.New(
		fiber.Config{
			TrustProxy:  true,
			ProxyHeader: fiber.HeaderXForwardedFor,
		},
	)
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

	subFS, err := fs.Sub(frontendFS, "frontend")
	if err != nil {
		log.Fatalf("Failed to initialize frontend filesystem: %v", err)
	}

	app.Use("/", static.New("", static.Config{
		FS:         subFS,
		IndexNames: []string{"index.html"},
		MaxAge:     0,
		ModifyResponse: func(c fiber.Ctx) error {
			c.Set("Cache-Control", "no-cache, no-store, must-revalidate")
			c.Set("Pragma", "no-cache")
			c.Set("Expires", "0")
			return nil
		},
	}))

	siemService := services.NewSIEMService()
	h := router.NewHandleSiem(siemService)

	loginLimiter := limiter.New(limiter.Config{
		Max:        5,
		Expiration: 1 * time.Minute,
		LimitReached: func(c fiber.Ctx) error {
			return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
				"error": "Too many Request, please try again later",
			})
		},
	})

	app.Get("/login", func(c fiber.Ctx) error {
		return c.Redirect().To("/login.html")
	})
	// Registrasi publik sengaja TIDAK didaftarkan di sini: akun admin dibuat oleh
	// seed database (ADMIN_INIT_PASSWORD). Pembuatan user hanya tersedia di area
	// admin-only (POST /api/v1/users) agar tidak jadi jalur eskalasi role.
	// Fiber v3 mengeksekusi handler sesuai urutan argumen, jadi limiter ditaruh
	// paling depan supaya berjalan SEBELUM HandleLogin.
	app.Post("/api/v1/auth/login", loginLimiter, authHandler.HandleLogin)

	// 5. Daftarkan Routes SIEM Telemetri
	// SSE: EventSource tidak bisa mengirim header Authorization, jadi token
	// dikirim lewat ?token= dan diverifikasi sebelum stream dibuka.
	app.Get("/api/v1/stream", router.RequireStreamAuth(), h.HandleStream)
	go func() {
		ticker := time.NewTicker(4 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			allocMB := float64(m.Alloc) / 1024.0 / 1024.0
			sysMB := float64(m.Sys) / 1024.0 / 1024.0

			payload := fmt.Sprintf(`{"event_type":"ENGINE_STATS","ram_alloc_mb":%.1f,"ram_sys_mb":%.1f,"goroutines":%d}`,
				allocMB, sysMB, runtime.NumGoroutine())
			siemService.Broadcast(payload)
		}
	}()

	go func() {
		grpcPort := os.Getenv("GRPC_PORT")
		if grpcPort == "" {
			grpcPort = ":50051"
		}

		if !strings.HasPrefix(grpcPort, ":") {
			grpcPort = ":" + grpcPort
		}

		lis, err := net.Listen("tcp", grpcPort)
		if err != nil {
			log.Fatalf("Failed to listen port gRPC %s: %v", grpcPort, err)
		}

		grpcServer := grpc.NewServer()
		grpcHandler := router.NewGRPCServer(siemService)
		proto.RegisterIngestionServiceServer(grpcServer, grpcHandler)
		fmt.Printf("gRPC High-Throughput Ingestion Server: tcp://0.0.0.0%s\n", grpcPort)
		if err := grpcServer.Serve(lis); err != nil {
			log.Fatalf("gRPC server crash: %v", err)
		}
	}()

	// 5a. API Agen (machine-to-machine, wajib header X-Agent-Key).
	// Didaftarkan SEBELUM baseApi karena baseApi memakai prefix "/api/v1" yang
	// juga mencakup "/api/v1/agent/*"; kalau urutannya terbalik, RequireAuth
	// akan menolak heartbeat & log dari agen lebih dulu.
	agentApi := app.Group("/api/v1/agent", router.RequireAgentKey())
	agentApi.Post("/heartbeat", h.HandleHeartbeat)
	agentApi.Post("/logs", h.HandleIncomingLog)

	// 5b. API Dashboard (JWT)
	baseApi := app.Group("/api/v1", router.RequireAuth())
	baseApi.Get("/logs", h.HandleGetLogs)
	baseApi.Get("/agents", h.HandleGetAgents)
	baseApi.Get("/ips", h.HandleGetIPs)
	baseApi.Post("/probe", h.HandleProbe)

	adminOnly := baseApi.Group("/", router.RequireRole("admin"))
	adminOnly.Delete("/agents/:id", h.HandleDeleteAgent)
	adminOnly.Post("/containment/block", h.HandleBlockIP)
	adminOnly.Post("/users", authHandler.HandleRegister)
	adminOnly.Post("/agents/:id/exec", h.HandleRemoteExec)

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
