package main

import (
	"fmt"
	"log"
	"os"

	"server2/clients"
	"server2/middleware"

	"github.com/gofiber/fiber/v2"
)

func main() {
	app := fiber.New()

	authServerURL := "http://localhost:3000"
	if envURL := os.Getenv("AUTH_SERVER_URL"); envURL != "" {
		authServerURL = envURL
	}
	authClient := clients.NewAuthClient(authServerURL)

	// Endpoint publik (tanpa login)
	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendString("Hello from Server 2 (Public)!")
	})

	app.Post("/receive-from-server1", func(c *fiber.Ctx) error {
		var data map[string]interface{}
		if err := c.BodyParser(&data); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid body"})
		}

		fmt.Printf("[SERVER 2] Menerima data dari Server 1: %v\n", data)
		return c.JSON(fiber.Map{
			"status":  "sukses",
			"message": "Data berhasil diterima oleh Server 2!",
		})
	})

	protected := app.Group("/api", middleware.AuthMiddleware(authClient))

	protected.Get("/secret-data", func(c *fiber.Ctx) error {
		userID := c.Locals("userID")
		return c.JSON(fiber.Map{
			"message": "Berhasil mengakses data rahasia di Server 2!",
			"user_id": userID,
		})
	})

	fmt.Println("Server 2 listening on port 3001...")
	log.Fatal(app.Listen(":3001"))
}
