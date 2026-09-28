package main

import (
	"fmt"
	"os"
	"time"

	"github.com/bytedance/sonic"
	"github.com/gofiber/fiber/v2"
)

func ma22in() {
	app := fiber.New()

	app.Post("/api/add", func(c *fiber.Ctx) error {
		var payload map[string]interface{}

		if err := c.BodyParser(&payload); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"status": "error",
				"error":  "Invalid request payload",
			})
		}

		jsonBytes, err := sonic.Marshal(payload)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"status": "error",
				"error":  "Failed to process request",
			})
		}

		logLines := fmt.Sprintf("[%s] %s\n", time.Now().Format("2006-01-02 15:04:05"), string(jsonBytes))

		filePath := "Test.txt"
		file, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"status": "error",
				"error":  "Failed to open log file",
			})
		}
		defer file.Close()

		if _, err := file.WriteString(logLines); err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"status": "error",
				"error":  "Failed to write to log file",
			})
		}

		return c.Status(fiber.StatusOK).JSON(fiber.Map{
			"status":  "success",
			"message": "Data added successfully",
		})
	})

	fmt.Println("🚀 Server API belajar berjalan di http://localhost:8080")
	if err := app.Listen(":8080"); err != nil {
		fmt.Println("Server error:", err)
	}
}
