package router

import (
	"server3/databases"
	"server3/models"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/golang-jwt/jwt/v5"
)

type AuthHandler struct {
	db *databases.DBService
}

func NewAuthHandler(db *databases.DBService) *AuthHandler {
	return &AuthHandler{db: db}
}

var SecretKey = []byte("AmboiSiPadangni")

func (d *AuthHandler) HandleRegister(c fiber.Ctx) error {
	var req models.AuthRequest

	if err := c.Bind().JSON(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Bad Format json"})
	}

	if req.Username == "" || len(req.Password) < 6 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Username invalid and Password Minimal 6 Character"})
	}

	if req.Role == "" {
		req.Role = "admin"
	}

	err := d.db.RegisterUser(req.Username, req.Password, req.Role)
	if err != nil {
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": "User already used"})
	}

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{"status": "success", "message": "User berhasil didaftarkan"})
}

func (d *AuthHandler) HandleLogin(c fiber.Ctx) error {
	var req models.AuthRequest

	if err := c.Bind().JSON(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid Format JSON"})
	}

	ok, role, err := d.db.Authenticate(req.Username, req.Password)
	if !ok || err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Username atau password salah",
		})
	}

	claims := jwt.MapClaims{
		"username": req.Username,
		"role":     role,
		"exp":      time.Now().Add(1 * time.Hour).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(SecretKey)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Gagal mem-generate token keamanan"})
	}

	return c.JSON(fiber.Map{
		"status":   "success",
		"message":  "Login berhasil",
		"token":    tokenString,
		"username": req.Username,
		"role":     role,
	})
}
