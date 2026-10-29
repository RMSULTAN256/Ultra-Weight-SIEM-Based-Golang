package handlers

import (
	"errors"
	"time"

	"server1/config"
	// "server1/database"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
)

type Handler struct {
	Config *config.Config
}

func New(cfg *config.Config) *Handler {
	return &Handler{Config: cfg}
}

type RegisterRequest struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// func (h *Handler) Register(c *fiber.Ctx) error {
// 	var req RegisterRequest
// 	if err := c.BodyParser(&req); err != nil {
// 		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request"})
// 	}

// 	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
// 	if err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to hash password"})
// 	}

// 	user := models.User{
// 		Name:     req.Name,
// 		Email:    req.Email,
// 		Password: string(hashedPassword),
// 	}

// 	if err := database.DB.Create(&user).Error; err != nil {
// 		return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": "user already exists"})
// 	}

// 	return c.Status(fiber.StatusCreated).JSON(fiber.Map{"message": "user created", "id": user.ID})
// }

// func (h *Handler) Login(c *fiber.Ctx) error {
// 	var req LoginRequest
// 	if err := c.BodyParser(&req); err != nil {
// 		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request"})
// 	}

// 	var user models.User
// 	if err := database.DB.Where("email = ?", req.Email).First(&user).Error; err != nil {
// 		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid credentials"})
// 	}

// 	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
// 		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid credentials"})
// 	}

// 	accessToken, err := generateToken(user.ID, h.Config.JWTSecret, 15*time.Minute)
// 	if err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to generate access token"})
// 	}

// 	refreshToken, err := generateToken(user.ID, h.Config.JWTSecret, 7*24*time.Hour)
// 	if err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to generate refresh token"})
// 	}

// 	return c.JSON(TokenResponse{
// 		AccessToken:  accessToken,
// 		RefreshToken: refreshToken,
// 	})
// }

func (h *Handler) Refresh(c *fiber.Ctx) error {
	var req RefreshRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request"})
	}

	token, err := jwt.Parse(req.RefreshToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(h.Config.JWTSecret), nil
	})

	if err != nil || !token.Valid {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid refresh token"})
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid token claims"})
	}

	userID, ok := claims["user_id"].(float64)
	if !ok {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid user id in token"})
	}

	accessToken, err := generateToken(uint(userID), h.Config.JWTSecret, 15*time.Minute)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to generate access token"})
	}

	return c.JSON(fiber.Map{"access_token": accessToken})
}

func generateToken(userID uint, secret string, duration time.Duration) (string, error) {
	claims := jwt.MapClaims{
		"user_id": userID,
		"exp":     time.Now().Add(duration).Unix(),
		"iat":     time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}
