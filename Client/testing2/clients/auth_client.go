package clients

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type AuthClient struct {
	BaseURL    string
	HTTPClient *http.Client
}

func NewAuthClient(baseURL string) *AuthClient {
	return &AuthClient{
		BaseURL: baseURL,
		HTTPClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (c *AuthClient) ValidateToken(token string) (uint, error) {
	req, err := http.NewRequest("GET", c.BaseURL+"/api/profile", nil)
	if err != nil {
		return 0, fmt.Errorf("create request failed: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("auth service unreachable: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("invalid token: status %d", resp.StatusCode)
	}
	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, fmt.Errorf("decode response failed: %w", err)
	}
	userID, ok := result["id"].(float64)
	if !ok {
		return 0, fmt.Errorf("user id not found in response")
	}
	return uint(userID), nil
}
