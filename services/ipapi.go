package services

import (
	"MiniSiem/models"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

type IPService struct {
	client *http.Client
	cache  sync.Map
}

func NewIPService() *IPService {
	return &IPService{
		client: &http.Client{Timeout: time.Duration(10) * time.Second},
		cache:  sync.Map{},
	}
}

func (s *IPService) GetIPInfo(ip string) (*models.IPAPIResponse, error) {
	if val, ok := s.cache.Load(ip); ok {
		return val.(*models.IPAPIResponse), nil
	}

	url := fmt.Sprintf("http://ip-api.com/json/%s?fields=64225277", ip)

	ctx, cancel := context.WithTimeout(context.TODO(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("Gagal membuat request: %w", err)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Gagal menghubungi IP-API: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ip-api error status code: %d", resp.StatusCode)
	}

	var ipData models.IPAPIResponse
	if err := json.NewDecoder(resp.Body).Decode(&ipData); err != nil {
		return nil, fmt.Errorf("gagal decode json: %w", err)
	}

	if ipData.Status == "fail" {
		return nil, fmt.Errorf("ip-api gagal memproses IP: %s", ipData.Message)
	}

	s.cache.Store(ip, &ipData)
	return &ipData, nil
}
