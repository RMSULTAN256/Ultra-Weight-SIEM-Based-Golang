package config

import (
	"Agent/models"
	"fmt"
	"os"

	"github.com/bytedance/sonic"
)

func LoadConfig(filepath string) (*models.LogConfig, error) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("Something wrong when read file")
	}

	var cfg models.LogConfig

	err = sonic.Unmarshal(data, &cfg)
	if err != nil {
		return nil, fmt.Errorf("Format invalid")
	}
	return &cfg, nil
}
