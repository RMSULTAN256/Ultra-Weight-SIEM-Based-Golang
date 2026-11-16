package config

import (
	"Agent/models"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/bytedance/sonic"
)

var DefaultConfig = models.LogConfig{
	ScanIntervalMs:  500,
	ScanIntervalSec: 5,
	Targets: []models.TargetConfig{
		{
			AppName:  "Nginx Web",
			FilePath: "/var/log/nginx/*.log",
			Keywords: []string{},
		},
		{
			AppName:  "Apache Web",
			FilePath: "/var/log/apache2/*.log",
			Keywords: []string{},
		},
		{
			AppName:  "SSH Auth",
			FilePath: "/var/log/auth.log",
			Keywords: []string{},
		},
		{
			AppName:  "System Syslog",
			FilePath: "/var/log/syslog",
			Keywords: []string{},
		},
		{
			AppName:  "Kernel",
			FilePath: "/var/log/kern.log",
			Keywords: []string{
				"ufw block",
				"out of memory",
				"oom-kill",
				"segfault",
			},
		},
		{
			AppName:  "UFW Firewall",
			FilePath: "/var/log/ufw.log",
			Keywords: []string{},
		},
		{
			AppName:  "MySQL Database",
			FilePath: "/var/log/mysql/*.log",
			Keywords: []string{},
		},
		{
			AppName:  "MariaDB Database",
			FilePath: "/var/log/mariadb/*.log",
			Keywords: []string{},
		},
		{
			AppName:  "PostgreSQL Database",
			FilePath: "/var/log/postgresql/*.log",
			Keywords: []string{},
		},
		{
			AppName:  "Web Application",
			FilePath: "/var/www/*/storage/logs/*.log",
			Keywords: []string{},
		},
		{
			AppName:  "Package Management",
			FilePath: "/var/log/dpkg.log",
			Keywords: []string{
				" install ",
				" remove ",
			},
		},
		{
			AppName:  "Fail2ban",
			FilePath: "/var/log/fail2ban.log",
			Keywords: []string{
				" ban ",
				" unban ",
			},
		},
	},
}

func LoadConfig(filePath string) (*models.LogConfig, error) {
	_, err := os.Stat(filePath)
	if errors.Is(err, os.ErrNotExist) {
		if dir := filepath.Dir(filePath); dir != "." {
			if err := os.MkdirAll(dir, 0755); err != nil {
				return nil, fmt.Errorf("Gagal membuat folder path")
			}
		}

		data, err := sonic.MarshalIndent(DefaultConfig, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("errors decode JSON")
		}

		data = append(data, '\n')

		if err := os.WriteFile(filePath, data, 0644); err != nil {
			return nil, fmt.Errorf("Gagal menuliskan file")
		}
		cfg := DefaultConfig

		return &cfg, nil
	} else if err != nil {
		return nil, fmt.Errorf("gagal cek file: %w", err)
	}
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("File not found: %w", err)
	}

	var cfg models.LogConfig

	err = sonic.Unmarshal(data, &cfg)
	if err != nil {
		return nil, fmt.Errorf("Format invalid : %w", err)
	}
	return &cfg, nil
}
