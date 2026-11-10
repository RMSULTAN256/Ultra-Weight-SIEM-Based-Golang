package router

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/bytedance/sonic"
	"github.com/gofiber/fiber/v3"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

type NodeSSHConfig struct {
	Addr, User, KeyPath, KnownHosts, ServiceName string
}

var NodeSSHMap = map[string]NodeSSHConfig{
	"ubuntu": {
		Addr:        "31.56.56.50:30061",
		User:        "root",
		KeyPath:     os.ExpandEnv("$HOME/.ssh/prod-1-only"),
		KnownHosts:  os.ExpandEnv("$HOME/.ssh/known_hosts"),
		ServiceName: "AgentgGo",
	},
	"ubuntu-2": {
		Addr:        "163.52.135.170:27151",
		User:        "ubuntu",
		KeyPath:     os.ExpandEnv("$HOME/.ssh/prod-1-only"),
		KnownHosts:  os.ExpandEnv("$HOME/.ssh/known_hosts"),
		ServiceName: "agentGo",
	},
}

var WhitelistCommands = map[string]string{
	"ssh_status": "systemctl status sshd --no-pager",
	"ports":      "ss -tuln",
	"disk":       "df -h /",
	"who":        "who",
	"pwd":        "pwd",
	"uptime":     "uptime",
	"memory":     "free -h",
}

func ResolveCommand(agentID, cmdKey string) (string, error) {
	node, exists := NodeSSHMap[agentID]
	if !exists {
		for k, v := range NodeSSHMap {
			if strings.Contains(agentID, k) || strings.Contains(v.Addr, agentID) {
				node = v
				exists = true
				break
			}
		}
		if !exists {
			return "", fmt.Errorf("Target node '%s' tidak ditemkan dalam konfigurasi SSH", agentID)
		}
	}

	switch cmdKey {
	case "agent_status":
		return fmt.Sprintf("systemctl status %s.service --no-pager", node.ServiceName), nil
	case "restart_agent":
		return fmt.Sprintf("sudo systemctl restart %s.service && systemctl status %s.service --no-pager", node.ServiceName, node.ServiceName), nil
	default:
		if cmd, ok := WhitelistCommands[cmdKey]; ok {
			return cmd, nil
		}
		return "", fmt.Errorf("Perintah '%s' tidak diizinkan (tidak terdaftar dalam whitelist)", cmdKey)
	}
}

func RunSSH(ctx context.Context, cfg NodeSSHConfig, cmd string) (string, int, error) {
	keyBytes, err := os.ReadFile(cfg.KeyPath)
	if err != nil {
		altPath := "/app/data/prod-1-only"
		if altBytes, altErr := os.ReadFile(altPath); altErr == nil {
			keyBytes = altBytes
		} else {
			return "", -1, fmt.Errorf("Kunci privat SSH tidak ditemukan di %s: %w", cfg.KeyPath, err)
		}
	}

	signer, err := ssh.ParsePrivateKey(keyBytes)
	if err != nil {
		return "", -1, fmt.Errorf("Format kunci privat SSH tidak valid: %w", err)
	}

	var hostKeyCB ssh.HostKeyCallback
	if cb, err := knownhosts.New(cfg.KnownHosts); err == nil {
		hostKeyCB = cb
	} else {
		hostKeyCB = ssh.InsecureIgnoreHostKey()
	}

	sshConfig := &ssh.ClientConfig{
		User:            cfg.User,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: hostKeyCB,
		Timeout:         10 * time.Second,
	}

	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", cfg.Addr)
	if err != nil {
		return "", -1, fmt.Errorf("Koneksi TCP ke %s gagal: %w", cfg.Addr, err)
	}

	c, chans, reqs, err := ssh.NewClientConn(conn, cfg.Addr, sshConfig)
	if err != nil {
		conn.Close()
		return "", -1, fmt.Errorf("SSH handshake ke %s gagal: %w", cfg.Addr, err)
	}

	client := ssh.NewClient(c, chans, reqs)
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return "", -1, fmt.Errorf("Gagal membuat SSH session: %w", err)
	}
	defer session.Close()

	type result struct {
		output   []byte
		exitCode int
		err      error
	}

	resCh := make(chan result, 1)
	go func() {
		out, runErr := session.CombinedOutput(cmd)
		exitCode := 0
		if runErr != nil {
			if exitErr, ok := runErr.(*ssh.ExitError); ok {
				exitCode = exitErr.ExitStatus()
			} else {
				exitCode = 1
			}
		}
		resCh <- result{output: out, exitCode: exitCode, err: runErr}
	}()

	select {
	case res := <-resCh:
		return string(res.output), res.exitCode, nil
	case <-ctx.Done():
		return "", -1, ctx.Err()
	}
}

func (sc *HandleService) HandleRemoteExec(c fiber.Ctx) error {
	agentID := strings.TrimSpace(c.Params("id"))
	if agentID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Agent ID wajib disertakan"})
	}

	var req struct {
		CommandKey string `json:"command_key"`
	}

	if err := sonic.Unmarshal(c.Body(), &req); err != nil || strings.TrimSpace(req.CommandKey) == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Payload tidak valid: command_key wajib diisi"})
	}

	node, exists := NodeSSHMap[agentID]
	if !exists {
		for k, v := range NodeSSHMap {
			if strings.Contains(agentID, k) || strings.Contains(v.Addr, agentID) {
				node = v
				exists = true
				break
			}
		}

		if !exists {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"error": fmt.Sprintf("Node '%s' tidak terdaftar dalam konfigurasi SSH", agentID),
			})
		}
	}

	rawCmd, err := ResolveCommand(agentID, req.CommandKey)
	if err != nil {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	start := time.Now()
	output, exitCode, err := RunSSH(ctx, node, rawCmd)
	elapsedMs := float64(time.Since(start).Microseconds()) / 1000.0

	if err != nil && exitCode == -1 {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":             err.Error(),
			"execution_time_ms": elapsedMs,
		})
	}

	return c.JSON(fiber.Map{
		"agent_id":          agentID,
		"command_key":       req.CommandKey,
		"executed_cmd":      rawCmd,
		"output":            output,
		"exit_code":         exitCode,
		"execution_time_ms": elapsedMs,
	})
}
