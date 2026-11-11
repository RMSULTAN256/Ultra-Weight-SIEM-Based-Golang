package router

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	"server3/models"

	"github.com/bytedance/sonic"
	"github.com/gofiber/fiber/v3"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// NodeSSHConfig mendeskripsikan satu host yang boleh menerima eksekusi perintah
// dari CenterServer. Semua field bisa di-override lewat environment variable,
// supaya IP/host/user tidak lagi hardcoded di source.
type NodeSSHConfig struct {
	// AgentID adalah ID yang dikirim heartbeat (biasanya hostname / hostname-IP).
	AgentID string
	// Aliases adalah ID/IP tambahan yang diterima APA ADANYA (exact match).
	// Tanpa pencocokan substring: salah tulis = 404, bukan nyasar ke host lain.
	Aliases []string
	Addr    string
	User    string
	KeyPath string
	// KnownHosts dipakai untuk verifikasi host key. Wajib bisa dibaca,
	// kecuali HostKeyPin diisi (mode pinning, lebih cocok untuk container).
	KnownHosts string
	// HostKeyPin (opsional) = "SHA256:..." dari `ssh-keygen -lf known_hosts`.
	// Kalau diisi, pin ini yang menang dan KnownHosts tidak perlu ada.
	HostKeyPin  string
	ServiceName string
}

var NodeSSHMap = map[string]NodeSSHConfig{
	"ubuntu": {
		AgentID:     "ubuntu",
		Aliases:     splitAliases(envOr("SSH_NODE1_ALIASES", "ubuntu-31.56.56.50,31.56.56.50")),
		Addr:        envOr("SSH_NODE1_ADDR", "31.56.56.50:30061"),
		User:        envOr("SSH_NODE1_USER", "root"),
		KeyPath:     envOr("SSH_KEY_PATH", os.ExpandEnv("$HOME/.ssh/prod-1-only")),
		KnownHosts:  envOr("SSH_KNOWN_HOSTS", os.ExpandEnv("$HOME/.ssh/known_hosts")),
		HostKeyPin:  os.Getenv("SSH_NODE1_HOSTKEY_PIN"),
		ServiceName: envOr("SSH_NODE1_SERVICE", "AgentgGo"),
	},
	"ubuntu-2": {
		AgentID:     "ubuntu-2",
		Aliases:     splitAliases(envOr("SSH_NODE2_ALIASES", "ubuntu-163.52.135.170,163.52.135.170")),
		Addr:        envOr("SSH_NODE2_ADDR", "163.52.135.170:27151"),
		User:        envOr("SSH_NODE2_USER", "ubuntu"),
		KeyPath:     envOr("SSH_KEY_PATH", os.ExpandEnv("$HOME/.ssh/prod-1-only")),
		KnownHosts:  envOr("SSH_KNOWN_HOSTS", os.ExpandEnv("$HOME/.ssh/known_hosts")),
		HostKeyPin:  os.Getenv("SSH_NODE2_HOSTKEY_PIN"),
		ServiceName: envOr("SSH_NODE2_SERVICE", "agentGo"),
	},
}

// WhitelistCommands: perintah read-only yang tidak bergantung pada ServiceName.
var WhitelistCommands = map[string]string{
	"ssh_status": "systemctl status sshd --no-pager",
	"ports":      "ss -tuln",
	"disk":       "df -h /",
	"who":        "who",
	"pwd":        "pwd",
	"uptime":     "uptime",
	"memory":     "free -h",
}

var (
	errNodeNotFound     = errors.New("node tidak terdaftar dalam konfigurasi SSH")
	errCommandRejected  = errors.New("perintah tidak diizinkan")
	errNoKnownHostsFile = errors.New("path known_hosts kosong")
)

// nodeIndex: peta deterministik ID -> node, dibangun sekali saat start.
// Kunci di-lowercase supaya perbandingan case-insensitive tapi tetap exact.
var nodeIndex = buildNodeIndex()

func buildNodeIndex() map[string]NodeSSHConfig {
	// Urutan iterasi map di Go acak, jadi key disortir dulu. Dengan begitu,
	// kalau ada ID kembar, pemenangnya selalu sama (bukan random per request).
	keys := make([]string, 0, len(NodeSSHMap))
	for k := range NodeSSHMap {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	idx := make(map[string]NodeSSHConfig, len(keys)*3)
	for _, k := range keys {
		node := NodeSSHMap[k]

		// Prioritas: key map, AgentID, Aliases, lalu host dari Addr
		// (supaya agen yang melapor pakai IP mentah tetap ketemu).
		candidates := make([]string, 0, 4+len(node.Aliases))
		candidates = append(candidates, k, node.AgentID)
		candidates = append(candidates, node.Aliases...)
		if host, _, err := net.SplitHostPort(node.Addr); err == nil {
			candidates = append(candidates, host, node.Addr)
		}

		for _, cand := range candidates {
			id := normalizeNodeID(cand)
			if id == "" {
				continue
			}
			if prev, dup := idx[id]; dup {
				if prev.Addr != node.Addr {
					// Konfigurasi bentrok: jangan menebak. Pemenang sudah
					// ditentukan urutan sortir, sisanya diperingatkan saat start.
					log.Printf("[ssh-exec] WARN: ID %q dipakai dua node (%s dan %s); dipakai %s",
						id, prev.Addr, node.Addr, prev.Addr)
				}
				continue
			}
			idx[id] = node
		}
	}

	logNodeIndex(idx)
	return idx
}

// logNodeIndex menulis ID apa saja yang diterima tiap node saat start, supaya
// kalau tombol Remote Shell balas 404, penyebabnya kelihatan di log container.
func logNodeIndex(idx map[string]NodeSSHConfig) {
	byAddr := make(map[string][]string, len(NodeSSHMap))
	for id, node := range idx {
		byAddr[node.Addr] = append(byAddr[node.Addr], id)
	}

	addrs := make([]string, 0, len(byAddr))
	for addr := range byAddr {
		addrs = append(addrs, addr)
	}
	sort.Strings(addrs)

	for _, addr := range addrs {
		ids := byAddr[addr]
		sort.Strings(ids)
		log.Printf("[ssh-exec] node %s (service %s) menerima agent ID: %s",
			addr, idx[ids[0]].ServiceName, strings.Join(ids, ", "))
	}
}

func normalizeNodeID(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// ResolveNode memetakan agent ID dari heartbeat ke konfigurasi SSH.
// Exact match saja: tanpa strings.Contains, tanpa iterasi map saat lookup.
func ResolveNode(agentID string) (NodeSSHConfig, error) {
	id := normalizeNodeID(agentID)
	if id == "" {
		return NodeSSHConfig{}, fmt.Errorf("%w: agent ID kosong", errNodeNotFound)
	}
	if node, ok := nodeIndex[id]; ok {
		return node, nil
	}
	return NodeSSHConfig{}, fmt.Errorf("%w: %q (daftarkan di NodeSSHMap/Aliases atau SSH_NODE*_ALIASES)", errNodeNotFound, id)
}

// BuildCommand menyusun perintah dari node yang SUDAH di-resolve.
// Fungsi ini murni (tidak menyentuh NodeSSHMap), jadi mustahil konek ke host A
// dengan nama service milik host B.
func BuildCommand(node NodeSSHConfig, cmdKey string) (string, error) {
	key := strings.TrimSpace(cmdKey)
	if key == "" {
		return "", fmt.Errorf("%w: command_key kosong", errCommandRejected)
	}

	switch key {
	case "agent_status", "restart_agent":
		if strings.TrimSpace(node.ServiceName) == "" {
			return "", fmt.Errorf("%w: ServiceName untuk node %s belum diisi", errCommandRejected, node.Addr)
		}
		if key == "agent_status" {
			return fmt.Sprintf("systemctl status %s.service --no-pager", node.ServiceName), nil
		}
		return fmt.Sprintf("sudo systemctl restart %s.service && systemctl status %s.service --no-pager",
			node.ServiceName, node.ServiceName), nil
	}

	if cmd, ok := WhitelistCommands[key]; ok {
		return cmd, nil
	}
	return "", fmt.Errorf("%w: %q tidak terdaftar dalam whitelist", errCommandRejected, key)
}

// hostKeyCallback: verifikasi host key WAJIB (fail-closed).
// Mode "insecure" hanya aktif kalau SSH_INSECURE_HOST_KEY=true dan selalu
// menghasilkan WARN di log, supaya tidak pernah jadi fallback diam-diam.
func hostKeyCallback(cfg NodeSSHConfig) (ssh.HostKeyCallback, error) {
	if pin := strings.TrimSpace(cfg.HostKeyPin); pin != "" {
		return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			got := ssh.FingerprintSHA256(key)
			if !strings.EqualFold(got, pin) {
				return fmt.Errorf("host key %s (%s) tidak cocok dengan pin %s", hostname, remote, pin)
			}
			return nil
		}, nil
	}

	var knownErr error
	if path := strings.TrimSpace(cfg.KnownHosts); path != "" {
		cb, err := knownhosts.New(path)
		if err == nil {
			return cb, nil
		}
		knownErr = err
	} else {
		knownErr = errNoKnownHostsFile
	}

	if insecureHostKeyAllowed() {
		log.Printf("[ssh-exec] WARN: verifikasi host key DIMATIKAN untuk %s (SSH_INSECURE_HOST_KEY=true): %v — jangan dipakai di production", cfg.Addr, knownErr)
		return ssh.InsecureIgnoreHostKey(), nil
	}

	return nil, fmt.Errorf("host key node %s tidak bisa diverifikasi: %w (siapkan %s atau set SSH_NODE*_HOSTKEY_PIN)",
		cfg.Addr, knownErr, cfg.KnownHosts)
}

func insecureHostKeyAllowed() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("SSH_INSECURE_HOST_KEY")))
	return v == "1" || v == "true" || v == "yes" || v == "on"
}

func RunSSH(ctx context.Context, cfg NodeSSHConfig, cmd string) (string, int, error) {
	keyBytes, err := os.ReadFile(cfg.KeyPath)
	if err != nil {
		// Fallback untuk container: kunci biasanya di-mount ke /app/data.
		altPath := envOr("SSH_KEY_FALLBACK", "/app/data/prod-1-only")
		altBytes, altErr := os.ReadFile(altPath)
		if altErr != nil {
			return "", -1, fmt.Errorf("kunci privat SSH tidak terbaca di %s maupun %s: %w", cfg.KeyPath, altPath, err)
		}
		keyBytes = altBytes
	}

	signer, err := ssh.ParsePrivateKey(keyBytes)
	if err != nil {
		return "", -1, fmt.Errorf("format kunci privat SSH tidak valid: %w", err)
	}

	hostKeyCB, err := hostKeyCallback(cfg)
	if err != nil {
		return "", -1, err
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
		return "", -1, fmt.Errorf("koneksi TCP ke %s gagal: %w", cfg.Addr, err)
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
		return "", -1, fmt.Errorf("gagal membuat SSH session: %w", err)
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

	// 1) Resolusi node SEKALI, exact match.
	node, err := ResolveNode(agentID)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": err.Error()})
	}

	// 2) Perintah dibangun dari node yang sama -> target dan service selalu sinkron.
	rawCmd, err := BuildCommand(node, req.CommandKey)
	if err != nil {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": err.Error()})
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	start := time.Now()
	output, exitCode, execErr := RunSSH(ctx, node, rawCmd)
	elapsedMs := float64(time.Since(start).Microseconds()) / 1000.0

	// 3) Audit trail: siapa mengeksekusi apa, di host mana, hasilnya bagaimana.
	sc.auditRemoteExec(c, node, agentID, req.CommandKey, rawCmd, exitCode, execErr, elapsedMs)

	if execErr != nil && exitCode == -1 {
		// Detail (path kunci, IP internal) hanya masuk log server, tidak ke client.
		log.Printf("[ssh-exec] agent=%s node=%s user=%s cmd=%q gagal: %v",
			agentID, node.Addr, node.User, req.CommandKey, execErr)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":             "Eksekusi SSH gagal. Detail sudah dicatat pada log server.",
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

// auditRemoteExec mencatat eksekusi remote ke ring buffer SIEM + broadcast ke
// dashboard, supaya aktivitas "root via SSH" tidak hilang tanpa jejak.
func (sc *HandleService) auditRemoteExec(c fiber.Ctx, node NodeSSHConfig, agentID, cmdKey, rawCmd string, exitCode int, execErr error, elapsedMs float64) {
	actor, _ := c.Locals("username").(string)
	if strings.TrimSpace(actor) == "" {
		actor = "unknown"
	}

	status := "success"
	severity := 3
	msg := fmt.Sprintf("Remote exec '%s' sukses di %s (exit=%d) oleh %s dalam %.1f ms",
		cmdKey, node.Addr, exitCode, actor, elapsedMs)

	if execErr != nil || exitCode != 0 {
		status = "failed"
		severity = 7
		msg = fmt.Sprintf("Remote exec '%s' GAGAL di %s (exit=%d) oleh %s: %v",
			cmdKey, node.Addr, exitCode, actor, execErr)
	} else if cmdKey == "restart_agent" {
		// Perubahan state layanan: naikkan severity supaya muncul di dashboard.
		severity = 10
	}

	secLog := models.SecurityLog{
		Timestamp: time.Now().UTC(),
		Hostname:  agentID,
		EventType: "remote_exec",
		Severity:  severity,
		SourceIP:  getClientIP(c),
		User:      actor,
		Service:   node.ServiceName,
		Endpoint:  "/api/v1/agents/:id/exec",
		Command:   rawCmd,
		Method:    "SSH",
		Status:    status,
		Message:   msg,
	}

	sc.siemService.AddLog(secLog)
	if b, err := sonic.Marshal(secLog); err == nil {
		sc.siemService.Broadcast(string(b))
	}
}

func envOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func splitAliases(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
