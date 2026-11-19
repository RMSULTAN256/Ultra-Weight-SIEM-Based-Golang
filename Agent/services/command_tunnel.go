package services

import (
	"Agent/proto"
	"context"
	"fmt"
	"log"
	"net"
	"os/exec"
	"strings"
	"time"

	"github.com/bytedance/sonic"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

var SafeWhitelistActions = map[string]string{
	"uptime":        "uptime",
	"memory":        "free -h",
	"disk":          "df -h /",
	"ports":         "ss -tuln",
	"who":           "who",
	"pwd":           "pwd",
	"ssh_status":    "systemctl status sshd --no-pager",
	"fix_ssh":       "sudo systemctl restart sshd && systemctl status sshd --no-pager",
	"agent_status":  "systemctl status AgentGo.service --no-pager",
	"restart_agent": "sudo systemctl restart AgentGo.service",
}

func StartCommandTunnel(conn *grpc.ClientConn, agentName, agentID, agentKey string) {
	if conn == nil {
		log.Println("[grpc-tunnel] Koneksi gRPC client nil, worker tidak dijalankan")
		return
	}

	client := proto.NewIngestionServiceClient(conn)

	go func() {
		for {
			log.Println("[grpc-tunnel] Menghubungkan ke Reverse Command Tunnel di CenterServer...")
			ctx, cancel := context.WithCancel(context.Background())
			ctx = metadata.AppendToOutgoingContext(ctx,
				"x-agent-key", agentKey,
				"x-agent-name", agentName,
				"x-agent-id", agentID,
			)

			stream, err := client.CommandStream(ctx)
			if err != nil {
				log.Printf("[grpc-tunnel] Gagal membuka stream: %v. Mencoba ulang dalam 5 detik...", err)
				cancel()
				time.Sleep(5 * time.Second)
				continue
			}

			log.Println("[grpc-tunnel]  Reverse Command Tunnel AKTIF dan siap menerima perintah")

			for {
				cmdPkt, err := stream.Recv()
				if err != nil {
					log.Printf("[grpc-tunnel] Stream terputus: %v. Melakukan auto-reconnect...", err)
					break
				}

				if cmdPkt.CommandId == "PING" {
					_ = stream.Send(&proto.CommandResultPacket{
						CommandId:   "PONG",
						ExitCode:    0,
						PayloadJson: []byte(`{"status":"pong"}`),
					})
					continue
				}

				if !VerifyHMAC(agentKey, cmdPkt.PayloadJson, cmdPkt.Timestamp, cmdPkt.Signature) {
					log.Printf("[SECURITY ALERT] HMAC Signature Mismatch untuk cmd_id=%s! Paket dimanipulasi atau kedaluwarsa.", cmdPkt.CommandId)
					_ = stream.Send(&proto.CommandResultPacket{
						CommandId:   cmdPkt.CommandId,
						ExitCode:    -1,
						PayloadJson: []byte(`{"output":"[SECURITY] Tanda tangan HMAC tidak valid. Perintah ditolak!"}`),
					})
					continue
				}

				var reqMap map[string]string
				if err := sonic.Unmarshal(cmdPkt.PayloadJson, &reqMap); err != nil {
					log.Printf("[grpc-tunnel] Gagal parse JSON payload: %v", err)
					continue
				}

				cmdKey := strings.TrimSpace(reqMap["command_key"])
				action := strings.TrimSpace(reqMap["action"])
				if action == "" {
					action = cmdKey
				}
				log.Printf("[grpc-tunnel] Menerima perintah: %q / action: %q (ID: %s)", cmdKey, action, cmdPkt.CommandId)

				// 1. Periksa apakah aksi merupakan Dynamic Containment (iptables PEP)
				if action == "block_ip" || action == "unblock_ip" || action == "containment_status" {
					outStr, exitCode := handleContainmentAction(action, reqMap)
					resMap := map[string]string{"output": outStr}
					resJson, _ := sonic.Marshal(resMap)
					_ = stream.Send(&proto.CommandResultPacket{
						CommandId:   cmdPkt.CommandId,
						ExitCode:    int32(exitCode),
						PayloadJson: resJson,
					})
					continue
				}

				// 2. Periksa whitelist perintah sistem standar
				rawCmd, allowed := SafeWhitelistActions[cmdKey]
				if !allowed {
					log.Printf("[SECURITY] Perintah %q DITOLAK (tidak terdaftar di whitelist)", cmdKey)
					_ = stream.Send(&proto.CommandResultPacket{
						CommandId:   cmdPkt.CommandId,
						ExitCode:    -1,
						PayloadJson: []byte(fmt.Sprintf(`{"output":"Perintah '%s' tidak diizinkan dalam whitelist aman agen."}`, cmdKey)),
					})
					continue
				}

				execCtx, excecCancel := context.WithTimeout(context.Background(), 15*time.Second)
				out, execErr := exec.CommandContext(execCtx, "sh", "-c", rawCmd).CombinedOutput()
				excecCancel()

				exitCode := int32(0)
				if execErr != nil {
					exitCode = 1
					if exitErr, ok := execErr.(*exec.ExitError); ok {
						exitCode = int32(exitErr.ExitCode())
					}
				}

				resMap := map[string]string{"output": string(out)}
				resJson, _ := sonic.Marshal(resMap)

				_ = stream.Send(&proto.CommandResultPacket{
					CommandId:   cmdPkt.CommandId,
					ExitCode:    exitCode,
					PayloadJson: resJson,
				})
			}
			cancel()
			time.Sleep(3 * time.Second)
		}
	}()
}

// handleContainmentAction mengeksekusi aksi isolasi firewall iptables (PEP Zero-Trust)
func handleContainmentAction(action string, reqMap map[string]string) (string, int) {
	if action == "containment_status" {
		out, err := exec.Command("iptables", "-L", "INPUT", "-v", "-n").CombinedOutput()
		if err != nil {
			out, err = exec.Command("sudo", "iptables", "-L", "INPUT", "-v", "-n").CombinedOutput()
		}
		if err != nil {
			return fmt.Sprintf("[PEP-ERROR] Gagal membaca iptables: %v (%s)", err, string(out)), 1
		}
		return string(out), 0
	}

	targetIP := strings.TrimSpace(reqMap["ip"])
	if targetIP == "" {
		targetIP = strings.TrimSpace(reqMap["target_ip"])
	}
	if targetIP == "" {
		return "[PEP-ERROR] Parameter IP target tidak disertakan", 1
	}

	parsedIP := net.ParseIP(targetIP)
	if parsedIP == nil {
		return fmt.Sprintf("[PEP-ERROR] Format IP target '%s' tidak valid", targetIP), 1
	}
	if parsedIP.IsLoopback() {
		return fmt.Sprintf("[PEP-ERROR] IP %s adalah loopback (dilarang diblokir demi keamanan node)", targetIP), 1
	}

	switch action {
	case "block_ip":
		// 1. Cek apakah aturan DROP sudah ada di kernel
		checkCmd := exec.Command("iptables", "-C", "INPUT", "-s", targetIP, "-j", "DROP")
		if err := checkCmd.Run(); err == nil {
			return fmt.Sprintf("[PEP-CONTAINMENT] IP %s sudah berada dalam daftar blokir iptables DROP", targetIP), 0
		}

		// 2. Terapkan aturan iptables -I INPUT -s <IP> -j DROP
		blockCmd := exec.Command("iptables", "-I", "INPUT", "-s", targetIP, "-j", "DROP")
		out, err := blockCmd.CombinedOutput()
		if err != nil {
			// Fallback coba dengan sudo jika service non-root
			sudoCmd := exec.Command("sudo", "iptables", "-I", "INPUT", "-s", targetIP, "-j", "DROP")
			sudoOut, sudoErr := sudoCmd.CombinedOutput()
			if sudoErr != nil {
				return fmt.Sprintf("[PEP-ERROR] Gagal menjalankan iptables DROP untuk %s: %v (%s | %s)", targetIP, err, string(out), string(sudoOut)), 1
			}
		}
		log.Printf("[PEP-CONTAINMENT] SUKSES: IP %s berhasil diisolasi (iptables -I INPUT -s %s -j DROP)", targetIP, targetIP)
		return fmt.Sprintf("[PEP-CONTAINMENT] SUKSES: IP %s berhasil diisolasi pada firewall kernel simpul (iptables DROP)", targetIP), 0

	case "unblock_ip":
		// Cek & hapus aturan iptables -D INPUT -s <IP> -j DROP
		delCmd := exec.Command("iptables", "-D", "INPUT", "-s", targetIP, "-j", "DROP")
		out, err := delCmd.CombinedOutput()
		if err != nil {
			sudoCmd := exec.Command("sudo", "iptables", "-D", "INPUT", "-s", targetIP, "-j", "DROP")
			sudoOut, sudoErr := sudoCmd.CombinedOutput()
			if sudoErr != nil {
				return fmt.Sprintf("[PEP-CONTAINMENT] IP %s tidak ditemukan atau gagal dihapus dari iptables: %s (direct: %s)", targetIP, string(sudoOut), string(out)), 1
			}
		}
		log.Printf("[PEP-CONTAINMENT] SUKSES: Blokir IP %s dilepas dari iptables DROP", targetIP)
		return fmt.Sprintf("[PEP-CONTAINMENT] SUKSES: Blokir IP %s berhasil dicabut dari iptables simpul", targetIP), 0

	default:
		return fmt.Sprintf("[PEP-ERROR] Aksi containment '%s' tidak dikenali", action), 1
	}
}
