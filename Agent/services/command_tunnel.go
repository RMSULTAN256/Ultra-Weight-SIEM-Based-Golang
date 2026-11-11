package services

import (
	"Agent/proto"
	"context"
	"fmt"
	"log"
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
				log.Printf("[grpc-tunnel] Menerima perintah: %q (ID: %s)", cmdKey, cmdPkt.CommandId)

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
