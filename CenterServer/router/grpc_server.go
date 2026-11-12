package router

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"server3/models"
	"server3/proto"
	"server3/services"
	"strings"
	"sync"
	"time"

	"github.com/bytedance/sonic"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

var ActiveGRPCServer *GRPCServer

type agentSession struct {
	agentID, agentName, sourceIP string
	sendCh                       chan *proto.CommandPacket
}

type commandWaiter struct {
	resultCh chan *proto.CommandResultPacket
}

type GRPCServer struct {
	proto.UnimplementedIngestionServiceServer
	siemService    *services.SIEMService
	sessions       sync.Map
	pendingWaiters sync.Map
}

func NewGRPCServer(siemSvc *services.SIEMService) *GRPCServer {
	srv := &GRPCServer{
		siemService: siemSvc,
	}
	ActiveGRPCServer = srv
	return srv
}

func (s *GRPCServer) StreamLogs(stream proto.IngestionService_StreamLogsServer) error {
	want := os.Getenv("AGENT_API_KEY")
	if want == "" {
		return status.Errorf(codes.NotFound, "Token not found")
	}

	md, ok := metadata.FromIncomingContext(stream.Context())
	if !ok {
		return status.Error(codes.Unauthenticated, "metadata not found")
	}

	keys := md.Get("x-agent-key")
	if len(keys) == 0 || subtle.ConstantTimeCompare([]byte(keys[0]), []byte(want)) != 1 {
		return status.Errorf(codes.Unauthenticated, "Token invalid")
	}

	for {
		packet, err := stream.Recv()
		if err == io.EOF {
			return stream.SendAndClose(&proto.Ack{Success: true})
		}

		if err != nil {
			return err
		}

		var secLog models.SecurityLog
		if err := sonic.Unmarshal(packet.PayloadJson, &secLog); err != nil {
			continue
		}

		if secLog.Timestamp.IsZero() {
			secLog.Timestamp = time.Now()
		}
		if secLog.Hostname == "" {
			secLog.Hostname = packet.AgentName
		}
		if secLog.Severity == 0 {
			secLog.Severity = 3
		}

		secLog = s.siemService.CorrelateLog(secLog)

		threat := "Normal"
		if secLog.Severity >= 12 {
			threat = "Critical"
		} else if secLog.Severity >= 7 {
			threat = "Suspicious"
		}

		s.siemService.RecordIP(secLog.SourceIP, secLog.Hostname, "Security/Access Log", threat)
		s.siemService.AddLog(secLog)

		if jsonBytes, err := sonic.Marshal(secLog); err == nil {
			if f, err := os.OpenFile(getEventsFilePath(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err == nil {
				f.Write(jsonBytes)
				f.WriteString("\n")
				f.Close()
			}
			s.siemService.Broadcast(string(jsonBytes))
		}
	}
}

func (s *GRPCServer) SendHeartbeat(ctx context.Context, req *proto.HeartbeatPacket) (*proto.Ack, error) {
	var status models.DeviceStatus
	if err := sonic.Unmarshal(req.PayloadJson, &status); err != nil {
		return &proto.Ack{Success: false}, err
	}

	status.ReceivedAt = time.Now()
	if status.AgentID == "" {
		status.AgentID = status.Hostname
	}

	s.siemService.RecordAgent(&status)
	s.siemService.RecordIP(status.SourceIP, status.Hostname, "Agent Heartbeat", "Normal")

	if jsonBytes, err := sonic.Marshal(status); err == nil {
		if f, err := os.OpenFile(getHeartbeatFilePath(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err == nil {
			f.Write(jsonBytes)
			f.WriteString("\n")
			f.Close()
		}
		s.siemService.Broadcast(string(jsonBytes))
	}
	return &proto.Ack{Success: true}, nil
}

func (s *GRPCServer) CommandStream(stream proto.IngestionService_CommandStreamServer) error {
	want := os.Getenv("AGENT_API_KEY")
	md, ok := metadata.FromIncomingContext(stream.Context())
	if !ok {
		return status.Error(codes.Unauthenticated, "Metadata context missing")
	}

	keys := md.Get("x-agent-key")
	if len(keys) == 0 || subtle.ConstantTimeCompare([]byte(keys[0]), []byte(want)) != 1 {
		return status.Errorf(codes.Unauthenticated, "token grpc not valid")
	}

	agentName := getMetaFirst(md, "x-agent-name")
	agentID := getMetaFirst(md, "x-agent-id")
	sourceIP := ""
	if p, ok := peer.FromContext(stream.Context()); ok {
		sourceIP = p.Addr.String()
		if idx := strings.LastIndex(sourceIP, ":"); idx != -1 {
			sourceIP = sourceIP[:idx]
		}
	}

	sess := &agentSession{
		agentID:   agentID,
		agentName: agentName,
		sourceIP:  sourceIP,
		sendCh:    make(chan *proto.CommandPacket, 8),
	}

	if agentID != "" {
		s.sessions.Store(strings.ToLower(agentID), sess)
	}

	if agentName != "" {
		s.sessions.Store(strings.ToLower(agentName), sess)
	}

	if sourceIP != "" {
		s.sessions.Store(strings.ToLower(sourceIP), sess)
	}

	log.Printf("[grpc-c2] Agen connected to Reverse Command Tunnel: id=%s name=%s ip=%s", agentID, agentName, sourceIP)

	defer func() {
		if agentID != "" {
			s.sessions.Delete(strings.ToLower(agentID))
		}
		if agentName != "" {
			s.sessions.Delete(strings.ToLower(sess.agentName))
		}
		if sourceIP != "" {
			s.sessions.Delete(strings.ToLower(sourceIP))
		}
		log.Printf("[grpc-c2] Agen terputus dari Reverse Command Tunnel: id=%s name=%s", agentID, agentName)
	}()

	ctx := stream.Context()
	pingTicker := time.NewTicker(25 * time.Second)
	defer pingTicker.Stop()

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-pingTicker.C:
				_ = stream.Send(&proto.CommandPacket{
					CommandId:   "PING",
					Timestamp:   time.Now().Unix(),
					PayloadJson: []byte(`{"command_key":"ping"}`),
				})
			case pkt, ok := <-sess.sendCh:
				if !ok {
					return
				}
				if err := stream.Send(pkt); err != nil {
					return
				}
			}
		}
	}()

	for {
		res, err := stream.Recv()
		if err != nil {
			return err
		}

		if val, found := s.pendingWaiters.LoadAndDelete(res.CommandId); found {
			waiter := val.(*commandWaiter)
			select {
			case waiter.resultCh <- res:
			default:
			}
		}
	}
}

func (s *GRPCServer) ExecuteCommandViaGRPC(targetID, cmdKey string, timeout time.Duration) (string, int, error) {
	val, ok := s.sessions.Load(strings.ToLower(strings.TrimSpace(targetID)))
	if !ok {
		return "", -1, fmt.Errorf("Agent %q not connected yet to grpc reverse tunnel", targetID)
	}
	sess := val.(*agentSession)

	SecretKey := os.Getenv("AGENT_API_KEY")
	if SecretKey == "" {
		return "", -1, errors.New("AGENT_API_KEY belum dikonfigurasi di server")
	}

	payloadMap := map[string]string{"command_key": cmdKey}
	payloadBytes, err := sonic.Marshal(payloadMap)
	if err != nil {
		return "", -1, fmt.Errorf("gagal marshal payload: %w", err)
	}

	cmdID := uuid.NewString()
	nowTs := time.Now().Unix()
	sig := services.GenerateHMAC(SecretKey, payloadBytes, nowTs)

	cmdPkt := &proto.CommandPacket{
		CommandId:   cmdID,
		Timestamp:   nowTs,
		Signature:   sig,
		PayloadJson: payloadBytes,
	}

	waiter := &commandWaiter{resultCh: make(chan *proto.CommandResultPacket, 1)}
	s.pendingWaiters.Store(cmdID, waiter)
	defer s.pendingWaiters.Delete(cmdID)

	select {
	case sess.sendCh <- cmdPkt:
	default:
		return "", -1, errors.New("queue command agent full")
	}

	select {
	case res := <-waiter.resultCh:
		var outMap map[string]string
		_ = sonic.Unmarshal(res.PayloadJson, &outMap)
		stdout := outMap["output"]
		if stdout == "" {
			stdout = string(res.PayloadJson)
		}

		return stdout, int(res.ExitCode), nil

	case <-time.After(timeout):
		return "", -1, fmt.Errorf("timeout (%v) menunggu respon eksekusi gRPC dari agen", timeout)
	}
}

func getMetaFirst(md metadata.MD, key string) string {
	vals := md.Get(key)
	if len(vals) > 0 {
		return strings.TrimSpace(vals[0])
	}
	return ""
}
