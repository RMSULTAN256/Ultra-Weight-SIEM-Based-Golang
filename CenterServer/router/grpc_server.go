package router

import (
	"context"
	"io"
	"os"
	"server3/models"
	"server3/proto"
	"server3/services"
	"time"

	"github.com/bytedance/sonic"
)

type GRPCServer struct {
	proto.UnimplementedIngestionServiceServer
	siemService *services.SIEMService
}

func NewGRPCServer(siemSvc *services.SIEMService) *GRPCServer {
	return &GRPCServer{
		siemService: siemSvc,
	}
}

func (s *GRPCServer) StreamLogs(stream proto.IngestionService_StreamLogsServer) error {
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
