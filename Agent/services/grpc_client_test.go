package services

import (
	"Agent/proto"
	"io"
	"net"
	"sync"
	"testing"

	"google.golang.org/grpc"
)

type mockIngestionServer struct {
	proto.UnimplementedIngestionServiceServer
	mu       sync.Mutex
	received []*proto.LogPacket
}

func (s *mockIngestionServer) StreamLogs(stream proto.IngestionService_StreamLogsServer) error {
	for {
		pkt, err := stream.Recv()
		if err == io.EOF {
			return stream.SendAndClose(&proto.Ack{Success: true})
		}
		if err != nil {
			return err
		}
		s.mu.Lock()
		s.received = append(s.received, pkt)
		s.mu.Unlock()
	}
}

func TestGRPCClient_LifecycleAndSend(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer lis.Close()

	srv := grpc.NewServer()
	mockSrv := &mockIngestionServer{}
	proto.RegisterIngestionServiceServer(srv, mockSrv)

	go func() {
		_ = srv.Serve(lis)
	}()
	defer srv.Stop()

	client, err := NewGRPCClient(lis.Addr().String(), "agent-uji", "kunci")
	if err != nil {
		t.Fatalf("NewGRPCClient gagal: %v", err)
	}
	defer client.Close()

	pkt := &proto.LogPacket{
		AgentName:   "agent-uji",
		PayloadJson: []byte(`{"message":"halo grpc"}`),
	}

	if err := client.SendLog(pkt); err != nil {
		t.Fatalf("SendLog gagal: %v", err)
	}

	// Test ReconnectStream
	stream, err := client.ReconnectStream()
	if err != nil {
		t.Fatalf("ReconnectStream gagal: %v", err)
	}
	if stream == nil {
		t.Fatal("stream hasil reconnect nil")
	}

	if client.GetLogStream() == nil {
		t.Fatal("GetLogStream seharusnya tidak nil")
	}

	if client.GetConn() == nil {
		t.Fatal("GetConn seharusnya tidak nil")
	}

	// Test auto-reconnect saat logStream sengaja di-nil kan
	client.streamMu.Lock()
	client.logStream = nil
	client.streamMu.Unlock()

	if err := client.SendLog(pkt); err != nil {
		t.Fatalf("SendLog gagal auto-reconnect saat logStream nil: %v", err)
	}

	// Test Close
	if err := client.Close(); err != nil {
		t.Fatalf("Close gagal: %v", err)
	}
	if client.GetConn() != nil {
		t.Fatal("GetConn seharusnya nil setelah Close")
	}
	if err := client.SendLog(pkt); err == nil {
		t.Fatal("SendLog seharusnya mengembalikan error setelah client ditutup")
	}
}

func TestIsTLSServer(t *testing.T) {
	cases := []struct {
		addr     string
		envKey   string
		envVal   string
		expected bool
	}{
		{addr: "gowaz.vulnstack.xyz:443", expected: true},
		{addr: "center-siem:50051", expected: false},
		{addr: "127.0.0.1:50051", expected: false},
		{addr: "localhost:50051", expected: false},
		{addr: "[::1]:50051", expected: false},
		{addr: "gowaz.vulnstack.xyz:443", envKey: "GRPC_INSECURE", envVal: "true", expected: false},
		{addr: "center-siem:50051", envKey: "GRPC_TLS", envVal: "true", expected: true},
	}

	for _, tc := range cases {
		t.Setenv("GRPC_INSECURE", "")
		t.Setenv("GRPC_TLS", "")
		if tc.envKey != "" {
			t.Setenv(tc.envKey, tc.envVal)
		}
		got := isTLSServer(tc.addr)
		if got != tc.expected {
			t.Errorf("isTLSServer(%q) [env %s=%s]: dapat %v, mau %v", tc.addr, tc.envKey, tc.envVal, got, tc.expected)
		}
	}
}

func TestNewGRPCClient_StreamLogsFailClosesConn(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer lis.Close()

	go func() {
		for {
			c, err := lis.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	// Port :443 memicu NewTLS yang akan gagal handshake dengan plain TCP listener
	_, err = NewGRPCClient(lis.Addr().String()+":443", "agent-uji", "kunci")
	if err == nil {
		t.Fatal("seharusnya gagal membuat log stream dan mengembalikan error")
	}
}
