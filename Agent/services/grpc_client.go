package services

import (
	"Agent/proto"
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"strings"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

type GRPCClient struct {
	conn      *grpc.ClientConn
	client    proto.IngestionServiceClient
	logStream proto.IngestionService_StreamLogsClient
	agentName string
	agentKey  string
	streamMu  sync.Mutex
}

func isTLSServer(serverAddr string) bool {
	if strings.EqualFold(os.Getenv("GRPC_INSECURE"), "true") {
		return false
	}
	if strings.EqualFold(os.Getenv("GRPC_TLS"), "true") {
		return true
	}
	if strings.Contains(serverAddr, ":443") {
		return true
	}
	if strings.Contains(serverAddr, ":50051") ||
		strings.Contains(serverAddr, "localhost") ||
		strings.Contains(serverAddr, "127.0.0.1") ||
		strings.Contains(serverAddr, "[::1]") ||
		strings.Contains(serverAddr, "center-siem") {
		return false
	}
	return false
}

func NewGRPCClient(serverAddr, agentName, agentKey string) (*GRPCClient, error) {
	var creds credentials.TransportCredentials

	if isTLSServer(serverAddr) {
		creds = credentials.NewTLS(&tls.Config{})
	} else {
		creds = insecure.NewCredentials()
	}

	conn, err := grpc.NewClient(serverAddr, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, fmt.Errorf("failed to create gRPC client: %w", err)
	}
	client := proto.NewIngestionServiceClient(conn)

	ctx := context.Background()

	if agentKey != "" {
		ctx = metadata.AppendToOutgoingContext(ctx, "x-agent-key", agentKey)
	}

	logStream, err := client.StreamLogs(ctx)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("failed to create log stream: %w", err)
	}

	return &GRPCClient{
		conn:      conn,
		client:    client,
		logStream: logStream,
		agentName: agentName,
		agentKey:  agentKey,
	}, nil
}

func (c *GRPCClient) GetConn() *grpc.ClientConn {
	return c.conn
}

// Close menutup koneksi gRPC
func (c *GRPCClient) Close() error {
	c.streamMu.Lock()
	defer c.streamMu.Unlock()
	c.logStream = nil
	if c.conn != nil {
		err := c.conn.Close()
		c.conn = nil
		c.client = nil
		return err
	}
	return nil
}

// ReconnectStream membuat ulang stream gRPC jika terputus atau nil (thread-safe)
func (c *GRPCClient) ReconnectStream() (proto.IngestionService_StreamLogsClient, error) {
	c.streamMu.Lock()
	defer c.streamMu.Unlock()
	return c.reconnectStreamLocked()
}

func (c *GRPCClient) reconnectStreamLocked() (proto.IngestionService_StreamLogsClient, error) {
	if c.client == nil {
		return nil, fmt.Errorf("gRPC client is not initialized")
	}
	ctx := context.Background()
	if c.agentKey != "" {
		ctx = metadata.AppendToOutgoingContext(ctx, "x-agent-key", c.agentKey)
	}
	stream, err := c.client.StreamLogs(ctx)
	if err != nil {
		c.logStream = nil
		return nil, fmt.Errorf("failed to reconnect log stream: %w", err)
	}
	c.logStream = stream
	return stream, nil
}

// GetLogStream mengambil logStream secara thread-safe
func (c *GRPCClient) GetLogStream() proto.IngestionService_StreamLogsClient {
	c.streamMu.Lock()
	defer c.streamMu.Unlock()
	return c.logStream
}

// SendLog mengirim paket log ke stream gRPC dengan auto-reconnect jika stream rusak/terputus
func (c *GRPCClient) SendLog(pkt *proto.LogPacket) error {
	c.streamMu.Lock()
	defer c.streamMu.Unlock()

	if c.logStream == nil {
		if _, err := c.reconnectStreamLocked(); err != nil {
			return err
		}
	}

	err := c.logStream.Send(pkt)
	if err != nil {
		// Log stream terputus, coba reconnect 1x dan retry kirim
		c.logStream = nil
		if _, recErr := c.reconnectStreamLocked(); recErr == nil {
			if retryErr := c.logStream.Send(pkt); retryErr == nil {
				return nil
			} else {
				c.logStream = nil
				return fmt.Errorf("gRPC log stream retry send failed: %w", retryErr)
			}
		}
		return fmt.Errorf("gRPC log stream send failed: %w", err)
	}

	return nil
}
