package services

import (
	"Agent/proto"
	"context"
	"crypto/tls"
	"fmt"
	"strings"

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
}

func NewGRPCClient(serverAddr, agentName, agentKey string) (*GRPCClient, error) {
	var creds credentials.TransportCredentials

	if strings.Contains(serverAddr, ":443") || !strings.Contains(serverAddr, "localhost") {
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
		return nil, fmt.Errorf("failed to create log stream: %w", err)
	}

	return &GRPCClient{
		conn:      conn,
		client:    client,
		logStream: logStream,
		agentName: agentName,
	}, nil
}

func (c *GRPCClient) GetConn() *grpc.ClientConn {
	return c.conn
}
