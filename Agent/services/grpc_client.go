package services

import (
	"Agent/proto"
	"context"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type GRPCClient struct {
	conn      *grpc.ClientConn
	client    proto.IngestionServiceClient
	logStream proto.IngestionService_StreamLogsClient
	agentName string
}

func NewGRPCClient(serverAddr, agentName string) (*GRPCClient, error) {
	conn, err := grpc.NewClient(serverAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("failed to create gRPC client: %w", err)
	}
	client := proto.NewIngestionServiceClient(conn)

	logStream, err := client.StreamLogs(context.Background())
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
