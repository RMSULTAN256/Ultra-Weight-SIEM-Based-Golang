package main

import (
	"fmt"
	"net"
)

type Server struct {
	listenAddress string
	ln            net.Listener
	quitch        chan struct{}
}

func NewServer(listenAddress string) *Server {
	return &Server{
		listenAddress: listenAddress,
		quitch:        make(chan struct{}),
	}
}

func (s *Server) Start() error {
	ln, err := net.Listen("tcp", s.listenAddress)
	if err != nil {
		return err
	}
	defer ln.Close()

	s.ln = ln

	go s.acceptLoop()

	fmt.Println("TCP Server berjalan di", s.listenAddress)
	<-s.quitch
	return nil
}

func (s *Server) acceptLoop() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			fmt.Println("acceprt Error:", err)
			continue
		}

		go s.readLoop(conn)
	}
}

func (s *Server) readLoop(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 2048)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			fmt.Println("Read error:", err)
			return
		}
		msg := buf[:n]
		fmt.Println("Received message:", string(msg))
	}
}

func main() {
	server := NewServer(":3000")
	err := server.Start()
	if err != nil {
		fmt.Println("Server start error:", err)
	}
}
