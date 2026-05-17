package tcp

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

func RunServer(ctx context.Context, wg *sync.WaitGroup, address string) error {
	defer wg.Done() // For the listening socket

	addr, err := net.ResolveTCPAddr("tcp", address)
	if err != nil {
		return fmt.Errorf("invalid address %s", address)
	}

	logrus.Infof("Starting on address %v", addr)
	listenSocket, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen to socket: %w", err)
	}
	defer func() {
		if listenSocket == nil {
			return
		}
		if err := listenSocket.Close(); err != nil {
			logrus.WithError(err).Errorf("Failed to close listening socket %v", listenSocket)
		}
	}()

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		deadline := time.Now().Add(time.Second)
		if err := listenSocket.SetDeadline(deadline); err != nil {
			logrus.WithError(err).Errorf("Failed to set deadline")
		}

		conn, err := listenSocket.Accept()
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}

			logrus.WithError(err).Errorf("failed to accept a connection")
		}

		wg.Add(1)
		go serveConnection(ctx, wg, conn)
	}
}

func serveConnection(ctx context.Context, wg *sync.WaitGroup, conn net.Conn) {
	defer wg.Done()
}
