package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

const (
	readBufferSize    = 4096
	connectionTimeout = time.Second
)

func main() {
	localAddress := flag.String("local", "127.0.0.1:9999", "listening address")
	flag.Parse()

	if localAddress == nil {
		fmt.Printf("No address provided")
		os.Exit(1)
	}

	addr, err := net.ResolveTCPAddr("tcp", *localAddress)
	if err != nil {
		fmt.Printf("Invalid address %s", *localAddress)
		os.Exit(1)
	}

	logrus.Infof("Starting on address %v", addr)
	defer shutdown()

	ctx := context.Background()
	var wg *sync.WaitGroup
	wg.Add(1)
	go runServer(ctx, wg, addr)

	wg.Wait()
}

func shutdown() {
	logrus.Info("Shutting down")
	os.Exit(0)
}

func runServer(ctx context.Context, wg *sync.WaitGroup, addr *net.TCPAddr) {
	defer wg.Done() // For the listening socket

	listenSocket, err := net.ListenTCP("tcp", addr)
	if err != nil {
		logrus.WithError(err).Errorf("Failed to listen to socket")
		return
	}
	defer func() {
		if err := listenSocket.Close(); err != nil {
			logrus.WithError(err).Errorf("Failed to close listening socket %v", listenSocket)
		}
	}()

	for {
		if ctx.Err() != nil {
			logrus.WithError(ctx.Err()).Infof("Context is closed")
			return
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
			continue
		}

		wg.Add(1)
		go serveConnection(ctx, wg, conn)
	}
}

func serveConnection(ctx context.Context, wg *sync.WaitGroup, conn net.Conn) {
	defer wg.Done()
	defer func() {
		if err := conn.Close(); err != nil {
			logrus.WithError(err).Errorf("Failed to close connection %v", conn.RemoteAddr())
		}
	}()

	logrus.Infof("Serving connection from %v", conn.RemoteAddr())

	buf := make([]byte, readBufferSize)
	for {
		if ctx.Err() != nil {
			return
		}

		if err := conn.SetDeadline(time.Now().Add(connectionTimeout)); err != nil {
			logrus.WithError(err).Errorf("Failed to set deadline on connection")
			return
		}

		n, err := conn.Read(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			if err != io.EOF {
				logrus.WithError(err).Errorf("Failed to read from connection %v", conn.RemoteAddr())
			}
			return
		}

		if _, err := conn.Write(buf[:n]); err != nil {
			logrus.WithError(err).Errorf("Failed to write to connection %v", conn.RemoteAddr())
			return
		}
	}
}
