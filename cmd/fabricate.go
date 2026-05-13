package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
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
			logrus.WithError(err).Errorf("failed to accept a connection")
		}

		wg.Add(1)
		go serveConnection(ctx, wg, conn)
	}
}

func serveConnection(ctx context.Context, wg *sync.WaitGroup, conn net.Conn) {
	defer wg.Done()
}
