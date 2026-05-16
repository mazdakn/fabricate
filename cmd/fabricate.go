package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/things-go/go-socks5"
	lua "github.com/yuin/gopher-lua"
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

	defer shutdown()

	ctx := context.Background()
	var wg sync.WaitGroup
	wg.Add(1)
	go runServer(ctx, &wg, addr)

	wg.Add(1)
	go runSocketServer(ctx, &wg)

	wg.Wait()
}

func shutdown() {
	logrus.Info("Shutting down")
	os.Exit(0)
}

func runSocketServer(_ context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	connectMiddleware := func(ctx context.Context, writer io.Writer, request *socks5.Request) error {
		src := request.RemoteAddr
		dst := request.DestAddr.FQDN
		verdict, err := callLuaHook(src.String(), dst)
		if err != nil {
			log.Printf("Failed to run lua script: %v", err)
			return err
		}

		log.Printf("Verdict: %v", verdict)
		if verdict == "DROP" {
			return fmt.Errorf("forbidden request")
		}
		return nil
	}

	// 3. Initialize the server
	server := socks5.NewServer(
		socks5.WithConnectMiddleware(connectMiddleware),
	)

	log.Println("Fabricate SOCKS5 server listening on :1080")
	if err := server.ListenAndServe("tcp", "0.0.0.0:1080"); err != nil {
		log.Fatal(err)
	}
}

// callLuaHook manages the Go-to-Lua communication
func callLuaHook(source, dest string) (string, error) {
	L := lua.NewState()
	defer L.Close()

	// Load the script
	if err := L.DoString(luaScript); err != nil {
		return "", err
	}

	// Push arguments onto the Virtual Stack
	L.Push(L.GetGlobal("on_connect")) // Push the function
	L.Push(lua.LString(source))       // Push Arg 1
	L.Push(lua.LString(dest))         // Push Arg 2

	// Execute the Lua function (2 arguments, 1 return)
	err := L.PCall(2, 1, nil)

	verdict := L.Get(1)
	L.Pop(1)
	return verdict.String(), err
}

// luaScript defines the logic to be executed.
// In a real app, you would load this from an external .lua file.
const luaScript = `
function on_connect(source, dest)
    print(string.format("[Lua] Connection Detected! Source: %s | Destination: %s", source, dest))
	if dest == "inter.it" or dest == "www.inter.it" then
		print("Detected inter.it")
		return "DROP"
	end
end
`

func runServer(ctx context.Context, wg *sync.WaitGroup, addr *net.TCPAddr) {
	defer wg.Done() // For the listening socket

	logrus.Infof("Starting on address %v", addr)
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
		}

		wg.Add(1)
		go serveConnection(ctx, wg, conn)
	}
}

func serveConnection(ctx context.Context, wg *sync.WaitGroup, conn net.Conn) {
	defer wg.Done()
}
