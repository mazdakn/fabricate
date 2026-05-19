package socks5

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"sync"

	luaHooks "github.com/mazdakn/fabricate/pkg/lua"
	"github.com/things-go/go-socks5"
)

func newConnectContext(request *socks5.Request) luaHooks.ConnectContext {
	connCtx := luaHooks.ConnectContext{
		DestinationFQDN: request.DestAddr.FQDN,
		DestinationPort: request.DestAddr.Port,
		Command:         request.Command,
	}
	if request.DestAddr.IP != nil {
		connCtx.DestinationIP = request.DestAddr.IP.String()
	}
	if host, portStr, err := net.SplitHostPort(request.RemoteAddr.String()); err == nil {
		connCtx.SourceIP = host
		connCtx.SourcePort, _ = strconv.Atoi(portStr)
	}
	return connCtx
}

func Run(_ context.Context, wg *sync.WaitGroup, address string, scriptFile string) {
	defer wg.Done()

	// TODO: make using script optional
	hookRunner, err := luaHooks.NewHookRunner(scriptFile)
	if err != nil {
		log.Fatalf("Failed to initialize lua script: %v", err)
	}
	defer hookRunner.Close()
	if !hookRunner.HasOnConnect() {
		log.Printf("Lua hook on_connect not found in %s; skipping hook calls", scriptFile)
	}

	connectMiddleware := func(ctx context.Context, writer io.Writer, request *socks5.Request) error {
		connCtx := newConnectContext(request)
		verdict, err := hookRunner.CallOnConnect(connCtx)
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

	log.Printf("Fabricate SOCKS5 server listening on %s", address)
	if err := server.ListenAndServe("tcp", address); err != nil {
		log.Fatal(err)
	}
}
