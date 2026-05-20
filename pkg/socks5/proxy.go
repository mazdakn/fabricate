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
	gosocks5 "github.com/things-go/go-socks5"
)

func newConnectContext(request *gosocks5.Request) luaHooks.ConnectContext {
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
	if request.AuthContext != nil {
		connCtx.AuthMethod = request.AuthContext.Method
		if username, ok := request.AuthContext.Payload["username"]; ok {
			connCtx.AuthUsername = username
		}
		if password, ok := request.AuthContext.Payload["password"]; ok {
			connCtx.AuthPassword = password
		}
	}
	return connCtx
}

func Run(_ context.Context, wg *sync.WaitGroup, address string, scriptFile string) {
	defer wg.Done()

	var hookRunner *luaHooks.HookRunner
	if scriptFile != "" {
		var err error
		hookRunner, err = luaHooks.NewHookRunner(scriptFile)
		if err != nil {
			log.Fatalf("Failed to initialize lua script: %v", err)
		}
		defer hookRunner.Close()
	}

	connectMiddleware := func(ctx context.Context, writer io.Writer, request *gosocks5.Request) error {
		if hookRunner == nil {
			return nil
		}
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

	var opts []gosocks5.Option
	if hookRunner != nil && hookRunner.HasOnConnect() {
		log.Printf("Found Lua hook on_connect in %s", scriptFile)
		opts = append(opts, gosocks5.WithConnectMiddleware(connectMiddleware))
	}

	server := gosocks5.NewServer(opts...)

	log.Printf("Fabricate SOCKS5 server listening on %s", address)
	if err := server.ListenAndServe("tcp", address); err != nil {
		log.Fatal(err)
	}
}
