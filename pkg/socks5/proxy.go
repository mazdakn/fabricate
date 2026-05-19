package socks5

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"sync"

	"github.com/things-go/go-socks5"
	lua "github.com/yuin/gopher-lua"
)

// ConnectContext holds all contextual information for an incoming CONNECT request
// and is passed to the Lua hook as a table.
type ConnectContext struct {
	// SourceIP is the IP address of the client.
	SourceIP string
	// SourcePort is the port number of the client.
	SourcePort int
	// DestinationFQDN is the domain name requested by the client, if any.
	DestinationFQDN string
	// DestinationIP is the resolved IP of the destination, if any.
	DestinationIP string
	// DestinationPort is the port number of the destination.
	DestinationPort int
	// Command is the SOCKS5 command byte (1=connect, 2=bind, 3=associate).
	Command uint8
}

func newConnectContext(request *socks5.Request) ConnectContext {
	connCtx := ConnectContext{
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
	hookRunner, err := newLuaHookRunner(scriptFile)
	if err != nil {
		log.Fatalf("Failed to initialize lua script: %v", err)
	}
	defer hookRunner.Close()
	if !hookRunner.hasOnConnect {
		log.Printf("Lua hook on_connect not found in %s; skipping hook calls", scriptFile)
	}

	connectMiddleware := func(ctx context.Context, writer io.Writer, request *socks5.Request) error {
		connCtx := newConnectContext(request)
		verdict, err := hookRunner.call(connCtx)
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

type luaHookRunner struct {
	L            *lua.LState
	mu           sync.Mutex
	hasOnConnect bool
}

func newLuaHookRunner(scriptFile string) (*luaHookRunner, error) {
	L := lua.NewState()

	if err := L.DoFile(scriptFile); err != nil {
		L.Close()
		return nil, err
	}

	_, hasOnConnect := L.GetGlobal("on_connect").(*lua.LFunction)
	return &luaHookRunner{
		L:            L,
		hasOnConnect: hasOnConnect,
	}, nil
}

func (r *luaHookRunner) Close() {
	r.L.Close()
}

// call manages the Go-to-Lua communication.
func (r *luaHookRunner) call(connCtx ConnectContext) (string, error) {
	if !r.hasOnConnect {
		return "", nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	tbl := r.L.NewTable()
	r.L.SetField(tbl, "source_ip", lua.LString(connCtx.SourceIP))
	r.L.SetField(tbl, "source_port", lua.LNumber(connCtx.SourcePort))
	r.L.SetField(tbl, "destination_fqdn", lua.LString(connCtx.DestinationFQDN))
	r.L.SetField(tbl, "destination_ip", lua.LString(connCtx.DestinationIP))
	r.L.SetField(tbl, "destination_port", lua.LNumber(connCtx.DestinationPort))
	r.L.SetField(tbl, "command", lua.LNumber(connCtx.Command))

	r.L.Push(r.L.GetGlobal("on_connect"))
	r.L.Push(tbl)

	err := r.L.PCall(1, 1, nil)
	verdict := r.L.Get(-1)
	r.L.Pop(1)
	return verdict.String(), err
}
