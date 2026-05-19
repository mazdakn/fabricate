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

	connectMiddleware := func(ctx context.Context, writer io.Writer, request *socks5.Request) error {
		connCtx := newConnectContext(request)
		verdict, err := callLuaHook(connCtx, scriptFile)
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

// callLuaHook manages the Go-to-Lua communication
func callLuaHook(connCtx ConnectContext, scriptFile string) (string, error) {
	L := lua.NewState()
	defer L.Close()

	// Load the script
	if err := L.DoFile(scriptFile); err != nil {
		return "", err
	}

	// Build a Lua table from ConnectContext and push it as the single argument
	tbl := L.NewTable()
	L.SetField(tbl, "source_ip", lua.LString(connCtx.SourceIP))
	L.SetField(tbl, "source_port", lua.LNumber(connCtx.SourcePort))
	L.SetField(tbl, "destination_fqdn", lua.LString(connCtx.DestinationFQDN))
	L.SetField(tbl, "destination_ip", lua.LString(connCtx.DestinationIP))
	L.SetField(tbl, "destination_port", lua.LNumber(connCtx.DestinationPort))
	L.SetField(tbl, "command", lua.LNumber(connCtx.Command))

	// Push arguments onto the Virtual Stack
	L.Push(L.GetGlobal("on_connect")) // Push the function
	L.Push(tbl)                       // Push Arg 1 (ConnectContext table)

	// Execute the Lua function (1 argument, 1 return)
	err := L.PCall(1, 1, nil)

	verdict := L.Get(1)
	L.Pop(1)
	return verdict.String(), err
}
