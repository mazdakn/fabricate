package socks5

import (
	"context"
	"fmt"
	"io"
	"log"
	"sync"

	"github.com/things-go/go-socks5"
	lua "github.com/yuin/gopher-lua"
)

// ConnectContext holds all contextual information for an incoming CONNECT request
// and is passed to the Lua hook as a table.
type ConnectContext struct {
	// Source is the address of the client (host:port).
	Source string
	// Destination is the resolved destination address (host:port).
	Destination string
	// DestinationFQDN is the domain name requested by the client, if any.
	DestinationFQDN string
	// DestinationIP is the resolved IP of the destination, if any.
	DestinationIP string
	// DestinationPort is the port number of the destination.
	DestinationPort int
	// LocalAddr is the local server address that accepted the connection (host:port).
	LocalAddr string
	// Command is the SOCKS5 command byte (1=connect, 2=bind, 3=associate).
	Command uint8
	// AuthMethod is the authentication method negotiated with the client.
	AuthMethod uint8
	// AuthPayload contains additional key/value pairs provided during authentication.
	AuthPayload map[string]string
}

func newConnectContext(request *socks5.Request) ConnectContext {
	connCtx := ConnectContext{
		Source:          request.RemoteAddr.String(),
		Destination:     request.DestAddr.String(),
		DestinationFQDN: request.DestAddr.FQDN,
		DestinationPort: request.DestAddr.Port,
		Command:         request.Command,
	}
	if request.LocalAddr != nil {
		connCtx.LocalAddr = request.LocalAddr.String()
	}
	if request.DestAddr.IP != nil {
		connCtx.DestinationIP = request.DestAddr.IP.String()
	}
	if request.AuthContext != nil {
		connCtx.AuthMethod = request.AuthContext.Method
		connCtx.AuthPayload = request.AuthContext.Payload
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
	L.SetField(tbl, "source", lua.LString(connCtx.Source))
	L.SetField(tbl, "destination", lua.LString(connCtx.Destination))
	L.SetField(tbl, "destination_fqdn", lua.LString(connCtx.DestinationFQDN))
	L.SetField(tbl, "destination_ip", lua.LString(connCtx.DestinationIP))
	L.SetField(tbl, "destination_port", lua.LNumber(connCtx.DestinationPort))
	L.SetField(tbl, "local_addr", lua.LString(connCtx.LocalAddr))
	L.SetField(tbl, "command", lua.LNumber(connCtx.Command))
	L.SetField(tbl, "auth_method", lua.LNumber(connCtx.AuthMethod))
	authPayload := L.NewTable()
	for k, v := range connCtx.AuthPayload {
		L.SetField(authPayload, k, lua.LString(v))
	}
	L.SetField(tbl, "auth_payload", authPayload)

	// Push arguments onto the Virtual Stack
	L.Push(L.GetGlobal("on_connect")) // Push the function
	L.Push(tbl)                       // Push Arg 1 (ConnectContext table)

	// Execute the Lua function (1 argument, 1 return)
	err := L.PCall(1, 1, nil)

	verdict := L.Get(1)
	L.Pop(1)
	return verdict.String(), err
}
