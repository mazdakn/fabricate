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

// ConnectContext holds the contextual information for an incoming CONNECT request
// and is passed to the Lua hook as a table.
type ConnectContext struct {
	Source      string
	Destination string
}

func Run(_ context.Context, wg *sync.WaitGroup, address string, scriptFile string) {
	defer wg.Done()

	connectMiddleware := func(ctx context.Context, writer io.Writer, request *socks5.Request) error {
		connCtx := ConnectContext{
			Source:      request.RemoteAddr.String(),
			Destination: request.DestAddr.FQDN,
		}
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

	// Push arguments onto the Virtual Stack
	L.Push(L.GetGlobal("on_connect")) // Push the function
	L.Push(tbl)                       // Push Arg 1 (ConnectContext table)

	// Execute the Lua function (1 argument, 1 return)
	err := L.PCall(1, 1, nil)

	verdict := L.Get(1)
	L.Pop(1)
	return verdict.String(), err
}
