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

func Run(_ context.Context, wg *sync.WaitGroup, address string, scriptFile string) {
	defer wg.Done()

	connectMiddleware := func(ctx context.Context, writer io.Writer, request *socks5.Request) error {
		src := request.RemoteAddr
		dst := request.DestAddr.FQDN
		verdict, err := callLuaHook(src.String(), dst, scriptFile)
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
func callLuaHook(source, dest, scriptFile string) (string, error) {
	L := lua.NewState()
	defer L.Close()

	// Load the script
	if err := L.DoFile(scriptFile); err != nil {
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
