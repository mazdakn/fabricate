package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"sync"

	"github.com/mazdakn/fabricate/pkg/socks5"
)

func main() {
	localAddress := flag.String("local", "127.0.0.1:9999", "listening address")
	luaScript := flag.String("script", "", "lua script file")
	flag.Parse()

	if localAddress == nil {
		slog.Error("No address provided")
		os.Exit(1)
	}

	defer shutdown()

	ctx := context.Background()
	var wg sync.WaitGroup

	wg.Add(1)
	go socks5.Run(ctx, &wg, *localAddress, *luaScript)

	wg.Wait()
}

func shutdown() {
	slog.Info("Shutting down")
	os.Exit(0)
}
