package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"sync"

	"github.com/mazdakn/fabricate/pkg/socks5"
	"github.com/sirupsen/logrus"
)

func main() {
	localAddress := flag.String("local", "127.0.0.1:9999", "listening address")
	luaScript := flag.String("script", "main.lua", "lua script file")
	flag.Parse()

	if localAddress == nil {
		fmt.Printf("No address provided")
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
	logrus.Info("Shutting down")
	os.Exit(0)
}
