package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/mazdakn/fabricate/pkg/socks5"
	"github.com/mazdakn/fabricate/pkg/udp"
)

func main() {
	localAddress := flag.String("local", "127.0.0.1:9999", "SOCKS5 listening address")
	udpLocalAddress := flag.String("udp-local", "", "UDP proxy listening address (e.g. 127.0.0.1:9998)")
	udpRemoteAddress := flag.String("udp-remote", "", "default upstream UDP target address (host:port)")
	udpTimeout := flag.Duration("udp-timeout", 60*time.Second, "UDP session idle timeout")
	luaScript := flag.String("script", "", "lua script file")
	flag.Parse()

	if (localAddress == nil || *localAddress == "") && (udpLocalAddress == nil || *udpLocalAddress == "") {
		slog.Error("No address provided")
		os.Exit(1)
	}

	defer shutdown()

	ctx := context.Background()
	var wg sync.WaitGroup

	if localAddress != nil && *localAddress != "" {
		wg.Add(1)
		go socks5.Run(ctx, &wg, *localAddress, *luaScript)
	}

	if udpLocalAddress != nil && *udpLocalAddress != "" {
		wg.Add(1)
		go udp.Run(ctx, &wg, *udpLocalAddress, *udpRemoteAddress, *luaScript, *udpTimeout)
	}

	wg.Wait()
}

func shutdown() {
	slog.Info("Shutting down")
	os.Exit(0)
}
