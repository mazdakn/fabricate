package socks5

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strings"

	luaHooks "github.com/mazdakn/fabricate/pkg/lua"
	gosocks5 "github.com/things-go/go-socks5"
	"github.com/things-go/go-socks5/statute"
)

const proxyBufferSize = 32 * 1024

func newConnectContext(request *gosocks5.Request) luaHooks.ConnectContext {
	connCtx := luaHooks.ConnectContext{
		Protocol:        "socks5",
		DestinationFQDN: request.DestAddr.FQDN,
		DestinationPort: request.DestAddr.Port,
		Command:         request.Command,
	}
	if addr, ok := netip.AddrFromSlice(request.DestAddr.IP); ok {
		connCtx.DestinationIP = addr.Unmap().String()
	}
	if addrPort, err := netip.ParseAddrPort(request.RemoteAddr.String()); err == nil {
		connCtx.SourceIP = addrPort.Addr().Unmap().String()
		connCtx.SourcePort = int(addrPort.Port())
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

type closeWriter interface {
	CloseWrite() error
}

func writeAll(dst io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := dst.Write(data)
		if err != nil {
			return err
		}
		data = data[n:]
	}
	return nil
}

func proxyWithPacketHook(dst io.Writer, src io.Reader, hookRunner *luaHooks.HookRunner, connCtx luaHooks.ConnectContext, direction string) error {
	if tcpConn, ok := dst.(closeWriter); ok {
		defer tcpConn.CloseWrite() //nolint: errcheck
	}

	buf := make([]byte, proxyBufferSize)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			payload := buf[:n]
			if hookRunner != nil && hookRunner.HasOnPacketWrite() {
				res, err := hookRunner.CallOnPacketWrite(connCtx, direction, payload)
				if err != nil {
					return err
				}
				if res.Drop {
					continue
				}
				payload = res.Data
			}
			if err := writeAll(dst, payload); err != nil {
				return err
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

func handleConnectWithPacketHook(ctx context.Context, writer io.Writer, request *gosocks5.Request, hookRunner *luaHooks.HookRunner) error {
	dialer := &net.Dialer{}
	target, err := dialer.DialContext(ctx, "tcp", request.DestAddr.String())
	if err != nil {
		msg := err.Error()
		resp := statute.RepHostUnreachable
		if strings.Contains(msg, "refused") {
			resp = statute.RepConnectionRefused
		} else if strings.Contains(msg, "network is unreachable") {
			resp = statute.RepNetworkUnreachable
		}
		if err := gosocks5.SendReply(writer, resp, nil); err != nil {
			return fmt.Errorf("failed to send reply, %v", err)
		}
		return fmt.Errorf("connect to %v failed, %v", request.RawDestAddr, err)
	}
	defer target.Close() //nolint: errcheck

	if err := gosocks5.SendReply(writer, statute.RepSuccess, target.LocalAddr()); err != nil {
		return fmt.Errorf("failed to send reply, %v", err)
	}

	connCtx := newConnectContext(request)
	errCh := make(chan error, 2)
	go func() { errCh <- proxyWithPacketHook(target, request.Reader, hookRunner, connCtx, "client_to_remote") }()
	go func() { errCh <- proxyWithPacketHook(writer, target, hookRunner, connCtx, "remote_to_client") }()

	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			return err
		}
	}
	return nil
}

func Run(_ context.Context, address string, scriptFile string) {
	var hookRunner *luaHooks.HookRunner
	if scriptFile != "" {
		var err error
		hookRunner, err = luaHooks.NewHookRunner(scriptFile)
		if err != nil {
			slog.Error("Failed to initialize lua script", "err", err)
			os.Exit(1)
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
			slog.Error("Failed to run lua script", "err", err)
			return err
		}

		slog.Info("Verdict", "verdict", verdict)
		if verdict == "DROP" {
			return fmt.Errorf("forbidden request")
		}
		return nil
	}

	var opts []gosocks5.Option
	if hookRunner != nil && hookRunner.HasOnConnect() {
		slog.Info("Found Lua hook on_connect", "script", scriptFile)
		opts = append(opts, gosocks5.WithConnectMiddleware(connectMiddleware))
	}
	if hookRunner != nil && hookRunner.HasOnPacketWrite() {
		slog.Info("Found Lua hook on_packet_write", "script", scriptFile)
		opts = append(opts, gosocks5.WithConnectHandle(func(ctx context.Context, writer io.Writer, request *gosocks5.Request) error {
			return handleConnectWithPacketHook(ctx, writer, request, hookRunner)
		}))
	}

	server := gosocks5.NewServer(opts...)

	slog.Info("Fabricate SOCKS5 server listening", "address", address)
	if err := server.ListenAndServe("tcp", address); err != nil {
		slog.Error("Server failed", "err", err)
		os.Exit(1)
	}
}
