package udp

import (
	"context"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	luaHooks "github.com/mazdakn/fabricate/pkg/lua"
)

func startUDPEchoServer(t *testing.T, prefix string) (*net.UDPConn, netip.AddrPort) {
	t.Helper()
	conn, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:0")))
	if err != nil {
		t.Fatalf("listen echo udp: %v", err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
	})

	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := conn.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			reply := append([]byte(prefix), buf[:n]...)
			_, _ = conn.WriteToUDPAddrPort(reply, addr)
		}
	}()

	return conn, conn.LocalAddr().(*net.UDPAddr).AddrPort()
}

func startUDPProxy(t *testing.T, remoteAddr string, script string) netip.AddrPort {
	t.Helper()

	var runner *luaHooks.HookRunner
	if script != "" {
		dir := t.TempDir()
		scriptPath := filepath.Join(dir, "hooks.lua")
		if err := os.WriteFile(scriptPath, []byte(script), 0o600); err != nil {
			t.Fatalf("write script: %v", err)
		}
		var err error
		runner, err = luaHooks.NewHookRunner(scriptPath)
		if err != nil {
			t.Fatalf("new hook runner: %v", err)
		}
		t.Cleanup(func() {
			runner.Close()
		})
	}

	listener, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:0")))
	if err != nil {
		t.Fatalf("listen proxy udp: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = Serve(ctx, listener, remoteAddr, runner, 2*time.Second)
	}()

	t.Cleanup(func() {
		cancel()
		_ = listener.Close()
		<-done
	})

	return listener.LocalAddr().(*net.UDPAddr).AddrPort()
}

func TestUDPProxyRewriteAndEcho(t *testing.T) {
	t.Parallel()

	_, echoAddr := startUDPEchoServer(t, "echo:")
	script := `
function on_connect(ctx)
	if ctx.protocol ~= "udp" then
		return "DROP"
	end
	return "ALLOW"
end

function on_packet_write(ctx)
	if ctx.direction == "client_to_remote" then
		return string.upper(ctx.data)
	end
	if ctx.direction == "remote_to_client" then
		return ctx.data .. "!"
	end
	return nil
end
`
	proxyAddr := startUDPProxy(t, echoAddr.String(), script)

	client, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(proxyAddr))
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer client.Close()

	if _, err := client.Write([]byte("hello")); err != nil {
		t.Fatalf("write to proxy: %v", err)
	}

	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1024)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("read from proxy: %v", err)
	}

	if got := string(buf[:n]); got != "echo:HELLO!" {
		t.Fatalf("unexpected UDP reply: got %q, want %q", got, "echo:HELLO!")
	}
}

func TestUDPProxyOnConnectDrop(t *testing.T) {
	t.Parallel()

	_, echoAddr := startUDPEchoServer(t, "echo:")
	script := `
function on_connect(ctx)
	return "DROP"
end
`
	proxyAddr := startUDPProxy(t, echoAddr.String(), script)

	client, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(proxyAddr))
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer client.Close()

	if _, err := client.Write([]byte("blocked")); err != nil {
		t.Fatalf("write to proxy: %v", err)
	}

	_ = client.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	buf := make([]byte, 1024)
	if _, err := client.Read(buf); err == nil {
		t.Fatalf("expected timeout when session is dropped by on_connect")
	}
}

func TestUDPProxyDropAndRedirectPerDatagram(t *testing.T) {
	t.Parallel()

	_, primaryAddr := startUDPEchoServer(t, "primary:")
	_, altAddr := startUDPEchoServer(t, "alt:")

	script := `
function on_packet_write(ctx)
	if ctx.direction == "client_to_remote" then
		if ctx.data == "dropme" then
			return false
		end
		if ctx.data == "reroute" then
			return {
				data = "rerouted",
				destination_ip = "` + altAddr.Addr().Unmap().String() + `",
				destination_port = ` + strconv.Itoa(int(altAddr.Port())) + `,
			}
		end
	end
	return nil
end
`
	proxyAddr := startUDPProxy(t, primaryAddr.String(), script)

	client, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(proxyAddr))
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer client.Close()

	// 1. Send dropped datagram, followed by normal datagram
	if _, err := client.Write([]byte("dropme")); err != nil {
		t.Fatalf("write dropme: %v", err)
	}
	if _, err := client.Write([]byte("normal")); err != nil {
		t.Fatalf("write normal: %v", err)
	}

	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1024)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("read normal reply: %v", err)
	}
	if got := string(buf[:n]); got != "primary:normal" {
		t.Fatalf("unexpected reply: got %q, want %q", got, "primary:normal")
	}

	// 2. Send redirected datagram to alternate upstream server
	if _, err := client.Write([]byte("reroute")); err != nil {
		t.Fatalf("write reroute: %v", err)
	}
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err = client.Read(buf)
	if err != nil {
		t.Fatalf("read rerouted reply: %v", err)
	}
	if got := string(buf[:n]); got != "alt:rerouted" {
		t.Fatalf("unexpected redirected reply: got %q, want %q", got, "alt:rerouted")
	}
}
