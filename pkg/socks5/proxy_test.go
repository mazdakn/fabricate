package socks5

import (
	"bytes"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	luaHooks "github.com/mazdakn/fabricate/pkg/lua"
	gosocks5 "github.com/things-go/go-socks5"
	"github.com/things-go/go-socks5/statute"
)

type closeBuffer struct {
	bytes.Buffer
	closed bool
}

func (b *closeBuffer) CloseWrite() error {
	b.closed = true
	return nil
}

type stubAddr struct {
	network string
	address string
}

func (a stubAddr) Network() string {
	return a.network
}

func (a stubAddr) String() string {
	return a.address
}

func TestProxyWithPacketHook(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	scriptPath := filepath.Join(dir, "hooks.lua")
	script := `
function on_packet_write(ctx)
	return string.upper(ctx.data)
end
`
	if err := os.WriteFile(scriptPath, []byte(script), 0o600); err != nil {
		t.Fatalf("write script: %v", err)
	}

	runner, err := luaHooks.NewHookRunner(scriptPath)
	if err != nil {
		t.Fatalf("new hook runner: %v", err)
	}
	defer runner.Close()

	var dst closeBuffer
	if err := proxyWithPacketHook(&dst, bytes.NewBufferString("hello"), runner, luaHooks.ConnectContext{}, "client_to_remote"); err != nil {
		t.Fatalf("proxy with packet hook: %v", err)
	}

	if got := dst.String(); got != "HELLO" {
		t.Fatalf("unexpected proxied payload: %q", got)
	}
	if !dst.closed {
		t.Fatalf("expected close write to be called")
	}
}

func TestNewConnectContextWithIPDestinationAndAuth(t *testing.T) {
	request := &gosocks5.Request{
		Request:    statute.Request{Command: statute.CommandConnect},
		RemoteAddr: net.TCPAddrFromAddrPort(netip.MustParseAddrPort("203.0.113.10:54321")),
		DestAddr: &statute.AddrSpec{
			IP:   netip.MustParseAddr("198.51.100.22").AsSlice(),
			Port: 443,
		},
		AuthContext: &gosocks5.AuthContext{
			Method: statute.MethodUserPassAuth,
			Payload: map[string]string{
				"username": "alice",
				"password": "secret",
			},
		},
	}

	ctx := newConnectContext(request)

	if ctx.Protocol != "socks5" {
		t.Fatalf("expected protocol %q, got %q", "socks5", ctx.Protocol)
	}
	if ctx.SourceIP != "203.0.113.10" {
		t.Fatalf("expected source IP %q, got %q", "203.0.113.10", ctx.SourceIP)
	}
	if ctx.SourcePort != 54321 {
		t.Fatalf("expected source port %d, got %d", 54321, ctx.SourcePort)
	}
	if ctx.DestinationIP != "198.51.100.22" {
		t.Fatalf("expected destination IP %q, got %q", "198.51.100.22", ctx.DestinationIP)
	}
	if ctx.DestinationPort != 443 {
		t.Fatalf("expected destination port %d, got %d", 443, ctx.DestinationPort)
	}
	if ctx.Command != statute.CommandConnect {
		t.Fatalf("expected command %d, got %d", statute.CommandConnect, ctx.Command)
	}
	if ctx.AuthMethod != statute.MethodUserPassAuth {
		t.Fatalf("expected auth method %d, got %d", statute.MethodUserPassAuth, ctx.AuthMethod)
	}
	if ctx.AuthUsername != "alice" {
		t.Fatalf("expected auth username %q, got %q", "alice", ctx.AuthUsername)
	}
	if ctx.AuthPassword != "secret" {
		t.Fatalf("expected auth password %q, got %q", "secret", ctx.AuthPassword)
	}
}

func TestNewConnectContextWithFQDNAndUnparsableSourceAddress(t *testing.T) {
	request := &gosocks5.Request{
		Request: statute.Request{Command: statute.CommandBind},
		RemoteAddr: stubAddr{
			network: "tcp",
			address: "not-a-host-port",
		},
		DestAddr: &statute.AddrSpec{
			FQDN: "example.com",
			Port: 1080,
		},
		AuthContext: &gosocks5.AuthContext{
			Method: statute.MethodUserPassAuth,
			Payload: map[string]string{
				"username": "bob",
			},
		},
	}

	ctx := newConnectContext(request)

	if ctx.Protocol != "socks5" {
		t.Fatalf("expected protocol %q, got %q", "socks5", ctx.Protocol)
	}
	if ctx.SourceIP != "" {
		t.Fatalf("expected empty source IP for unparsable source address, got %q", ctx.SourceIP)
	}
	if ctx.SourcePort != 0 {
		t.Fatalf("expected source port 0 for unparsable source address, got %d", ctx.SourcePort)
	}
	if ctx.DestinationFQDN != "example.com" {
		t.Fatalf("expected destination FQDN %q, got %q", "example.com", ctx.DestinationFQDN)
	}
	if ctx.DestinationPort != 1080 {
		t.Fatalf("expected destination port %d, got %d", 1080, ctx.DestinationPort)
	}
	if ctx.Command != statute.CommandBind {
		t.Fatalf("expected command %d, got %d", statute.CommandBind, ctx.Command)
	}
	if ctx.AuthMethod != statute.MethodUserPassAuth {
		t.Fatalf("expected auth method %d, got %d", statute.MethodUserPassAuth, ctx.AuthMethod)
	}
	if ctx.AuthUsername != "bob" {
		t.Fatalf("expected auth username %q, got %q", "bob", ctx.AuthUsername)
	}
	if ctx.AuthPassword != "" {
		t.Fatalf("expected empty auth password when missing from payload, got %q", ctx.AuthPassword)
	}
}
