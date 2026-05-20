package socks5

import (
	"net"
	"testing"

	gosocks5 "github.com/things-go/go-socks5"
	"github.com/things-go/go-socks5/statute"
)

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

func TestNewConnectContextWithIPDestinationAndAuth(t *testing.T) {
	request := &gosocks5.Request{
		Request: statute.Request{Command: statute.CommandConnect},
		RemoteAddr: &net.TCPAddr{
			IP:   net.ParseIP("203.0.113.10"),
			Port: 54321,
		},
		DestAddr: &statute.AddrSpec{
			IP:   net.ParseIP("198.51.100.22"),
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
