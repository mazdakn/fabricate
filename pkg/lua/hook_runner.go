package lua

import (
	"sync"

	gopherlua "github.com/yuin/gopher-lua"
)

// ConnectContext holds all contextual information for an incoming CONNECT request
// and is passed to the Lua hook as a table.
type ConnectContext struct {
	// SourceIP is the IP address of the client.
	SourceIP string
	// SourcePort is the port number of the client.
	SourcePort int
	// DestinationFQDN is the domain name requested by the client, if any.
	DestinationFQDN string
	// DestinationIP is the resolved IP of the destination, if any.
	DestinationIP string
	// DestinationPort is the port number of the destination.
	DestinationPort int
	// Command is the SOCKS5 command byte (1=connect, 2=bind, 3=associate).
	Command uint8
	// AuthMethod is the negotiated SOCKS5 auth method byte.
	AuthMethod uint8
	// AuthUsername is the authenticated username, when username/password auth is used.
	AuthUsername string
}

type HookRunner struct {
	L            *gopherlua.LState
	mu           sync.Mutex
	hasOnConnect bool
}

func NewHookRunner(scriptFile string) (*HookRunner, error) {
	L := gopherlua.NewState()

	if err := L.DoFile(scriptFile); err != nil {
		L.Close()
		return nil, err
	}

	_, hasOnConnect := L.GetGlobal("on_connect").(*gopherlua.LFunction)
	return &HookRunner{
		L:            L,
		hasOnConnect: hasOnConnect,
	}, nil
}

func (r *HookRunner) HasOnConnect() bool {
	return r.hasOnConnect
}

func (r *HookRunner) Close() {
	r.L.Close()
}

// CallOnConnect manages the Go-to-Lua communication.
func (r *HookRunner) CallOnConnect(connCtx ConnectContext) (string, error) {
	if !r.hasOnConnect {
		return "", nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	tbl := r.L.NewTable()
	r.L.SetField(tbl, "source_ip", gopherlua.LString(connCtx.SourceIP))
	r.L.SetField(tbl, "source_port", gopherlua.LNumber(connCtx.SourcePort))
	r.L.SetField(tbl, "destination_fqdn", gopherlua.LString(connCtx.DestinationFQDN))
	r.L.SetField(tbl, "destination_ip", gopherlua.LString(connCtx.DestinationIP))
	r.L.SetField(tbl, "destination_port", gopherlua.LNumber(connCtx.DestinationPort))
	r.L.SetField(tbl, "command", gopherlua.LNumber(connCtx.Command))
	r.L.SetField(tbl, "auth_method", gopherlua.LNumber(connCtx.AuthMethod))
	r.L.SetField(tbl, "auth_username", gopherlua.LString(connCtx.AuthUsername))

	r.L.Push(r.L.GetGlobal("on_connect"))
	r.L.Push(tbl)

	err := r.L.PCall(1, 1, nil)
	verdict := r.L.Get(-1)
	r.L.Pop(1)
	return verdict.String(), err
}
