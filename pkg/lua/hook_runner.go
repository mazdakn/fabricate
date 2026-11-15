package lua

import (
	"fmt"
	"sync"

	gopherlua "github.com/yuin/gopher-lua"
)

// ConnectContext holds all contextual information for an incoming connection/session
// and is passed to the Lua hook as a table.
type ConnectContext struct {
	// Protocol is the transport/proxy protocol (e.g. "socks5", "udp").
	Protocol string
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
	// Command is the SOCKS5 command byte (1=connect, 2=bind, 3=associate), or 0 for raw UDP.
	Command uint8
	// AuthMethod is the negotiated SOCKS5 auth method byte.
	AuthMethod uint8
	// AuthUsername is the authenticated username, when username/password auth is used.
	AuthUsername string
	// AuthPassword is the authenticated password, when username/password auth is used.
	AuthPassword string
}

// PacketWriteResult holds the outcome of an on_packet_write Lua hook invocation.
type PacketWriteResult struct {
	Data            []byte
	Drop            bool
	DestinationIP   string
	DestinationPort int
}

type HookRunner struct {
	L                *gopherlua.LState
	mu               sync.Mutex
	hasOnConnect     bool
	hasOnPacketWrite bool
}

func NewHookRunner(scriptFile string) (*HookRunner, error) {
	L := gopherlua.NewState()

	if err := L.DoFile(scriptFile); err != nil {
		L.Close()
		return nil, err
	}

	_, hasOnConnect := L.GetGlobal("on_connect").(*gopherlua.LFunction)
	_, hasOnPacketWrite := L.GetGlobal("on_packet_write").(*gopherlua.LFunction)
	return &HookRunner{
		L:                L,
		hasOnConnect:     hasOnConnect,
		hasOnPacketWrite: hasOnPacketWrite,
	}, nil
}

func (r *HookRunner) HasOnConnect() bool {
	return r.hasOnConnect
}

func (r *HookRunner) HasOnPacketWrite() bool {
	return r.hasOnPacketWrite
}

func (r *HookRunner) Close() {
	r.L.Close()
}

func (r *HookRunner) newConnectTable(connCtx ConnectContext) *gopherlua.LTable {
	tbl := r.L.NewTable()
	r.L.SetField(tbl, "protocol", gopherlua.LString(connCtx.Protocol))
	r.L.SetField(tbl, "source_ip", gopherlua.LString(connCtx.SourceIP))
	r.L.SetField(tbl, "source_port", gopherlua.LNumber(connCtx.SourcePort))
	r.L.SetField(tbl, "destination_fqdn", gopherlua.LString(connCtx.DestinationFQDN))
	r.L.SetField(tbl, "destination_ip", gopherlua.LString(connCtx.DestinationIP))
	r.L.SetField(tbl, "destination_port", gopherlua.LNumber(connCtx.DestinationPort))
	r.L.SetField(tbl, "command", gopherlua.LNumber(connCtx.Command))
	r.L.SetField(tbl, "auth_method", gopherlua.LNumber(connCtx.AuthMethod))
	r.L.SetField(tbl, "auth_username", gopherlua.LString(connCtx.AuthUsername))
	r.L.SetField(tbl, "auth_password", gopherlua.LString(connCtx.AuthPassword))
	return tbl
}

// CallOnConnect manages the Go-to-Lua communication.
func (r *HookRunner) CallOnConnect(connCtx ConnectContext) (string, error) {
	if !r.hasOnConnect {
		return "", nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	tbl := r.newConnectTable(connCtx)

	r.L.Push(r.L.GetGlobal("on_connect"))
	r.L.Push(tbl)

	err := r.L.PCall(1, 1, nil)
	verdict := r.L.Get(-1)
	r.L.Pop(1)
	return verdict.String(), err
}

// CallOnPacketWrite invokes the Lua packet write hook and allows it to rewrite bytes,
// drop the packet, or redirect the destination address.
func (r *HookRunner) CallOnPacketWrite(connCtx ConnectContext, direction string, data []byte) (PacketWriteResult, error) {
	res := PacketWriteResult{
		Data:            data,
		DestinationIP:   connCtx.DestinationIP,
		DestinationPort: connCtx.DestinationPort,
	}
	if !r.hasOnPacketWrite {
		return res, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	tbl := r.newConnectTable(connCtx)
	r.L.SetField(tbl, "direction", gopherlua.LString(direction))
	r.L.SetField(tbl, "data", gopherlua.LString(string(data)))
	r.L.SetField(tbl, "data_len", gopherlua.LNumber(len(data)))

	r.L.Push(r.L.GetGlobal("on_packet_write"))
	r.L.Push(tbl)

	err := r.L.PCall(1, 1, nil)
	result := r.L.Get(-1)
	r.L.Pop(1)
	if err != nil {
		return PacketWriteResult{}, err
	}

	if ipVal, ok := r.L.GetField(tbl, "destination_ip").(gopherlua.LString); ok {
		res.DestinationIP = string(ipVal)
	}
	if portVal, ok := r.L.GetField(tbl, "destination_port").(gopherlua.LNumber); ok {
		res.DestinationPort = int(portVal)
	}

	switch v := result.(type) {
	case *gopherlua.LNilType:
		return res, nil
	case gopherlua.LBool:
		if !bool(v) {
			res.Drop = true
		}
		return res, nil
	case gopherlua.LString:
		res.Data = []byte(string(v))
		return res, nil
	case *gopherlua.LTable:
		if b, ok := r.L.GetField(v, "drop").(gopherlua.LBool); ok && bool(b) {
			res.Drop = true
		}
		if s, ok := r.L.GetField(v, "data").(gopherlua.LString); ok {
			res.Data = []byte(string(s))
		}
		if ip, ok := r.L.GetField(v, "destination_ip").(gopherlua.LString); ok {
			res.DestinationIP = string(ip)
		}
		if port, ok := r.L.GetField(v, "destination_port").(gopherlua.LNumber); ok {
			res.DestinationPort = int(port)
		}
		return res, nil
	default:
		return PacketWriteResult{}, fmt.Errorf("on_packet_write must return string, table, boolean, or nil, got %s", result.Type().String())
	}
}
