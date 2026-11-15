package lua

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCallOnPacketWrite(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	scriptPath := filepath.Join(dir, "hooks.lua")
	script := `
function on_connect(ctx)
	return "ALLOW"
end

function on_packet_write(ctx)
	if ctx.direction == "client_to_remote" then
		return string.upper(ctx.data)
	end
	return nil
end
`
	if err := os.WriteFile(scriptPath, []byte(script), 0o600); err != nil {
		t.Fatalf("write script: %v", err)
	}

	runner, err := NewHookRunner(scriptPath)
	if err != nil {
		t.Fatalf("new hook runner: %v", err)
	}
	defer runner.Close()

	if !runner.HasOnConnect() {
		t.Fatalf("expected on_connect hook to be detected")
	}
	if !runner.HasOnPacketWrite() {
		t.Fatalf("expected on_packet_write hook to be detected")
	}

	verdict, err := runner.CallOnConnect(ConnectContext{})
	if err != nil {
		t.Fatalf("call on_connect: %v", err)
	}
	if verdict != "ALLOW" {
		t.Fatalf("unexpected verdict: %q", verdict)
	}

	rewritten, err := runner.CallOnPacketWrite(ConnectContext{Protocol: "socks5"}, "client_to_remote", []byte("hello"))
	if err != nil {
		t.Fatalf("call on_packet_write rewrite: %v", err)
	}
	if string(rewritten.Data) != "HELLO" {
		t.Fatalf("unexpected rewritten payload: %q", string(rewritten.Data))
	}
	if rewritten.Drop {
		t.Fatalf("did not expect packet to be dropped")
	}

	unchanged, err := runner.CallOnPacketWrite(ConnectContext{Protocol: "socks5"}, "remote_to_client", []byte("hello"))
	if err != nil {
		t.Fatalf("call on_packet_write passthrough: %v", err)
	}
	if string(unchanged.Data) != "hello" {
		t.Fatalf("unexpected passthrough payload: %q", string(unchanged.Data))
	}
}

func TestCallOnPacketWriteDropAndRedirect(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	scriptPath := filepath.Join(dir, "hooks.lua")
	script := `
function on_packet_write(ctx)
	if ctx.data == "drop-bool" then
		return false
	end
	if ctx.data == "drop-table" then
		return { drop = true }
	end
	if ctx.data == "redirect-table" then
		return {
			data = "redirected",
			destination_ip = "10.0.0.99",
			destination_port = 5353,
		}
	end
	if ctx.data == "redirect-ctx" then
		ctx.destination_ip = "10.0.0.42"
		ctx.destination_port = 9000
		return "mutated"
	end
	return nil
end
`
	if err := os.WriteFile(scriptPath, []byte(script), 0o600); err != nil {
		t.Fatalf("write script: %v", err)
	}

	runner, err := NewHookRunner(scriptPath)
	if err != nil {
		t.Fatalf("new hook runner: %v", err)
	}
	defer runner.Close()

	baseCtx := ConnectContext{
		Protocol:        "udp",
		DestinationIP:   "127.0.0.1",
		DestinationPort: 8080,
	}

	res, err := runner.CallOnPacketWrite(baseCtx, "client_to_remote", []byte("drop-bool"))
	if err != nil {
		t.Fatalf("drop-bool: %v", err)
	}
	if !res.Drop {
		t.Fatalf("expected drop-bool to set Drop=true")
	}

	res, err = runner.CallOnPacketWrite(baseCtx, "client_to_remote", []byte("drop-table"))
	if err != nil {
		t.Fatalf("drop-table: %v", err)
	}
	if !res.Drop {
		t.Fatalf("expected drop-table to set Drop=true")
	}

	res, err = runner.CallOnPacketWrite(baseCtx, "client_to_remote", []byte("redirect-table"))
	if err != nil {
		t.Fatalf("redirect-table: %v", err)
	}
	if res.Drop || string(res.Data) != "redirected" || res.DestinationIP != "10.0.0.99" || res.DestinationPort != 5353 {
		t.Fatalf("unexpected redirect-table result: %+v", res)
	}

	res, err = runner.CallOnPacketWrite(baseCtx, "client_to_remote", []byte("redirect-ctx"))
	if err != nil {
		t.Fatalf("redirect-ctx: %v", err)
	}
	if res.Drop || string(res.Data) != "mutated" || res.DestinationIP != "10.0.0.42" || res.DestinationPort != 9000 {
		t.Fatalf("unexpected redirect-ctx result: %+v", res)
	}
}

func TestCallOnPacketWriteRejectsInvalidReturnType(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	scriptPath := filepath.Join(dir, "hooks.lua")
	script := `
function on_packet_write(ctx)
	return 123
end
`
	if err := os.WriteFile(scriptPath, []byte(script), 0o600); err != nil {
		t.Fatalf("write script: %v", err)
	}

	runner, err := NewHookRunner(scriptPath)
	if err != nil {
		t.Fatalf("new hook runner: %v", err)
	}
	defer runner.Close()

	if _, err := runner.CallOnPacketWrite(ConnectContext{}, "client_to_remote", []byte("hello")); err == nil {
		t.Fatalf("expected invalid return type error")
	}
}
