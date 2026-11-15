# Fabricate

Run with defaults (no Lua script):

```bash
./bin/fabricate
```

Use a custom Lua script file:

```bash
./bin/fabricate -script rules.lua
```

Run with the standalone UDP proxy enabled:

```bash
./bin/fabricate -udp-local 127.0.0.1:9998 -udp-remote 127.0.0.1:5353 -script rules.lua
```

Available Lua hooks (`ctx.protocol` is `"socks5"` or `"udp"`):

- `on_connect(ctx)` runs before a SOCKS5 `CONNECT` request or new UDP session is allowed through. Return `"DROP"` to reject the connection/session.
- `on_packet_write(ctx)` runs for proxied TCP/UDP payload writes (`ctx.direction` is `"client_to_remote"` or `"remote_to_client"`):
  - Return `nil` to keep the original bytes and destination.
  - Return a `string` to replace the payload bytes.
  - Return `false` to drop the packet/datagram.
  - Return a `table` (`{ data = "...", drop = false, destination_ip = "10.0.0.1", destination_port = 5353 }`) or mutate `ctx.destination_ip` / `ctx.destination_port` to rewrite, drop, or redirect individual UDP datagrams.
