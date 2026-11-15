function on_connect(ctx)
    print(string.format("[OnConnect] proto=%s %s:%d -> %s:%d (fqdn=%s, cmd=%d, auth_method=%d, auth_username=%s, auth_password=%s)",
        ctx.protocol,
        ctx.source_ip, ctx.source_port,
        ctx.destination_ip, ctx.destination_port,
        ctx.destination_fqdn, ctx.command,
        ctx.auth_method, ctx.auth_username, ctx.auth_password))
end

function on_packet_write(ctx)
    print(string.format("[OnPacketWrite] proto=%s direction=%s bytes=%d", ctx.protocol, ctx.direction, ctx.data_len))
    return ctx.data
end
