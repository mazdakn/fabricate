function on_connect(ctx)
    print(string.format("[OnConnect] %s:%d -> %s:%d (fqdn=%s, cmd=%d)",
        ctx.source_ip, ctx.source_port,
        ctx.destination_ip, ctx.destination_port,
        ctx.destination_fqdn, ctx.command))
end
