function on_connect(ctx)
    print(string.format("[OnConnect] %s -> %s (fqdn=%s, ip=%s, port=%d, cmd=%d, auth=%d)",
        ctx.source, ctx.destination,
        ctx.destination_fqdn, ctx.destination_ip, ctx.destination_port,
        ctx.command, ctx.auth_method))
end
