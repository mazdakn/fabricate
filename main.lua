function on_connect(ctx)
    print(string.format("[OnConnect] %s:%d -> %s:%d (fqdn=%s, cmd=%d, auth_method=%d, auth_username=%s, auth_password=%s)",
        ctx.source_ip, ctx.source_port,
        ctx.destination_ip, ctx.destination_port,
        ctx.destination_fqdn, ctx.command,
        ctx.auth_method, ctx.auth_username, ctx.auth_password))
end
