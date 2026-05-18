function on_connect(ctx)
    print(string.format("[OnConnect] Connection request: %s -> %s", ctx.source, ctx.destination))
end
