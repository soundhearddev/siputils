const std = @import("std");
const sip = @import("sip");

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());

    if (args.len < 2) {
        std.debug.print("[SYSTEM] Error: Missing mode. Usage: discovery_test server|client\n", .{});
        return;
    }
    const mode = args[1];

    const addr = sip.synet.buildSockaddrIn6([_]u8{0} ** 15 ++ [_]u8{1}, 5555);

    if (std.mem.eql(u8, mode, "server")) {
        std.debug.print("[SERVER] Initializing AF_INET6 TCP socket...\n", .{});
        const sock = try sip.synet.createTcpSocketFamily(std.posix.AF.INET6);
        defer {
            std.debug.print("[SERVER] Closing main listener socket.\n", .{});
            sip.synet.close(sock);
        }

        std.debug.print("[SERVER] Binding socket to [::1]:5555...\n", .{});
        try sip.synet.bind6(sock, &addr);

        std.debug.print("[SERVER] Putting socket into listening mode (backlog=128)...\n", .{});
        try sip.synet.listen(sock, 128);

        std.debug.print("[SERVER] TCP server is listening on [::1]:5555\n", .{});

        while (true) {
            std.debug.print("\n[SERVER] Blocking in accept() - Waiting for client connection...\n", .{});
            const client = try sip.synet.accept(sock);
            std.debug.print("[SERVER] New connection accepted! Client FD: {}\n", .{client});

            handleClient(
                client,
            ) catch |err| {
                std.debug.print("[SERVER] [ERROR] Error while handling client: {}\n", .{err});
                sip.synet.close(client);
            };
        }
    }

    if (std.mem.eql(u8, mode, "client")) {
        std.debug.print("[CLIENT] Initializing AF_INET6 TCP socket...\n", .{});
        const sock = try sip.synet.createTcpSocketFamily(std.posix.AF.INET6);
        defer {
            std.debug.print("[CLIENT] Closing client socket.\n", .{});
            sip.synet.close(sock);
        }

        std.debug.print("[CLIENT] Connecting via TCP to [::1]:5555...\n", .{});
        try sip.synet.connect6(sock, &addr);
        std.debug.print("[CLIENT] TCP connection established successfully.\n", .{});

        var tx_buf: [sip.header.OUTER_HEADER_SIZE]u8 = undefined;
        @memset(&tx_buf, 0x00);

        const src = [_]u8{0x11} ** 16;
        std.debug.print("[CLIENT] Building discovery packet (Src: {x})...\n", .{src});
        const pkt = try sip.header.buildDiscoveryPacket(&tx_buf, src, [_]u8{0} ** 16);

        std.debug.print("[CLIENT] Sending exactly {} bytes of discovery data...\n", .{pkt.len});
        std.debug.print("[CLIENT] Hex dump (TX): ", .{});
        for (pkt) |b| std.debug.print("{X:0>2} ", .{b});
        std.debug.print("\n", .{});

        try sip.synet.sendAll(sock, pkt);
        std.debug.print("[CLIENT] Send complete. Switching to receive mode...\n", .{});

        var rx_buf: [sip.header.OUTER_HEADER_SIZE]u8 = undefined;
        @memset(&rx_buf, 0x00);

        std.debug.print("[CLIENT] Blocking in recvExact() - Waiting for exactly {} bytes of reply...\n", .{pkt.len});
        try sip.synet.recvExact(sock, rx_buf[0..pkt.len]);

        std.debug.print("[CLIENT] Data received! Hex dump (RX): ", .{});
        for (rx_buf[0..pkt.len]) |b| std.debug.print("{X:0>2} ", .{b});
        std.debug.print("\n", .{});

        std.debug.print("[CLIENT] Parsing received outer header...\n", .{});
        const reply = try sip.header.parseOuter(&rx_buf);
        std.debug.print("[CLIENT] Discovery reply processed successfully!\n", .{});
        std.debug.print("[CLIENT]   -> Server SIP (Src): {x}\n", .{reply.src});
        std.debug.print("[CLIENT]   -> Target SIP (Dst): {x}\n", .{reply.dst});
        std.debug.print("[CLIENT]   -> Command ID: {}\n", .{reply.command});
    }
}

fn handleClient(sock: sip.synet.Socket) !void {
    defer {
        std.debug.print("[SERVER] Closing connection to client FD: {}\n", .{sock});
        sip.synet.close(sock);
    }

    var buf: [sip.header.OUTER_HEADER_SIZE]u8 = undefined;
    @memset(&buf, 0x00);

    std.debug.print("[SERVER] Blocking in recvExact() - Waiting for {} bytes of discovery header...\n", .{buf.len});
    try sip.synet.recvExact(sock, &buf);

    std.debug.print("[SERVER] {} bytes received! Hex dump (RX): ", .{buf.len});
    for (buf) |b| std.debug.print("{X:0>2} ", .{b});
    std.debug.print("\n", .{});

    std.debug.print("[SERVER] Parsing discovery packet...\n", .{});
    const disc = try sip.header.parseOuter(&buf);
    std.debug.print("[SERVER] Parsing successful:\n", .{});
    std.debug.print("[SERVER]   -> Client SIP (Src): {x}\n", .{disc.src});
    std.debug.print("[SERVER]   -> Command ID: {}\n", .{disc.command});

    std.debug.print("[SERVER] Generating discovery reply...\n", .{});
    var reply_buf: [sip.header.OUTER_HEADER_SIZE]u8 = undefined;
    @memset(&reply_buf, 0x00);

    const srv_src = [_]u8{0x99} ** 16;
    const reply_pkt = try sip.header.buildDiscoveryPacket(&reply_buf, srv_src, disc.src);

    std.debug.print("[SERVER] Sending exactly {} bytes of reply...\n", .{reply_pkt.len});
    std.debug.print("[SERVER] Hex dump (TX): ", .{});
    for (reply_pkt) |b| std.debug.print("{X:0>2} ", .{b});
    std.debug.print("\n", .{});

    try sip.synet.sendAll(
        sock,
        reply_pkt,
    );
    std.debug.print("[SERVER] Reply sent successfully.\n", .{});
}
