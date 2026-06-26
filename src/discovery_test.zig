const std = @import("std");
const sip = @import("sip");

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());

    if (args.len < 2) {
        std.debug.print("[SYSTEM] Fehler: Modus fehlt. Verwendung: discovery_test server|client\n", .{});
        return;
    }
    const mode = args[1];

    // IPv6 Loopback [::1] auf Port 5555
    const addr = sip.synet.buildSockaddrIn6([_]u8{0} ** 15 ++ [_]u8{1}, 5555);

    if (std.mem.eql(u8, mode, "server")) {
        std.debug.print("[SERVER] Initialisiere AF_INET6 TCP Socket...\n", .{});
        const sock = try sip.synet.createTcpSocketFamily(std.posix.AF.INET6);
        defer {
            std.debug.print("[SERVER] Schliesse Haupt-Listener Socket.\n", .{});
            sip.synet.close(sock);
        }

        std.debug.print("[SERVER] Binde Socket an [::1]:5555...\n", .{});
        try sip.synet.bind6(sock, &addr);

        std.debug.print("[SERVER] Setze Socket in Listen-Modus (Backlog=128)...\n", .{});
        try sip.synet.listen(sock, 128);

        std.debug.print("[SERVER] TCP Server lauscht aktiv auf [::1]:5555\n", .{});

        while (true) {
            std.debug.print("\n[SERVER] Blockiere in accept() - Warte auf Client-Verbindung...\n", .{});
            const client = try sip.synet.accept(sock);
            std.debug.print("[SERVER] Neue Verbindung akzeptiert! Client-FD: {}\n", .{client});

            handleClient(
                client,
            ) catch |err| {
                std.debug.print("[SERVER] [FEHLER] Fehler bei Client-Handling: {}\n", .{err});
                sip.synet.close(client);
            };
        }
    }

    if (std.mem.eql(u8, mode, "client")) {
        std.debug.print("[CLIENT] Initialisiere AF_INET6 TCP Socket...\n", .{});
        const sock = try sip.synet.createTcpSocketFamily(std.posix.AF.INET6);
        defer {
            std.debug.print("[CLIENT] Schliesse Client-Socket.\n", .{});
            sip.synet.close(sock);
        }

        std.debug.print("[CLIENT] Verbinde via TCP zu [::1]:5555...\n", .{});
        try sip.synet.connect6(sock, &addr);
        std.debug.print("[CLIENT] TCP-Verbindung erfolgreich hergestellt.\n", .{});

        var tx_buf: [sip.header.OUTER_HEADER_SIZE]u8 = undefined;
        @memset(&tx_buf, 0x00); // Puffer nullen für sauberes Tracing

        const src = [_]u8{0x11} ** 16;
        std.debug.print("[CLIENT] Baue Discovery-Paket (Src: {x})...\n", .{src});
        const pkt = try sip.header.buildDiscoveryPacket(&tx_buf, src, [_]u8{0} ** 16);

        std.debug.print("[CLIENT] Sende exakt {} Bytes Discovery-Daten...\n", .{pkt.len});
        std.debug.print("[CLIENT] Hex-Dump (TX): ", .{});
        for (pkt) |b| std.debug.print("{X:0>2} ", .{b});
        std.debug.print("\n", .{});

        try sip.synet.sendAll(sock, pkt);
        std.debug.print("[CLIENT] Senden abgeschlossen. Gehe in den Lese-Modus...\n", .{});

        var rx_buf: [sip.header.OUTER_HEADER_SIZE]u8 = undefined;
        @memset(&rx_buf, 0x00);

        std.debug.print("[CLIENT] Blockiere in recvExact() - Erwarte exakt {} Bytes Reply...\n", .{pkt.len});
        try sip.synet.recvExact(sock, rx_buf[0..pkt.len]);

        std.debug.print("[CLIENT] Daten empfangen! Hex-Dump (RX): ", .{});
        for (rx_buf[0..pkt.len]) |b| std.debug.print("{X:0>2} ", .{b});
        std.debug.print("\n", .{});

        std.debug.print("[CLIENT] Parse empfangenen Outer-Header...\n", .{});
        const reply = try sip.header.parseOuter(&rx_buf);
        std.debug.print("[CLIENT] Discovery-Reply erfolgreich verarbeitet!\n", .{});
        std.debug.print("[CLIENT]   -> Server-SIP (Src): {x}\n", .{reply.src});
        std.debug.print("[CLIENT]   -> Target-SIP (Dst): {x}\n", .{reply.dst});
        std.debug.print("[CLIENT]   -> Command-ID: {}\n", .{reply.command});
    }
}

fn handleClient(sock: sip.synet.Socket) !void {
    defer {
        std.debug.print("[SERVER_WORKER] Schliesse Verbindung zu Client-FD: {}\n", .{sock});
        sip.synet.close(sock);
    }

    var buf: [sip.header.OUTER_HEADER_SIZE]u8 = undefined;
    @memset(&buf, 0x00);

    std.debug.print("[SERVER_WORKER] Blockiere in recvExact() - Erwarten {} Bytes Discovery-Header...\n", .{buf.len});
    try sip.synet.recvExact(sock, &buf);

    std.debug.print("[SERVER_WORKER] {} Bytes empfangen! Hex-Dump (RX): ", .{buf.len});
    for (buf) |b| std.debug.print("{X:0>2} ", .{b});
    std.debug.print("\n", .{});

    std.debug.print("[SERVER_WORKER] Parse Discovery-Paket...\n", .{});
    const disc = try sip.header.parseOuter(&buf);
    std.debug.print("[SERVER_WORKER] Parsing erfolgreich:\n", .{});
    std.debug.print("[SERVER_WORKER]   -> Client-SIP (Src): {x}\n", .{disc.src});
    std.debug.print("[SERVER_WORKER]   -> Command-ID: {}\n", .{disc.command});

    std.debug.print("[SERVER_WORKER] Generiere Discovery-Reply...\n", .{});
    var reply_buf: [sip.header.OUTER_HEADER_SIZE]u8 = undefined;
    @memset(&reply_buf, 0x00);

    const srv_src = [_]u8{0x99} ** 16;
    const reply_pkt = try sip.header.buildDiscoveryPacket(&reply_buf, srv_src, disc.src);

    std.debug.print("[SERVER_WORKER] Sende exakt {} Bytes Reply zurück...\n", .{reply_pkt.len});
    std.debug.print("[SERVER_WORKER] Hex-Dump (TX): ", .{});
    for (reply_pkt) |b| std.debug.print("{X:0>2} ", .{b});
    std.debug.print("\n", .{});

    try sip.synet.sendAll(
        sock,
        reply_pkt,
    );
    std.debug.print("[SERVER_WORKER] Reply erfolgreich gesendet.\n", .{});
}
