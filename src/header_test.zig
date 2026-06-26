const std = @import("std");
const sip = @import("sip");

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());

    if (args.len < 2) {
        std.debug.print("Usage: server|client\n", .{});
        return;
    }
    const mode = args[1];

    const addr = sip.synet.buildSockaddrIn6([_]u8{0} ** 15 ++ [_]u8{1}, 5555);

    if (std.mem.eql(u8, mode, "server")) {
        const sock = try sip.synet.createTcpSocketFamily(std.posix.AF.INET6);
        defer sip.synet.close(sock);

        try sip.synet.bind6(sock, &addr);
        try sip.synet.listen(sock, 128);

        std.debug.print("TCP server listening on [::1]:5555\n", .{});

        while (true) {
            const client = try sip.synet.accept(sock);
            std.debug.print("Client connected\n", .{});
            handleClient(client) catch |err| {
                std.debug.print("Client error: {}\n", .{err});
                sip.synet.close(client);
            };
        }
    }

    if (std.mem.eql(u8, mode, "client")) {
        const sock = try sip.synet.createTcpSocketFamily(std.posix.AF.INET6);
        defer sip.synet.close(sock);

        try sip.synet.connect6(sock, &addr);

        var buf: [4096]u8 = undefined;
        const src = [_]u8{0x11} ** 16;
        const dst = [_]u8{0x22} ** 16;
        const payload = "TEST TEST TEST";

        const pkt = try sip.header.buildPacket(
            &buf,
            src,
            dst,
            123,
            0,
            .discovery,
            payload,
        );

        try sip.synet.sendAll(sock, pkt);
        std.debug.print("Sent {} bytes\n", .{pkt.len});
        for (pkt) |b| std.debug.print("{X:0>3} ", .{b});
        std.debug.print("\n", .{});
    }
}

fn handleClient(sock: sip.synet.Socket) !void {
    defer sip.synet.close(sock);

    var buf: [4096]u8 = undefined;
    const len = try sip.synet.recvSome(sock, &buf);
    std.debug.print("Received {} bytes: ", .{len});
    for (buf[0..len]) |b| std.debug.print("{X:0>3} ", .{b});
    std.debug.print("\n", .{});

    const parsed = sip.header.parsePacket(buf[0..len]) catch |err| {
        std.debug.print("Parse error: {}\n", .{err});
        return;
    };

    std.debug.print("\n--- PACKET ---\n", .{});
    std.debug.print("len: {}\n", .{len});
    std.debug.print("cmd: {}\n", .{parsed.command});
    std.debug.print("conn_id: {}\n", .{parsed.header.inner.conn_id});
    std.debug.print("payload: {s}\n", .{parsed.payload});
}
