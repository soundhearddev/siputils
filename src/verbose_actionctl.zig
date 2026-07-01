const std = @import("std");
const sip = @import("sip");
const actions = @import("actions.zig");
const keymng = @import("keymng.zig");

fn dumpBytes(label: []const u8, bytes: []const u8) void {
    std.debug.print("\n=== [HEX DUMP] {s} ({d} Bytes) ===\n", .{ label, bytes.len });
    var i: usize = 0;
    while (i < bytes.len) : (i += 16) {
        std.debug.print("{x:4}: ", .{i});
        var j: usize = 0;
        while (j < 16) : (j += 1) {
            if (i + j < bytes.len) {
                std.debug.print("{x:2} ", .{bytes[i + j]});
            } else {
                std.debug.print("   ", .{});
            }
        }
        std.debug.print(" | ", .{});
        j = 0;
        while (j < 16) : (j += 1) {
            if (i + j < bytes.len) {
                const c = bytes[i + j];
                if (std.ascii.isPrint(c)) {
                    std.debug.print("{c}", .{c});
                } else {
                    std.debug.print(".", .{});
                }
            }
        }
        std.debug.print("\n", .{});
    }
    std.debug.print("==================================\n\n", .{});
}

fn promptPassword(allocator: std.mem.Allocator, prompt_text: []const u8) ![]u8 {
    std.debug.print("{s}: ", .{prompt_text});
    const fd = std.posix.STDIN_FILENO;
    const original_termios = try std.posix.tcgetattr(fd);
    var no_echo_termios = original_termios;
    no_echo_termios.lflag.ECHO = false;
    no_echo_termios.lflag.ECHONL = false;
    try std.posix.tcsetattr(fd, .NOW, no_echo_termios);
    defer {
        std.posix.tcsetattr(fd, .NOW, original_termios) catch {};
        std.debug.print("\n", .{});
    }
    var buf: [1024]u8 = undefined;
    const n = try std.posix.read(fd, &buf);
    var len = n;
    if (len > 0 and buf[len - 1] == '\n') len -= 1;
    if (len > 0 and buf[len - 1] == '\r') len -= 1;
    const password = try allocator.alloc(u8, len);
    @memcpy(password, buf[0..len]);
    return password;
}

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.gpa;

    const identity_name = "actionctl";

    const prompt_msg = try std.fmt.allocPrint(gpa, "[{s}] Passwort", .{identity_name});
    defer gpa.free(prompt_msg);

    const password = try promptPassword(gpa, prompt_msg);
    defer gpa.free(password);

    std.debug.print("Lade Identität '{s}'...\n", .{identity_name});
    const client_keys = try keymng.loadIdentity(io, identity_name, password);
    const client_addr = sip.identity.baseAddress(client_keys.public);

    dumpBytes("Client Public Key", &client_keys.public);
    std.debug.print("Abgeleitete Mesh-Adresse: {x}\n", .{client_addr});

    const host = [4]u8{ 127, 0, 0, 1 };
    const port = 4433;
    std.debug.print("Verbinde zu 127.0.0.1:{d}...\n", .{port});

    const sock = try sip.synet.createTcpSocket();
    defer sip.synet.close(sock);
    var sockaddr = sip.synet.buildSockaddrIn(host, port);
    try sip.synet.connect(sock, &sockaddr);
    std.debug.print("TCP-Socket verbunden.\n", .{});

    std.debug.print("Starte SIP-Key-Exchange (Handshake)...\n", .{});
    var session = try sip.handshake.performKeyExchange(
        io,
        gpa,
        sock,
        client_keys,
        client_addr,
        true,
        null,
    );
    defer session.deinit();

    std.debug.print("Handshake OK!\n", .{});
    std.debug.print("  -> Connection ID: {x}\n", .{session.conn_id});
    dumpBytes("Session TX Key", &session.tx);
    dumpBytes("Session RX Key", &session.rx);

    const action = actions.Action.ping;
    const seq_num: u32 = 0;

    var nonce_bytes: [8]u8 = undefined;
    try io.randomSecure(&nonce_bytes);
    const nonce = std.mem.readInt(u64, &nonce_bytes, .big);
    const timestamp: i64 = @intCast(@divFloor(std.Io.Timestamp.now(io, .real).toNanoseconds(), std.time.ns_per_s));

    std.debug.print("Baue ActionRequest:\n", .{});
    std.debug.print("  -> Action: {}\n", .{action});
    std.debug.print("  -> Nonce: {d}\n", .{nonce});
    std.debug.print("  -> Timestamp: {d}\n", .{timestamp});

    var req_buf: [512]u8 = undefined;
    const req_len = try actions.ActionRequest.buildSigned(
        &req_buf,
        client_keys,
        action,
        nonce,
        timestamp,
        "",
        session.conn_id,
        seq_num,
    );

    dumpBytes("Signierter ActionRequest Payload", req_buf[0..req_len]);

    std.debug.print("Kapsle Payload in Outbound-Paket...\n", .{});
    const wire = try sip.translation.buildOutboundPacket(
        io,
        gpa,
        client_addr,
        session.peer_address,
        session.conn_id,
        seq_num,
        .Data,
        req_buf[0..req_len],
        session.tx,
    );
    defer gpa.free(wire);

    dumpBytes("Verschlüsseltes Wire-Paket", wire);

    std.debug.print("Sende Bytes über den Socket...\n", .{});
    try sip.synet.sendAll(sock, wire);

    std.debug.print("Warte auf Antwort vom Server...\n", .{});

    const inbound = try sip.translation.readInboundPacket(sock, gpa, session.rx);
    defer sip.translation.freeInboundPacket(gpa, inbound);

    std.debug.print("Antwort-Paket empfangen!\n", .{});
    std.debug.print("  -> Command: {}\n", .{inbound.parsed.command});
    std.debug.print("  -> Conn ID: {x}\n", .{inbound.parsed.header.inner.conn_id});

    dumpBytes("Entschlüsselter Antwort-Payload", inbound.parsed.payload);

    // 8. Antwort parsen
    const resp = actions.ActionResponse.decode(inbound.parsed.payload) catch {
        std.debug.print("[FEHLER] Konnte ActionResponse nicht dekodieren!\n", .{});
        return;
    };

    std.debug.print("\n=== ERGEBNIS ===\n", .{});
    std.debug.print("Status: {}\n", .{resp.ok});
    std.debug.print("Nachricht: {s}\n", .{resp.message});
    std.debug.print("================\n", .{});
}
