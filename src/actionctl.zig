// Proof of Concept!!!

const std = @import("std");
const sip = @import("sip");
const actions = @import("actions.zig");
const keymng = @import("keymng.zig");
const registry = @import("registry.zig");

fn printUsage() void {
    std.debug.print(
        \\actionctl - SIP action client
        \\
        \\  actionctl <identity> <host> <port> <action> [arg]
        \\      Actions: ping, status, reload_config, shutdown
        \\
    , .{});
}

fn actionFromString(s: []const u8) ?actions.Action {
    if (std.mem.eql(u8, s, "ping")) return .ping;
    if (std.mem.eql(u8, s, "status")) return .status;
    if (std.mem.eql(u8, s, "reload_config")) return .reload_config;
    if (std.mem.eql(u8, s, "shutdown")) return .shutdown;
    return null;
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
    const argv = try init.minimal.args.toSlice(init.arena.allocator());

    if (argv.len < 3) {
        printUsage();
        return;
    }

    if (argv.len < 5) {
        printUsage();
        return error.MissingArguments;
    }

    const host = argv[2];
    const port = try std.fmt.parseInt(u16, argv[3], 10);
    const action = actionFromString(argv[4]) orelse {
        std.debug.print("Unknown action: {s}\n", .{argv[4]});
        return error.UnknownAction;
    };
    const arg = if (argv.len > 5) argv[5] else "";

    const identity_name = argv[1];
    const prompt_msg = try std.fmt.allocPrint(gpa, "[{s}] Password", .{identity_name});
    defer gpa.free(prompt_msg);
    const password = try promptPassword(gpa, prompt_msg);
    defer gpa.free(password);
    const client_keys = try keymng.loadIdentity(io, identity_name, password);
    const client_addr = sip.identity.baseAddress(client_keys.public);

    var hex_buf: [64]u8 = undefined;
    const hex = std.fmt.bufPrint(&hex_buf, "{x}", .{client_keys.public}) catch unreachable;
    std.debug.print("[actionctl] own identity (pubkey): {s}\n", .{hex});
    std.debug.print("[actionctl] -> must be trusted on server via --trust {s}\n", .{hex});

    const ip = try registry.parseIpv4(host);

    const sock = try sip.synet.createTcpSocket();
    defer sip.synet.close(sock);

    var sockaddr = sip.synet.buildSockaddrIn(ip, port);
    try sip.synet.connect(sock, &sockaddr);

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

    std.debug.print("handshake ok, server={x} conn_id={x}\n", .{ session.peer_address, session.conn_id });

    const seq_num: u32 = 0;

    var nonce_bytes: [8]u8 = undefined;
    try io.randomSecure(&nonce_bytes);
    const nonce = std.mem.readInt(u64, &nonce_bytes, .big);
    const timestamp: i64 = @intCast(@divFloor(std.Io.Timestamp.now(io, .real).toNanoseconds(), std.time.ns_per_s));

    var req_buf: [512]u8 = undefined;
    const req_len = try actions.ActionRequest.buildSigned(
        &req_buf,
        client_keys,
        action,
        nonce,
        timestamp,
        arg,
        session.conn_id,
        seq_num,
    );

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

    try sip.synet.sendAll(sock, wire);
    std.debug.print("Action '{s}' gesendet, warte auf Antwort...\n", .{argv[4]});

    const inbound = try sip.translation.readInboundPacket(sock, gpa, session.rx);
    defer sip.translation.freeInboundPacket(gpa, inbound);

    if (inbound.parsed.command != .Data) {
        std.debug.print("unerwartetes Antwort-Command: {}\n", .{inbound.parsed.command});
        return;
    }

    const resp = actions.ActionResponse.decode(inbound.parsed.payload) catch {
        std.debug.print("ungültige Antwort vom Server\n", .{});
        return;
    };

    if (resp.ok) {
        std.debug.print("OK: {s}\n", .{resp.message});
    } else {
        std.debug.print("FEHLER: {s}\n", .{resp.message});
    }
}
