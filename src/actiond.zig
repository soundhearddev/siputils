const std = @import("std");
const sip = @import("sip");
const actions = @import("actions.zig");
const keymng = @import("keymng.zig");

const Io = std.Io;

// TODO: Passwort aus Env-Variable oder Prompt lesen (wie in sipd.zig)
fn loadServerIdentity(io: std.Io, gpa: std.mem.Allocator) !sip.identity.KeyPair {
    // TODO: Identity-Name als CLI-Argument statt hardcoded "actiond"
    const password = try promptPassword(gpa, "[actiond] Passwort");
    defer gpa.free(password);
    return keymng.loadIdentity(io, "actiond", password);
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

fn lookupPubkey(known: []const actions.KnownClient, addr: [16]u8) ?[32]u8 {
    for (known) |k| {
        if (std.mem.eql(u8, &k.addr, &addr)) return k.pubkey;
    }
    return null;
}

fn buildAllowlist(known_clients: []const actions.KnownClient) [4]actions.ActionAllowlist {
    return .{
        .{ .action = .ping, .allowed_clients = known_clients },
        .{ .action = .status, .allowed_clients = known_clients },
        .{ .action = .reload_config, .allowed_clients = known_clients },
        .{ .action = .shutdown, .allowed_clients = &[_]actions.KnownClient{} },
    };
}

fn dispatch(action: actions.Action, arg: []const u8) actions.ActionResponse {
    _ = arg;
    return switch (action) {
        .ping => .{ .ok = true, .message = "pong" },
        .status => .{ .ok = true, .message = "status: running" },
        .reload_config => .{ .ok = true, .message = "config reloaded" },
        .shutdown => .{ .ok = false, .message = "shutdown not permitted" },
        _ => .{ .ok = false, .message = "unknown action" },
    };
}

fn handleActionPayload(
    io: std.Io,
    payload: []const u8,
    peer_addr: [16]u8,
    conn_id: u64,
    seq_num: u32,
    known_clients: []const actions.KnownClient,
    allowlist: []const actions.ActionAllowlist,
    nonce_cache: *actions.NonceCache,
) actions.ActionResponse {
    const req = actions.ActionRequest.parse(payload) catch {
        return .{ .ok = false, .message = "malformed request" };
    };

    const peer_pubkey = lookupPubkey(known_clients, peer_addr) orelse {
        return .{ .ok = false, .message = "unknown peer identity" };
    };

    req.verify(peer_pubkey, conn_id, seq_num) catch {
        return .{ .ok = false, .message = "invalid signature" };
    };

    const now: i64 = @intCast(@divFloor(std.Io.Timestamp.now(io, .real).toNanoseconds(), std.time.ns_per_s));
    const req_time = req.timestamp;

    if (@abs(now - req_time) > actions.MAX_REQUEST_AGE_SECONDS) {
        return .{ .ok = false, .message = "stale request" };
    }

    if (!nonce_cache.checkAndInsert(peer_addr, req.nonce, now)) {
        return .{ .ok = false, .message = "replayed nonce" };
    }

    actions.isAuthorized(allowlist, req.action, peer_addr) catch |err| {
        return .{ .ok = false, .message = @errorName(err) };
    };

    return dispatch(req.action, req.arg);
}

fn handleConnection(
    io: std.Io,
    allocator: std.mem.Allocator,
    sock: sip.synet.Socket,
    server_keys: sip.identity.KeyPair,
    server_addr: [16]u8,
    known_clients: []const actions.KnownClient,
    nonce_cache: *actions.NonceCache,
    verbose: bool,
) !void {
    defer sip.synet.close(sock);

    var session = try sip.handshake.performKeyExchange(
        io,
        allocator,
        sock,
        server_keys,
        server_addr,
        false,
        null,
    );
    defer session.deinit();

    if (verbose) {
        std.debug.print("handshake ok, peer={x} conn_id={x}\n", .{ session.peer_address, session.conn_id });
    }

    const inbound = sip.translation.readInboundPacket(sock, allocator, session.rx) catch |err| {
        std.debug.print("Error reading packet: {}\n", .{err});
        return;
    };
    defer sip.translation.freeInboundPacket(allocator, inbound);

    if (inbound.parsed.command != .Data) {
        std.debug.print("unexpected command: {}\n", .{inbound.parsed.command});
        return;
    }

    sip.protocol.validatePayload(allocator, .Data, inbound.parsed.payload) catch |err| {
        std.debug.print("invalid payload: {}\n", .{err});
        return;
    };

    const allowlist = buildAllowlist(known_clients);

    const resp = handleActionPayload(
        io,
        inbound.parsed.payload,
        session.peer_address,
        inbound.parsed.header.inner.conn_id,
        inbound.parsed.header.inner.seq_num,
        known_clients,
        &allowlist,
        nonce_cache,
    );

    if (verbose) {
        std.debug.print("action processed: ok={} msg={s}\n", .{ resp.ok, resp.message });
    }

    var resp_buf: [512]u8 = undefined;
    const encoded = resp.encode(&resp_buf) catch {
        std.debug.print("Response too large for buffer\n", .{});
        return;
    };

    const wire = sip.translation.buildOutboundPacket(
        io,
        allocator,
        server_addr,
        session.peer_address,
        session.conn_id,
        0,
        .Data,
        encoded,
        session.tx,
    ) catch |err| {
        std.debug.print("Error building response: {}\n", .{err});
        return;
    };
    defer allocator.free(wire);

    sip.synet.sendAll(sock, wire) catch |err| {
        std.debug.print("Error sending response: {}\n", .{err});
        return;
    };
}

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.gpa;

    const server_keys = try loadServerIdentity(io, gpa);
    const server_addr = sip.identity.baseAddress(server_keys.public);

    var addr_buf: [80]u8 = undefined;
    const addr_str = try sip.identity.formatSipAddress(&addr_buf, "actiond", server_addr);
    std.debug.print("actiond starting, address={s}\n", .{addr_str});

    // TODO: known_clients aus registry.zig laden statt per --trust Argument.
    // registry.resolve(io, gpa, hex_or_name) gibt den Pubkey zurück.
    // Solange registry nicht angebunden ist, bleibt --trust als Workaround.
    const argv = try init.minimal.args.toSlice(init.arena.allocator());
    var known_buf: [8]actions.KnownClient = undefined;
    var known_count: usize = 0;

    var i: usize = 1;
    while (i < argv.len) : (i += 1) {
        if (std.mem.eql(u8, argv[i], "--trust") and i + 1 < argv.len) {
            i += 1;
            const hex = argv[i];
            if (hex.len != 64) {
                std.debug.print("invalid --trust Pubkey: {s}\n", .{hex});
                continue;
            }
            var pubkey: [32]u8 = undefined;
            _ = std.fmt.hexToBytes(&pubkey, hex) catch {
                std.debug.print("invalid --trust Pubkey: {s}\n", .{hex});
                continue;
            };
            if (known_count < known_buf.len) {
                known_buf[known_count] = .{ .addr = sip.identity.baseAddress(pubkey), .pubkey = pubkey };
                known_count += 1;
                std.debug.print("Client trusts: addr={x}\n", .{known_buf[known_count - 1].addr});
            }
        }
    }

    const listen_sock = try sip.synet.createTcpSocket();
    defer sip.synet.close(listen_sock);

    const port: u16 = 4433;
    var sockaddr = sip.synet.buildSockaddrIn(.{ 0, 0, 0, 0 }, port);
    try sip.synet.bind(listen_sock, &sockaddr);
    try sip.synet.listen(listen_sock, 16);
    std.debug.print("actiond hoert auf Port {d}\n", .{port});

    var nonce_entries: [256]actions.NonceCache.Entry = undefined;
    var nonce_cache = actions.NonceCache.init(&nonce_entries);

    while (true) {
        const client_sock = sip.synet.accept(listen_sock) catch |err| {
            std.debug.print("accept fehlgeschlagen: {}\n", .{err});
            continue;
        };

        handleConnection(
            io,
            gpa,
            client_sock,
            server_keys,
            server_addr,
            known_buf[0..known_count],
            &nonce_cache,
            true,
        ) catch |err| {
            std.debug.print("Verbindung fehlgeschlagen: {}\n", .{err});
        };
    }
}
