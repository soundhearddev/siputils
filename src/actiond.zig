const std = @import("std");
const sip = @import("sip");
const actions = @import("actions.zig");
const keymng = @import("keymng.zig");
const registry = @import("registry.zig");

const Io = std.Io;

fn loadServerIdentity(io: std.Io, gpa: std.mem.Allocator, identity_name: []const u8) !sip.identity.KeyPair {
    const prompt_msg = try std.fmt.allocPrint(gpa, "[{s}] Passwort", .{identity_name});
    defer gpa.free(prompt_msg);
    const password = try promptPassword(gpa, prompt_msg);
    defer gpa.free(password);
    return keymng.loadIdentity(io, identity_name, password);
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

fn buildAllowlist(known_clients: []const actions.KnownClient) [9]actions.ActionAllowlist {
    return .{
        .{ .action = .ping, .allowed_clients = known_clients },
        .{ .action = .status, .allowed_clients = known_clients },
        .{ .action = .reload_config, .allowed_clients = known_clients },
        .{ .action = .shutdown, .allowed_clients = &[_]actions.KnownClient{} },
        .{ .action = .echo, .allowed_clients = known_clients },
        .{ .action = .metrics, .allowed_clients = known_clients },
        .{ .action = .peer_list, .allowed_clients = known_clients },
        .{ .action = .registry_lookup, .allowed_clients = known_clients },
        .{ .action = .whoami, .allowed_clients = known_clients },
    };
}

const DispatchContext = struct {
    identity_name: []const u8,
    server_addr: [16]u8,
    known_clients: []const actions.KnownClient,
    metrics: *Metrics,
    io: std.Io,
};

const Metrics = struct {
    start_time: i64,
    total_connections: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    auth_failures: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    actions_executed: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    fn init(start_time: i64) Metrics {
        return .{ .start_time = start_time };
    }
};

fn dispatch(buf: []u8, action: actions.Action, arg: []const u8, ctx: DispatchContext) actions.ActionResponse {
    return switch (action) {
        .ping => .{ .ok = true, .message = "pong" },
        .status => buildStatusResponse(buf, ctx),
        .reload_config => .{ .ok = true, .message = "config reloaded" },
        .shutdown => .{ .ok = false, .message = "shutdown not permitted" },
        .echo => .{ .ok = true, .message = arg },
        .metrics => buildMetricsResponse(buf, ctx),
        .peer_list => buildPeerListResponse(buf, ctx),
        .registry_lookup => buildRegistryLookupResponse(buf, ctx.io, arg),
        .whoami => buildWhoamiResponse(buf, ctx),
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
    ctx: DispatchContext,
    resp_buf: []u8,
) actions.ActionResponse {
    const req = actions.ActionRequest.parse(payload) catch {
        return .{ .ok = false, .message = "malformed request" };
    };

    const peer_pubkey = lookupPubkey(known_clients, peer_addr) orelse {
        return .{ .ok = false, .message = "unknown peer identity" };
    };

    req.verify(peer_pubkey, conn_id, seq_num) catch {
        _ = ctx.metrics.auth_failures.fetchAdd(1, .monotonic);
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

    const resp = dispatch(resp_buf, req.action, req.arg, ctx);
    _ = ctx.metrics.actions_executed.fetchAdd(1, .monotonic);
    return resp;
}

fn handleConnection(
    io: std.Io,
    allocator: std.mem.Allocator,
    sock: sip.synet.Socket,
    server_keys: sip.identity.KeyPair,
    server_addr: [16]u8,
    identity_name: []const u8,
    known_clients: []const actions.KnownClient,
    nonce_cache: *actions.NonceCache,
    metrics: *Metrics,
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

    var dispatch_buf: [400]u8 = undefined;
    const allowlist = buildAllowlist(known_clients);
    const ctx = DispatchContext{
        .identity_name = identity_name,
        .server_addr = server_addr,
        .known_clients = known_clients,
        .metrics = metrics,
        .io = io,
    };

    _ = ctx.metrics.total_connections.fetchAdd(1, .monotonic);

    const resp = handleActionPayload(
        io,
        inbound.parsed.payload,
        session.peer_address,
        inbound.parsed.header.inner.conn_id,
        inbound.parsed.header.inner.seq_num,
        known_clients,
        &allowlist,
        nonce_cache,
        ctx,
        &dispatch_buf,
    );

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

fn getIdentityPassword(gpa: std.mem.Allocator, identity_name: []const u8) ![]u8 {
    var env_buf: [64]u8 = undefined;
    const env_name = std.fmt.bufPrint(&env_buf, "ACTIOND_PASSWORD_{s}", .{identity_name}) catch identity_name;

    if (std.process.getEnvVarOwned(gpa, env_name)) |val| {
        return val;
    } else |_| {}

    const prompt_msg = try std.fmt.allocPrint(gpa, "[{s}] Passwort", .{identity_name});
    defer gpa.free(prompt_msg);
    return promptPassword(gpa, prompt_msg);
}

fn buildWhoamiResponse(buf: []u8, ctx: DispatchContext) actions.ActionResponse {
    const msg = std.fmt.bufPrint(buf,
        \\{{"identity":"{s}","address":"{x}"}}
    , .{ ctx.identity_name, ctx.server_addr }) catch return .{ .ok = false, .message = "buffer too small" };
    return .{ .ok = true, .message = msg };
}

fn buildMetricsResponse(buf: []u8, ctx: DispatchContext) actions.ActionResponse {
    const now: i64 = @intCast(@divFloor(std.Io.Timestamp.now(ctx.io, .real).toNanoseconds(), std.time.ns_per_s));
    const uptime = now - ctx.metrics.start_time;
    const msg = std.fmt.bufPrint(buf,
        \\{{"uptime_seconds":{d},"total_connections":{d},"auth_failures":{d},"actions_executed":{d},"known_peers":{d}}}
    , .{
        uptime,
        ctx.metrics.total_connections.load(.monotonic),
        ctx.metrics.auth_failures.load(.monotonic),
        ctx.metrics.actions_executed.load(.monotonic),
        ctx.known_clients.len,
    }) catch return .{ .ok = false, .message = "buffer too small" };
    return .{ .ok = true, .message = msg };
}

fn buildStatusResponse(buf: []u8, ctx: DispatchContext) actions.ActionResponse {
    const now: i64 = @intCast(@divFloor(std.Io.Timestamp.now(ctx.io, .real).toNanoseconds(), std.time.ns_per_s));
    const uptime = now - ctx.metrics.start_time;
    const msg = std.fmt.bufPrint(buf,
        \\{{"status":"running","identity":"{s}","uptime_seconds":{d},"known_peers":{d}}}
    , .{ ctx.identity_name, uptime, ctx.known_clients.len }) catch return .{ .ok = false, .message = "buffer too small" };
    return .{ .ok = true, .message = msg };
}

fn buildPeerListResponse(buf: []u8, ctx: DispatchContext) actions.ActionResponse {
    var w: usize = 0;
    const opening = "{\"peers\":[";
    if (w + opening.len > buf.len) return .{ .ok = false, .message = "buffer too small" };
    @memcpy(buf[w..][0..opening.len], opening);
    w += opening.len;

    for (ctx.known_clients, 0..) |client, idx| {
        const piece = std.fmt.bufPrint(buf[w..], "{s}\"{x}\"", .{ if (idx > 0) "," else "", client.addr }) catch
            return .{ .ok = false, .message = "buffer too small" };
        w += piece.len;
    }

    if (w + 2 > buf.len) return .{ .ok = false, .message = "buffer too small" };
    buf[w] = ']';
    buf[w + 1] = '}';
    w += 2;

    return .{ .ok = true, .message = buf[0..w] };
}

fn buildRegistryLookupResponse(buf: []u8, io: std.Io, arg: []const u8) actions.ActionResponse {
    if (arg.len == 0) return .{ .ok = false, .message = "missing name arg" };

    const result = registry.resolve(io, undefined, arg) catch {
        return .{ .ok = false, .message = "not found" };
    };

    switch (result.entry.kind) {
        .ipv4 => {
            const msg = std.fmt.bufPrint(buf,
                \\{{"kind":"ipv4","addr":"{d}.{d}.{d}.{d}"}}
            , .{ result.entry.ipv4[0], result.entry.ipv4[1], result.entry.ipv4[2], result.entry.ipv4[3] }) catch
                return .{ .ok = false, .message = "buffer too small" };
            return .{ .ok = true, .message = msg };
        },
        .ipv6 => {
            var ip_buf: [40]u8 = undefined;
            const ip_str = registry.formatIpv6(&ip_buf, result.entry.ipv6);
            const msg = std.fmt.bufPrint(buf,
                \\{{"kind":"ipv6","addr":"{s}"}}
            , .{ip_str}) catch return .{ .ok = false, .message = "buffer too small" };
            return .{ .ok = true, .message = msg };
        },
        .mesh => {
            const msg = std.fmt.bufPrint(buf,
                \\{{"kind":"mesh","addr":"{x}"}}
            , .{result.entry.mesh}) catch return .{ .ok = false, .message = "buffer too small" };
            return .{ .ok = true, .message = msg };
        },
    }
}

fn setReuseAddr(sock: sip.synet.Socket) void {
    const val: c_int = 1;
    const rc = std.os.linux.setsockopt(
        sock,
        std.os.linux.SOL.SOCKET,
        std.os.linux.SO.REUSEADDR,
        std.mem.asBytes(&val),
        @sizeOf(c_int),
    );
    if (rc != 0) {
        std.debug.print("Warning: failed to set SO_REUSEADDR\n", .{});
    }
}

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.gpa;

    const argv = try init.minimal.args.toSlice(init.arena.allocator());

    var metrics = Metrics.init(@intCast(@divFloor(std.Io.Timestamp.now(io, .real).toNanoseconds(), std.time.ns_per_s)));

    var identity_name: []const u8 = "default";
    {
        var i: usize = 1;
        while (i < argv.len) : (i += 1) {
            if (std.mem.eql(u8, argv[i], "--identity") and i + 1 < argv.len) {
                i += 1;
                identity_name = argv[i];
            }
        }
    }

    const server_keys = try loadServerIdentity(io, gpa, identity_name);
    const server_addr = sip.identity.baseAddress(server_keys.public);

    var addr_buf: [80]u8 = undefined;
    const addr_str = try sip.identity.formatSipAddress(&addr_buf, identity_name, server_addr);
    std.debug.print("actiond starting, address={s}\n", .{addr_str});
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

    setReuseAddr(listen_sock);

    const port: u16 = 4433;
    var sockaddr = sip.synet.buildSockaddrIn(.{ 0, 0, 0, 0 }, port);
    try sip.synet.bind(listen_sock, &sockaddr);
    try sip.synet.listen(listen_sock, 16);
    std.debug.print("actiond is listening on port {d}\n", .{port});

    var nonce_entries: [256]actions.NonceCache.Entry = undefined;
    var nonce_cache = actions.NonceCache.init(&nonce_entries);

    while (true) {
        const client_sock = sip.synet.accept(listen_sock) catch |err| {
            std.debug.print("Connection failed: {}\n", .{err});
            continue;
        };

        handleConnection(io, gpa, client_sock, server_keys, server_addr, identity_name, known_buf[0..known_count], &nonce_cache, &metrics, true) catch |err| {
            std.debug.print("accept failed: {}\n", .{err});
        };
    }
}
