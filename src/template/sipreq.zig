const std = @import("std");
const linux = std.os.linux;
const sip = @import("sip");
const Io = std.Io;

const utils = @import("siputils");
const keymng = utils.keymng;
const registry = utils.registry;
const fs = utils.filesystem;
const cmd = utils.cmdhandler;
const helpers = utils.helpers;
const sipd_lib = utils.sipd;

const synet = sip.synet;
const handshake = sip.handshake;
const translation = sip.translation;

pub const DEFAULT_PORT: u16 = 9443;
const DEFAULT_IDENTITY: []const u8 = "default";
const DEFAULT_SIPD_CONFIG = "/etc/sip/sipd.conf";

// =====================================================================
// Server
// =====================================================================

const ServerHandlerContext = struct {
    keys: sip.identity.KeyPair,
    allocator: std.mem.Allocator,
    verbose: bool,
};

fn handleQuery(
    io: Io,
    ctx: *ServerHandlerContext,
    conn: synet.Socket,
    session: *handshake.SessionKeys,
    seq_num: *u32,
    payload: []const u8,
) !void {
    if (payload.len < 1) {
        try sendRegistryResponse(io, ctx, conn, session, seq_num, .err, &.{});
        return;
    }

    const sub_cmd: registry.RegistrySubCommand = @enumFromInt(payload[0]);
    const body = payload[1..];

    switch (sub_cmd) {
        .resolve => try handleResolve(io, ctx, conn, session, seq_num, body),
        .register => try handleRegister(io, ctx, conn, session, seq_num, body),
        .unregister => try handleUnregister(io, ctx, conn, session, seq_num, body),
        _ => {
            std.debug.print("[ERROR] Unknown registry sub-command: {d}\n", .{payload[0]});
            try sendRegistryResponse(io, ctx, conn, session, seq_num, .err, &.{});
        },
    }
}

fn handleResolve(
    io: Io,
    ctx: *ServerHandlerContext,
    conn: synet.Socket,
    session: *handshake.SessionKeys,
    seq_num: *u32,
    name: []const u8,
) !void {
    if (name.len == 0) {
        try sendRegistryResponse(io, ctx, conn, session, seq_num, .not_found, &.{});
        return;
    }

    const result = registry.resolve(io, name) catch |err| switch (err) {
        registry.RegistryError.NotFound => {
            std.debug.print("[ERROR] Resolve '{s}': not found\n", .{name});
            try sendRegistryResponse(io, ctx, conn, session, seq_num, .not_found, &.{});
            return;
        },
        registry.RegistryError.Ambiguous => {
            std.debug.print("[ERROR] Resolve '{s}': ambiguous\n", .{name});
            try sendRegistryResponse(io, ctx, conn, session, seq_num, .ambiguous, &.{});
            return;
        },
        else => {
            std.debug.print("[ERROR] Resolve '{s}' failed: {any}\n", .{ name, err });
            try sendRegistryResponse(io, ctx, conn, session, seq_num, .err, &.{});
            return;
        },
    };

    var entry_buf: [17]u8 = undefined;
    const entry_wire = registry.encodeEntry(&entry_buf, result.entry) catch {
        try sendRegistryResponse(io, ctx, conn, session, seq_num, .err, &.{});
        return;
    };

    try sendRegistryResponse(io, ctx, conn, session, seq_num, .ok, entry_wire);
}

fn handleRegister(
    io: Io,
    ctx: *ServerHandlerContext,
    conn: synet.Socket,
    session: *handshake.SessionKeys,
    seq_num: *u32,
    body: []const u8,
) !void {
    const req = registry.decodeRegisterRequest(body) catch |err| {
        std.debug.print("[ERROR] Register: invalid payload ({any})\n", .{err});
        try sendRegistryResponse(io, ctx, conn, session, seq_num, .err, &.{});
        return;
    };

    // Autorisierung ist aktuell offen!!!
    // TODO: einschränken, sobald das Autorisierungsmodell feststeht
    registry.register(io, req.name, req.entry) catch |err| {
        std.debug.print("[ERROR] Register '{s}' failed: {any}\n", .{ req.name, err });
        try sendRegistryResponse(io, ctx, conn, session, seq_num, .err, &.{});
        return;
    };

    std.debug.print("[registry] Registered: '{s}' ({s})\n", .{ req.name, @tagName(req.entry.kind) });
    try sendRegistryResponse(io, ctx, conn, session, seq_num, .ok, &.{});
}

fn handleUnregister(
    io: Io,
    ctx: *ServerHandlerContext,
    conn: synet.Socket,
    session: *handshake.SessionKeys,
    seq_num: *u32,
    name: []const u8,
) !void {
    if (name.len == 0) {
        try sendRegistryResponse(io, ctx, conn, session, seq_num, .not_found, &.{});
        return;
    }

    registry.unregister(io, name) catch |err| switch (err) {
        registry.RegistryError.NotFound => {
            try sendRegistryResponse(io, ctx, conn, session, seq_num, .not_found, &.{});
            return;
        },
        else => {
            std.debug.print("[ERROR] Unregister '{s}' failed: {any}\n", .{ name, err });
            try sendRegistryResponse(io, ctx, conn, session, seq_num, .err, &.{});
            return;
        },
    };

    std.debug.print("[registry] Removed: '{s}'\n", .{name});
    try sendRegistryResponse(io, ctx, conn, session, seq_num, .ok, &.{});
}

fn sendRegistryResponse(
    io: Io,
    ctx: *ServerHandlerContext,
    conn: synet.Socket,
    session: *handshake.SessionKeys,
    seq_num: *u32,
    code: registry.RegistryResponseCode,
    data: []const u8,
) !void {
    const payload = try ctx.allocator.alloc(u8, 1 + data.len);
    defer ctx.allocator.free(payload);
    payload[0] = @intFromEnum(code);
    @memcpy(payload[1..], data);

    const pkt = try translation.buildOutboundPacket(
        io,
        ctx.allocator,
        session.peer_address,
        session.peer_address,
        session.conn_id,
        seq_num.*,
        .Data,
        payload,
        session.tx,
    );
    defer ctx.allocator.free(pkt);

    try synet.sendAll(conn, pkt);
    seq_num.* += 1;
}

fn handleConnection(io: Io, ctx: *ServerHandlerContext, conn: synet.Socket) void {
    defer synet.close(conn);

    const my_address = sip.identity.baseAddress(ctx.keys.public);

    var session = handshake.performKeyExchange(
        io,
        ctx.allocator,
        conn,
        ctx.keys,
        my_address,
        false,
        null,
    ) catch |err| {
        std.debug.print("[ERROR] Handshake failed: {any}\n", .{err});
        return;
    };
    defer session.deinit();

    var seq_num: u32 = 0;

    while (true) {
        const inbound = translation.readInboundPacket(
            conn,
            ctx.allocator,
            session.rx,
        ) catch |err| {
            switch (err) {
                error.ConnectionClosed, error.SocketError => {
                    std.debug.print("[registry] Client disconnected.\n", .{});
                    break;
                },
                else => {
                    std.debug.print("[ERROR] Unexpected error while reading packet: {any}\n", .{err});
                    break;
                },
            }
        };
        defer translation.freeInboundPacket(ctx.allocator, inbound);

        switch (inbound.parsed.command) {
            .Query => {
                handleQuery(io, ctx, conn, &session, &seq_num, inbound.parsed.payload) catch |err| {
                    std.debug.print("[ERROR] Error while processing Query: {any}\n", .{err});
                    break;
                };
            },
            .Close => {
                std.debug.print("[registry] Client sent Close signal.\n", .{});
                break;
            },
            else => {
                std.debug.print("[WARNING] Ignoring unexpected command: {}\n", .{inbound.parsed.command});
            },
        }
    }
}

fn handleConnectionWrapper(io: Io, ctx: *ServerHandlerContext, conn: synet.Socket) void {
    handleConnection(io, ctx, conn);
}

fn cmdServer(init: std.process.Init, args: *cmd.ArgIter) !void {
    const gpa = init.gpa;
    const io = init.io;

    const config_path = args.next() orelse sipd_lib.CONFIG_PATH;

    std.debug.print("[registry] Loading configuration from: {s}...\n", .{config_path});

    const config = try sipd_lib.loadConfig(io, gpa, config_path);
    defer {
        if (config.host) |h| gpa.free(h);
        if (config.output_path) |o| gpa.free(o);
        gpa.free(config.identity_name);
    }

    const keys = try sipd_lib.loadOrCreateIdentity(init, config.identity_name);

    std.debug.print("[registry] Identity '{s}' loaded successfully.\n", .{config.identity_name});

    sipd_lib.initGlobalState(gpa);
    defer sipd_lib.deinitGlobalState();

    const listener = try sipd_lib.createListener(config);

    std.debug.print("[registry] Server listening on port {}\n", .{config.port});

    var context = ServerHandlerContext{
        .keys = keys,
        .allocator = gpa,
        .verbose = config.verbose,
    };

    try sipd_lib.acceptLoop(io, listener, &context, handleConnectionWrapper);
}

// =====================================================================
// Client
// =====================================================================

pub const RegistryClient = struct {
    allocator: std.mem.Allocator,
    client_keys: sip.identity.KeyPair,

    pub fn init(allocator: std.mem.Allocator, io: Io, init_ctx: std.process.Init, identity_name: []const u8) !RegistryClient {
        var pw_buf: [256]u8 = undefined;

        var stdout_io_buf: [1024]u8 = undefined;
        var stdout_struct = std.Io.File.stdout().writer(io, &stdout_io_buf);
        const stdout_writer = &stdout_struct.interface;

        const password = try cmd.resolvePassword(
            io,
            stdout_writer,
            init_ctx.environ_map,
            .{ .env_name = "SIP_PASSWORD" },
            &pw_buf,
            false,
        );

        const client_keys = try keymng.loadIdentity(io, identity_name, password);

        return RegistryClient{
            .allocator = allocator,
            .client_keys = client_keys,
        };
    }

    fn connectAndHandshake(
        self: *RegistryClient,
        io: Io,
        server_host: []const u8,
        server_port: u16,
    ) !struct { sock: synet.Socket, session: handshake.SessionKeys } {
        const sock = try synet.createTcpSocketFamily(std.posix.AF.INET6);
        errdefer synet.close(sock);

        const server_ip = try registry.parseIpv6(server_host);
        const server_addr = synet.buildSockaddrIn6(server_ip, server_port);

        synet.connect6(sock, &server_addr) catch |err| {
            std.debug.print("[ERROR]: {}\n", .{err});
            return error.ConnectionError;
        };

        const my_address = sip.identity.baseAddress(self.client_keys.public);

        const session = handshake.performKeyExchange(
            io,
            self.allocator,
            sock,
            self.client_keys,
            my_address,
            true,
            null,
        ) catch |err| {
            std.debug.print("[registry] Handshake failed: {}\n", .{err});
            return error.HandshakeFailed;
        };

        return .{ .sock = sock, .session = session };
    }

    fn sendQuery(
        self: *RegistryClient,
        io: Io,
        sock: synet.Socket,
        session: *handshake.SessionKeys,
        sub_cmd: registry.RegistrySubCommand,
        body: []const u8,
    ) !void {
        const payload = try self.allocator.alloc(u8, 1 + body.len);
        defer self.allocator.free(payload);
        payload[0] = @intFromEnum(sub_cmd);
        @memcpy(payload[1..], body);

        const pkt = try translation.buildOutboundPacket(
            io,
            self.allocator,
            session.peer_address,
            session.peer_address,
            session.conn_id,
            0,
            .Query,
            payload,
            session.tx,
        );
        defer self.allocator.free(pkt);

        try synet.sendAll(sock, pkt);
    }

    const RegistryResponse = struct {
        code: registry.RegistryResponseCode,
        data: []const u8,
        _pkt: translation.InboundPacket,

        fn deinit(self: RegistryResponse, allocator: std.mem.Allocator) void {
            translation.freeInboundPacket(allocator, self._pkt);
        }
    };

    fn readResponse(self: *RegistryClient, sock: synet.Socket, session: *handshake.SessionKeys) !RegistryResponse {
        const resp_pkt = try translation.readInboundPacket(sock, self.allocator, session.rx);
        errdefer translation.freeInboundPacket(self.allocator, resp_pkt);

        const parsed = resp_pkt.parsed;
        if (parsed.command != .Data) {
            translation.freeInboundPacket(self.allocator, resp_pkt);
            return error.InvalidServerResponse;
        }
        if (parsed.payload.len < 1) {
            translation.freeInboundPacket(self.allocator, resp_pkt);
            return error.InvalidServerResponse;
        }

        const code = std.enums.fromInt(registry.RegistryResponseCode, parsed.payload[0]) orelse {
            translation.freeInboundPacket(self.allocator, resp_pkt);
            return error.InvalidServerResponse;
        };
        return RegistryResponse{
            .code = code,
            .data = parsed.payload[1..],
            ._pkt = resp_pkt,
        };
    }

    pub fn resolveRemote(
        self: *RegistryClient,
        io: Io,
        server_host: []const u8,
        server_port: u16,
        target_name: []const u8,
    ) !?registry.Entry {
        const conn = try self.connectAndHandshake(io, server_host, server_port);
        var session = conn.session;
        defer synet.close(conn.sock);
        defer session.deinit();

        try self.sendQuery(io, conn.sock, &session, .resolve, target_name);

        const resp = try self.readResponse(conn.sock, &session);
        defer resp.deinit(self.allocator);

        switch (resp.code) {
            .ok => {
                const entry = registry.decodeEntry(resp.data) catch {
                    return error.InvalidServerResponse;
                };
                return entry;
            },
            .not_found => {
                std.debug.print("[registry] Server reports: Name '{s}' not found.\n", .{target_name});
                return null;
            },
            .ambiguous => return error.NameAmbiguous,
            .err => return error.ServerError,
            else => return error.InvalidServerResponse,
        }
    }

    pub fn registerAtServer(
        self: *RegistryClient,
        io: Io,
        server_host: []const u8,
        server_port: u16,
        my_name: []const u8,
        my_ipv6: [16]u8,
    ) !void {
        const conn = try self.connectAndHandshake(io, server_host, server_port);
        var session = conn.session;
        defer synet.close(conn.sock);
        defer session.deinit();

        const entry = registry.Entry.fromIpv6(my_ipv6);
        var body_buf: [300]u8 = undefined;
        const body = try registry.encodeRegisterRequest(&body_buf, my_name, entry);

        try self.sendQuery(io, conn.sock, &session, .register, body);

        const resp = try self.readResponse(conn.sock, &session);
        defer resp.deinit(self.allocator);

        switch (resp.code) {
            .ok => {
                std.debug.print("[registry] Registration for '{s}' completed successfully.\n", .{my_name});
            },
            else => return error.RegistrationFailed,
        }
    }

    pub fn unregisterAtServer(
        self: *RegistryClient,
        io: Io,
        server_host: []const u8,
        server_port: u16,
        my_name: []const u8,
    ) !void {
        const conn = try self.connectAndHandshake(io, server_host, server_port);
        var session = conn.session;
        defer synet.close(conn.sock);
        defer session.deinit();

        try self.sendQuery(io, conn.sock, &session, .unregister, my_name);

        const resp = try self.readResponse(conn.sock, &session);
        defer resp.deinit(self.allocator);

        switch (resp.code) {
            .ok => {
                std.debug.print("[registry] '{s}' successfully removed.\n", .{my_name});
            },
            .not_found => return error.UnregistrationFailed,
            else => return error.UnregistrationFailed,
        }
    }
};

const ClientArgs = struct {
    server_host: []const u8 = "::1",
    identity_name: []const u8 = DEFAULT_IDENTITY,
    port: u16 = DEFAULT_PORT,
    manual_name: ?[]const u8 = null,
    manual_ipv6: ?[]const u8 = null,
    positional: ?[]const u8 = null,
};

fn parseClientArgs(args: *cmd.ArgIter) !ClientArgs {
    var result = ClientArgs{};

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "-p") or std.mem.eql(u8, arg, "--port")) {
            const val = args.next() orelse return error.MissingFlagValue;
            result.port = std.fmt.parseInt(u16, val, 10) catch return error.InvalidPort;
        } else if (std.mem.eql(u8, arg, "-i") or std.mem.eql(u8, arg, "--identity")) {
            result.identity_name = args.next() orelse return error.MissingFlagValue;
        } else if (std.mem.eql(u8, arg, "-n") or std.mem.eql(u8, arg, "--name")) {
            result.manual_name = args.next() orelse return error.MissingFlagValue;
        } else if (std.mem.eql(u8, arg, "-ip") or std.mem.eql(u8, arg, "--ipv6")) {
            result.manual_ipv6 = args.next() orelse return error.MissingFlagValue;
        } else if (std.mem.eql(u8, arg, "--host")) {
            result.server_host = args.next() orelse return error.MissingFlagValue;
        } else if (std.mem.startsWith(u8, arg, "-")) {
            std.debug.print("Error: Unknown option '{s}'\n", .{arg});
            return error.UnknownFlag;
        } else {
            if (result.positional == null) {
                result.positional = arg;
            } else {
                std.debug.print("Error: Too many positional arguments ('{s}')\n", .{arg});
                return error.TooManyArgs;
            }
        }
    }

    return result;
}

fn resolveDefaultIdentityName(io: Io, identity_name: []const u8) []const u8 {
    if (!std.mem.eql(u8, identity_name, "default")) return identity_name;

    var path_buf: [300]u8 = undefined;
    const dpath = keymng.identityDir(&path_buf, "default") catch return identity_name;

    var symlink_buf: [256]u8 = undefined;
    const cwd = std.Io.Dir.cwd();
    const bytes_read = cwd.readLink(io, dpath, &symlink_buf) catch |err| {
        if (err != error.FileNotFound and err != error.NotLink) {
            std.debug.print("[WARNING] Could not resolve 'default' identity symlink: {any}\n", .{err});
        }
        return identity_name;
    };

    const target_path = symlink_buf[0..bytes_read];
    const base_name = std.fs.path.basename(target_path);
    std.debug.print("[cli] Identity 'default' resolved to symlink target: '{s}'\n", .{base_name});
    return base_name;
}

fn cmdResolve(init: std.process.Init, args: *cmd.ArgIter) !void {
    const gpa = init.gpa;
    const io = init.io;

    const cargs = parseClientArgs(args) catch {
        printClientUsage();
        return;
    };
    const target_name = cargs.positional orelse {
        std.debug.print("[ERROR] 'resolve' requires a target name.\n", .{});
        return;
    };

    var client = RegistryClient.init(gpa, io, init, cargs.identity_name) catch |err| {
        std.debug.print("[ERROR] Client initialization failed with: {any}\n", .{err});
        return;
    };

    const entry = client.resolveRemote(io, cargs.server_host, cargs.port, target_name) catch return;

    if (entry) |e| {
        var ip_buf: [40]u8 = undefined;
        switch (e.kind) {
            .mesh => std.debug.print("[✓] Found: Mesh address: {x}\n", .{e.mesh}),
            .ipv4 => std.debug.print("[✓] Found: IPv4 address: {d}.{d}.{d}.{d}\n", .{ e.ipv4[0], e.ipv4[1], e.ipv4[2], e.ipv4[3] }),
            .ipv6 => {
                const formatted = registry.formatIpv6(&ip_buf, e.ipv6);
                std.debug.print("[✓] Found: IPv6 address: {s}\n", .{formatted});
            },
        }
    } else {
        std.debug.print("[✗] Resolution failed. Entry does not exist on the server.\n", .{});
    }
}

fn cmdRegister(init: std.process.Init, args: *cmd.ArgIter) !void {
    const gpa = init.gpa;
    const io = init.io;

    const cargs = parseClientArgs(args) catch {
        printClientUsage();
        return;
    };

    const resolved_identity_name = resolveDefaultIdentityName(io, cargs.identity_name);

    var client = RegistryClient.init(gpa, io, init, cargs.identity_name) catch |err| {
        std.debug.print("[ERROR] Client initialization failed with: {any}\n", .{err});
        return;
    };

    const my_name = cargs.manual_name orelse resolved_identity_name;

    var my_ipv6: [16]u8 = undefined;
    if (cargs.manual_ipv6) |ip_str| {
        my_ipv6 = registry.parseIpv6(ip_str) catch |err| {
            std.debug.print("Failed to parse manual IPv6 address '{s}': {any}\n", .{ ip_str, err });
            return;
        };
    } else {
        const iface = helpers.getDefaultIface(gpa, io) catch |err| {
            std.debug.print("Error: Failed to determine default interface: {any}\n", .{err});
            return;
        };
        defer gpa.free(iface);

        const prefix = helpers.getPrefix(gpa, io, iface) catch |err| {
            std.debug.print("Error: Failed to read IPv6 prefix from interface '{s}': {any}\n", .{ iface, err });
            return;
        };
        defer gpa.free(prefix);

        const generated_ip_str = helpers.generateAddress(gpa, prefix, init) catch |err| {
            std.debug.print("Address generation failed: {any}\n", .{err});
            return;
        };
        defer gpa.free(generated_ip_str);

        my_ipv6 = registry.parseIpv6(generated_ip_str) catch |err| {
            std.debug.print("Failed to parse generated address '{s}': {any}\n", .{ generated_ip_str, err });
            return;
        };
        std.debug.print("[cli] IP automatically generated: {s}\n", .{generated_ip_str});
    }

    std.debug.print("[cli] Registering name '{s}' with the server...\n", .{my_name});
    client.registerAtServer(io, cargs.server_host, cargs.port, my_name, my_ipv6) catch |err| {
        std.debug.print("[✗] Registration failed: {any}\n", .{err});
    };
}

fn cmdUnregister(init: std.process.Init, args: *cmd.ArgIter) !void {
    const gpa = init.gpa;
    const io = init.io;

    const cargs = parseClientArgs(args) catch {
        printClientUsage();
        return;
    };

    const resolved_identity_name = resolveDefaultIdentityName(io, cargs.identity_name);

    var client = RegistryClient.init(gpa, io, init, cargs.identity_name) catch |err| {
        std.debug.print("[ERROR] Client initialization failed with: {any}\n", .{err});
        return;
    };

    const my_name = cargs.manual_name orelse resolved_identity_name;

    std.debug.print("[cli] Removing '{s}' from the server...\n", .{my_name});
    client.unregisterAtServer(io, cargs.server_host, cargs.port, my_name) catch |err| {
        std.debug.print("[✗] Removal failed: {any}\n", .{err});
    };
}

fn printClientUsage() void {
    std.debug.print(
        \\Usage:
        \\  sipreg resolve <target_name> [Options]
        \\  sipreg register [Options]
        \\  sipreg unregister [Options]
        \\
        \\Options:
        \\  --host HOST            Server host (Default: "::1")
        \\  -p, --port N           Server port (Default: {d})
        \\  -i, --identity NAME    Local identity to use (Default: "{s}")
        \\  -n, --name NAME        Manual registration name (Default: Identity name)
        \\  -ip, --ipv6 ADDR       Manual registration IPv6 (Default: Auto-generated)
        \\
    , .{ DEFAULT_PORT, DEFAULT_IDENTITY });
}

// =====================================================================
// Local registry viewer ("list")
// =====================================================================

const ViewCtx = struct {
    stdout: *Io.Writer,
    idx: usize = 1,
};

fn printRegistryEntry(ctx: *ViewCtx, entry: registry.RegistryEntry) !void {
    var ipv4_ipv6_buf: [80]u8 = undefined;
    var mesh_raw_buf: [registry.MESH_ADDR_SIZE * 2]u8 = undefined;
    var mesh_grouped_buf: [registry.MESH_ADDR_SIZE * 2 + 7]u8 = undefined;

    const addr_str = switch (entry.kind) {
        .ipv4 => blk: {
            const addr = entry.addr[0..4];
            break :blk try std.fmt.bufPrint(&ipv4_ipv6_buf, "{}.{}.{}.{}", .{
                addr[0], addr[1], addr[2], addr[3],
            });
        },
        .ipv6 => registry.formatIpv6(&ipv4_ipv6_buf, entry.addr[0..16].*),
        .mesh => registry.formatMeshAddr(&mesh_raw_buf, entry.addr[0..16].*),
    };

    try ctx.stdout.print("{d}: {s}: {s}", .{ ctx.idx, entry.name(), addr_str });

    if (entry.has_mesh) {
        const mesh_str = registry.formatMeshAddrGrouped(&mesh_grouped_buf, entry.mesh_addr);
        try ctx.stdout.print(" [mesh: {s}]", .{mesh_str});
    }

    if (entry.isDiscovered()) {
        try ctx.stdout.writeAll(" (discovered)");
    }

    try ctx.stdout.writeAll("\n");
    ctx.idx += 1;
}

fn cmdList(io: Io, stdout: *Io.Writer) !void {
    var ctx = ViewCtx{ .stdout = stdout };

    registry.forEachRecord(io, *ViewCtx, &ctx, struct {
        fn cb(c: *ViewCtx, entry: registry.RegistryEntry) !void {
            try printRegistryEntry(c, entry);
        }
    }.cb) catch |err| switch (err) {
        error.FileNotFound => {
            try stdout.writeAll("Registry not found.\n");
            try stdout.flush();
            return;
        },
        else => return err,
    };

    if (ctx.idx == 1) {
        try stdout.writeAll("No registry entries found.\n");
    }
    try stdout.flush();
}

// =====================================================================
// Discovery / trust-on-first-use flow ("discover")
// =====================================================================
fn cmdDiscover(init: std.process.Init, stdout: *Io.Writer, args: *cmd.ArgIter) !void {
    const io = init.io;
    const gpa = init.gpa;

    const prev_arg = args.argv[args.idx.* - 1];
    if (std.mem.eql(u8, "list", prev_arg)) {}

    const query = args.next() orelse {
        try stdout.writeAll("Usage: sipreg discover <ipv6-or-unreg-name>\n");
        try stdout.flush();
        return;
    };

    const config = sipd_lib.loadConfig(io, gpa, DEFAULT_SIPD_CONFIG) catch |err| {
        try stdout.print("Error loading sipd config: {}\n", .{err});
        try stdout.flush();
        return;
    };
    defer {
        gpa.free(config.identity_name);
        if (config.host) |h| gpa.free(h);
        if (config.output_path) |o| gpa.free(o);
    }

    var pw_buf: [256]u8 = undefined;
    const password = cmd.resolvePassword(io, stdout, init.environ_map, .{ .env_name = "SIPREG_PASSWORD" }, &pw_buf, false) catch |err| {
        try stdout.print("Error resolving password: {}\n", .{err});
        try stdout.flush();
        return;
    };

    const kp = keymng.loadIdentity(io, config.identity_name, password) catch |err| {
        try stdout.print("Error loading identity '{s}': {}\n", .{ config.identity_name, err });
        try stdout.flush();
        return;
    };

    const our_base_addr = sip.identity.baseAddress(kp.public);
    try stdout.print("[sipreg] Loading identity '{s}', base: {x}\n", .{ config.identity_name, our_base_addr });

    const resolved = registry.resolve(io, query) catch |err| {
        try stdout.print("Error resolving '{s}': {}\n", .{ query, err });
        try stdout.flush();
        return;
    };

    if (resolved.entry.kind != .ipv6) {
        try stdout.writeAll("Error: resolved entry is not IPv6 type\n");
        try stdout.flush();
        return;
    }

    if (resolved.entry.resolved_mesh == null) {
        try stdout.writeAll("Error: no mesh address associated with this entry\n");
        try stdout.flush();
        return;
    }

    const peer_ipv6 = resolved.entry.ipv6;
    const peer_mesh = resolved.entry.resolved_mesh.?;

    var ipv6_buf: [50]u8 = undefined;
    var mesh_buf: [registry.MESH_ADDR_SIZE * 2]u8 = undefined;
    const ipv6_str = registry.formatIpv6(&ipv6_buf, peer_ipv6);
    const mesh_str = registry.formatMeshAddr(&mesh_buf, peer_mesh);

    try stdout.print("[sipreg] Resolved '{s}':\n", .{query});
    try stdout.print("  IPv6: {s}\n", .{ipv6_str});
    try stdout.print("  Mesh: {s}\n", .{mesh_str});
    try stdout.print("  Discovered: {}\n", .{resolved.source == .registry and registry.isDiscoveredName(resolved.matchedName())});

    try stdout.print("[sipreg] Sende Discovery-Paket an {s}:{d}...\n", .{ ipv6_str, config.port });
    try stdout.flush();

    const sock = try sip.synet.createTcpSocketFamily(std.posix.AF.INET6);
    defer sip.synet.close(sock);

    const peer_sockaddr = sip.synet.buildSockaddrIn6(peer_ipv6, config.port);
    sip.synet.connect6(sock, &peer_sockaddr) catch |err| {
        try stdout.print("Error: Verbindung zu {s}:{d} fehlgeschlagen: {}\n", .{ ipv6_str, config.port, err });
        try stdout.flush();
        return;
    };

    var disc_buf: [sip.header.OUTER_HEADER_SIZE]u8 = undefined;
    const disc_pkt = try sip.header.buildDiscoveryPacket(&disc_buf, our_base_addr, [_]u8{0} ** 16);

    sip.synet.sendAll(sock, disc_pkt) catch |err| {
        try stdout.print("Error: Discovery-Paket konnte nicht gesendet werden: {}\n", .{err});
        try stdout.flush();
        return;
    };

    var reply_buf: [34]u8 = undefined;
    sip.synet.recvExact(sock, &reply_buf) catch |err| {
        try stdout.print("Error: Keine Antwort auf Discovery-Paket: {}\n", .{err});
        try stdout.flush();
        return;
    };

    if (reply_buf[0] != sip.header.MAGIC) {
        try stdout.writeAll("Error: Ungültiges Magic-Byte in Discovery-Antwort\n");
        try stdout.flush();
        return;
    }

    var fresh_peer_addr: [16]u8 = undefined;
    @memcpy(&fresh_peer_addr, reply_buf[2..18]);

    // TODO: hier soll später noch mehr Logik rein (z.B. Re-Trust-Flow)
    if (!std.mem.eql(u8, &fresh_peer_addr, &peer_mesh)) {
        try stdout.writeAll("Error: Peer-Identität hat sich geändert! Erwartete SIP-Adresse stimmt nicht mit der Discovery-Antwort überein.\n");
        try stdout.print("  Erwartet: {x}\n", .{peer_mesh});
        try stdout.print("  Erhalten: {x}\n", .{fresh_peer_addr});
        try stdout.flush();
        return error.PeerIdentityMismatch;
    }

    try stdout.print("[sipreg] Discovery bestätigt: {x}\n", .{fresh_peer_addr});
    try stdout.flush();

    try stdout.writeAll("\nEnter label to register (or Ctrl+C to cancel):\n");
    try stdout.writeAll("> ");
    try stdout.flush();

    var label_buf: [64]u8 = undefined;
    const n_rc = linux.read(0, &label_buf, label_buf.len);
    const n_signed: isize = @bitCast(n_rc);
    if (n_signed <= 0) {
        try stdout.writeAll("Error reading input\n");
        try stdout.flush();
        return;
    }
    const n: usize = @intCast(n_signed);
    const label = std.mem.trim(u8, label_buf[0..n], " \t\r\n");

    if (label.len == 0 or label.len > registry.MAX_NAME_LEN) {
        try stdout.writeAll("Error: label must be 1-64 characters\n");
        try stdout.flush();
        return;
    }

    var entry = registry.Entry.fromIpv6(peer_ipv6);
    entry.resolved_mesh = peer_mesh;

    try registry.register(io, label, entry);
    try stdout.print("[sipreg] Registered '{s}' (IPv6: {s})\n", .{ label, ipv6_str });
    try stdout.flush();
}

// =====================================================================
// Dispatch
// =====================================================================

fn printHelp(stdout: anytype) !void {
    try stdout.print(
        \\sipreg
        \\
        \\Server:
        \\  sipreg server [config_path]     Start the registry server
        \\                                    (Default config: /etc/sip/sipd.conf)
        \\
        \\Client:
        \\  sipreg resolve <name> [Options] Resolve a name against a server
        \\  sipreg register [Options]       Register this identity at a server
        \\  sipreg unregister [Options]     Remove this identity from a server
        \\
        \\  Options:
        \\    --host HOST            Server host (Default: "::1")
        \\    -p, --port N           Server port (Default: {d})
        \\    -i, --identity NAME    Local identity to use (Default: "{s}")
        \\    -n, --name NAME        Manual registration name (Default: Identity name)
        \\    -ip, --ipv6 ADDR       Manual registration IPv6 (Default: Auto-generated)
        \\
        \\Local:
        \\  sipreg list                     List all local registry entries
        \\  sipreg discover <target>        Discover + trust-register a peer
        \\                                    (resolves an unreg/name entry, verifies
        \\                                    identity via Discovery packet, then
        \\                                    prompts for a label to register it under)
        \\
        \\  sipreg -h, --help               Show this help message
        \\
    , .{ DEFAULT_PORT, DEFAULT_IDENTITY });
}

pub fn main(init: std.process.Init) !void {
    const io = init.io;

    var stdout_buf: [4096]u8 = undefined;
    var stdout_w = Io.File.stdout().writer(io, &stdout_buf);
    const stdout = &stdout_w.interface;

    defer stdout_w.flush() catch {};

    const arena_alloc = init.arena.allocator();
    const argv = try init.minimal.args.toSlice(arena_alloc);

    var arg_idx: usize = 1;
    var args = cmd.ArgIter{ .argv = argv, .idx = &arg_idx };

    const first = args.next() orelse {
        try printHelp(stdout);
        return; // Jetzt wird vor dem Exit geflusht!
    };

    if (std.mem.eql(u8, first, "-h") or std.mem.eql(u8, first, "--help")) {
        try printHelp(stdout);
        return;
    } else if (std.mem.eql(u8, first, "server")) {
        try cmdServer(init, &args);
    } else if (std.mem.eql(u8, first, "resolve")) {
        try cmdResolve(init, &args);
    } else if (std.mem.eql(u8, first, "register")) {
        try cmdRegister(init, &args);
    } else if (std.mem.eql(u8, first, "unregister")) {
        try cmdUnregister(init, &args);
    } else if (std.mem.eql(u8, first, "list")) {
        try cmdList(io, stdout);
    } else if (std.mem.eql(u8, first, "discover")) {
        try cmdDiscover(init, stdout, &args);
    } else {
        try stdout.print("Unknown command: '{s}'\n", .{first});
        try stdout.writeAll("See 'sipreg --help' for help.\n");
        try stdout.flush();
    }
}
