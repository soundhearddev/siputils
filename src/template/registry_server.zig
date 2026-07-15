const std = @import("std");
const sip = @import("sip");
const utils = @import("siputils");

const Io = std.Io;
const synet = sip.synet;
const handshake = sip.handshake;
const translation = sip.translation;
const protocol = sip.protocol;

const keymng = utils.keymng;
const fs = utils.filesystem;
const cmd = utils.cmdhandler;
const registry = utils.registry;

pub const CONFIG_PATH: []const u8 = fs.get_config_path();

pub var should_shutdown: std.atomic.Value(bool) = std.atomic.Value(bool).init(false);

const HandlerContext = struct {
    keys: sip.identity.KeyPair,
    allocator: std.mem.Allocator,
    verbose: bool,
};

fn handleQuery(
    io: Io,
    ctx: *HandlerContext,
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
    ctx: *HandlerContext,
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
    ctx: *HandlerContext,
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
    ctx: *HandlerContext,
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
    ctx: *HandlerContext,
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

fn handleConnection(io: Io, ctx: *HandlerContext, conn: synet.Socket) void {
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

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;

    const args = try init.minimal.args.toSlice(gpa);
    defer gpa.free(args);

    const config_path = if (args.len > 1) args[1] else CONFIG_PATH;

    std.debug.print("[registry] Loading configuration from: {s}...\n", .{config_path});

    const config = try utils.sipd.loadConfig(io, gpa, config_path);
    defer {
        if (config.host) |h| gpa.free(h);
        if (config.output_path) |o| gpa.free(o);
        gpa.free(config.identity_name);
    }

    const keys = try utils.sipd.loadOrCreateIdentity(init, config.identity_name);

    std.debug.print("[registry] Identity '{s}' loaded successfully.\n", .{config.identity_name});

    const listener = try utils.sipd.createListener(config);
    defer synet.close(listener);

    std.debug.print("[registry] Server listening on port {} (IPv6: {})...\n", .{ config.port, config.use_v6 });

    var context = HandlerContext{
        .keys = keys,
        .allocator = gpa,
        .verbose = config.verbose,
    };

    while (!should_shutdown.load(.acquire)) {
        const conn = synet.accept(listener) catch |err| {
            if (should_shutdown.load(.acquire)) break;
            std.debug.print("[ERROR] Accept failed: {any}\n", .{err});
            continue;
        };

        utils.sipd.setCurrentConnection(io, conn);
        handleConnection(io, &context, conn);
        utils.sipd.clearCurrentConnection(io);
    }
}
