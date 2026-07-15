const std = @import("std");
const sip = @import("sip");
const utils = @import("root.zig");

const keymng = utils.keymng;
const fs = utils.filesystem;
const cmd = utils.cmdhandler;

pub const CONFIG_PATH: []const u8 = fs.get_config_path();
pub const DEFAULT_PORT: u16 = 9443;

pub fn verbosePrint(verbose: bool, comptime fmt: []const u8, args: anytype) void {
    if (verbose) {
        std.debug.print(fmt, args);
    }
}

pub const DaemonConfig = struct {
    identity_name: []const u8,
    host: ?[]const u8 = null,
    port: u16 = DEFAULT_PORT,
    use_v6: bool = false,
    output_path: ?[]const u8 = null,
    verbose: bool = false,
};

pub fn loadConfig(io: std.Io, allocator: std.mem.Allocator, path: []const u8) !DaemonConfig {
    const cwd = std.Io.Dir.cwd();
    const raw = cwd.readFileAlloc(io, path, allocator, .unlimited) catch |err| {
        std.debug.print("[sipd] Error: Cannot open configuration: {s} ({any})\n", .{ path, err });
        return err;
    };
    defer allocator.free(raw);

    var identity_name: ?[]u8 = null;
    var host: ?[]u8 = null;
    var port: u16 = DEFAULT_PORT;
    var use_v6: bool = false;
    var output_path: ?[]u8 = null;
    var verbose: bool = false;

    var lines = std.mem.splitScalar(u8, raw, '\n');
    var line_nr: usize = 0;

    errdefer {
        if (identity_name) |n| allocator.free(n);
        if (host) |h| allocator.free(h);
        if (output_path) |o| allocator.free(o);
    }

    while (lines.next()) |line_raw| {
        line_nr += 1;
        const line = std.mem.trim(u8, line_raw, " \t\r");

        if (line.len == 0 or line[0] == '#') continue;

        const eq = std.mem.indexOfScalar(u8, line, '=') orelse {
            std.debug.print("[sipd] Warning: Ignoring line {d} (no '='): {s}\n", .{ line_nr, line });
            continue;
        };

        const key = std.mem.trim(u8, line[0..eq], " \t");
        const val = std.mem.trim(u8, line[eq + 1 ..], " \t");

        if (std.mem.eql(u8, key, "identity_name")) {
            if (identity_name) |old| allocator.free(old);
            identity_name = try allocator.dupe(u8, val);
        } else if (std.mem.eql(u8, key, "host")) {
            if (host) |old| allocator.free(old);
            host = try allocator.dupe(u8, val);
        } else if (std.mem.eql(u8, key, "port")) {
            port = std.fmt.parseInt(u16, val, 10) catch {
                std.debug.print("[sipd] Error: Invalid port on line {d}: {s}\n", .{ line_nr, val });
                return error.InvalidPort;
            };
        } else if (std.mem.eql(u8, key, "use_v6")) {
            use_v6 = parseBool(val) catch {
                std.debug.print("[sipd] Error: Invalid boolean on line {d}: {s}\n", .{ line_nr, val });
                return error.InvalidBool;
            };
        } else if (std.mem.eql(u8, key, "output_path")) {
            if (output_path) |old| allocator.free(old);
            output_path = try allocator.dupe(u8, val);
        } else if (std.mem.eql(u8, key, "verbose")) {
            verbose = parseBool(val) catch {
                std.debug.print("[sipd] Error: Invalid boolean on line {d}: {s}\n", .{ line_nr, val });
                return error.InvalidBool;
            };
        } else {
            std.debug.print("[sipd] Warning: Unknown key on line {d}: {s}\n", .{ line_nr, key });
        }
    }

    const resolved_identity = identity_name orelse {
        std.debug.print("[sipd] Error: 'identity_name' missing in {s}\n", .{path});
        return error.MissingIdentity;
    };

    return DaemonConfig{
        .identity_name = resolved_identity,
        .host = host,
        .port = port,
        .use_v6 = use_v6,
        .output_path = output_path,
        .verbose = verbose,
    };
}

pub fn parseBool(s: []const u8) !bool {
    if (std.mem.eql(u8, s, "true") or std.mem.eql(u8, s, "1") or std.mem.eql(u8, s, "yes")) return true;
    if (std.mem.eql(u8, s, "false") or std.mem.eql(u8, s, "0") or std.mem.eql(u8, s, "no")) return false;
    return error.InvalidBool;
}

pub var should_shutdown: std.atomic.Value(bool) = std.atomic.Value(bool).init(false);
var current_connection: ?sip.synet.Socket = null;
var connection_mutex: std.Io.Mutex = .init;

pub fn setCurrentConnection(io: std.Io, conn: sip.synet.Socket) void {
    connection_mutex.lockUncancelable(io);
    defer connection_mutex.unlock(io);
    current_connection = conn;
}

pub fn clearCurrentConnection(io: std.Io) void {
    connection_mutex.lockUncancelable(io);
    defer connection_mutex.unlock(io);
    current_connection = null;
}

pub fn loadOrCreateIdentity(
    init: std.process.Init,
    identity_name: []const u8,
) !sip.identity.KeyPair {
    const io = init.io;

    var stdout_io_buf: [1024]u8 = undefined;
    var stdout_struct = std.Io.File.stdout().writer(io, &stdout_io_buf);
    const stdout_writer = &stdout_struct.interface;

    var pw_buf: [256]u8 = undefined;

    if (keymng.identityExists(io, identity_name)) {
        const password = try cmd.resolvePassword(io, stdout_writer, init.environ_map, .{ .env_name = "SIPD_PASSWORD" }, &pw_buf, false);

        return keymng.loadIdentity(io, identity_name, password);
    } else {
        std.debug.print("[sipd] '{s}' not found\n", .{identity_name});
        if (!keymng.validName(identity_name)) {
            std.debug.print("[sipd] Invalid identity name\n", .{});
            return error.InvalidIdentityName;
        }

        const password = try cmd.resolvePassword(io, stdout_writer, init.environ_map, .{ .env_name = "SIPD_PASSWORD" }, &pw_buf, true);

        return keymng.createIdentity(io, identity_name, password) catch |err| {
            std.debug.print("[sipd] Error creating identity: {any}\n", .{err});
            return err;
        };
    }
}

pub fn createListener(config: DaemonConfig) !sip.synet.Socket {
    const listener = if (config.use_v6)
        try sip.synet.createTcpSocketFamily(std.posix.AF.INET6)
    else
        try sip.synet.createTcpSocket();
    errdefer sip.synet.close(listener);

    if (config.use_v6) {
        var ip_bytes = [_]u8{0} ** 16;
        if (config.host) |h| {
            if (std.mem.eql(u8, h, "::1")) {
                ip_bytes[15] = 1;
            } else if (std.mem.eql(u8, h, "::")) {} else {
                std.debug.print("[sipd] Error: IPv6 parsing for '{s}' not implemented (use '::1' or '::')\n", .{h});
                return error.UnsupportedIPv6Format;
            }
        }
        const bind_addr = sip.synet.buildSockaddrIn6(ip_bytes, config.port);
        try sip.synet.bind6(listener, &bind_addr);
    } else {
        var ip_bytes = [_]u8{ 0, 0, 0, 0 };
        if (config.host) |h| {
            var it = std.mem.splitScalar(u8, h, '.');
            var i: usize = 0;
            while (it.next()) |part| : (i += 1) {
                if (i >= 4) return error.InvalidAddress;
                ip_bytes[i] = std.fmt.parseInt(u8, part, 10) catch {
                    std.debug.print("[sipd] Error: Invalid IPv4 component '{s}' in '{s}'\n", .{ part, h });
                    return error.InvalidAddress;
                };
            }
            if (i != 4) {
                std.debug.print("[sipd] Error: IPv4 address '{s}' does not have 4 segments\n", .{h});
                return error.InvalidAddress;
            }
        }
        const bind_addr = sip.synet.buildSockaddrIn(ip_bytes, config.port);
        try sip.synet.bind(listener, &bind_addr);
    }

    try sip.synet.listen(listener, 1);
    return listener;
}

pub fn acceptLoop(
    io: std.Io,
    listener: sip.synet.Socket,
    context: anytype,
    comptime handler: fn (io: std.Io, ctx: @TypeOf(context), conn: sip.synet.Socket) void,
) !void {
    while (!should_shutdown.load(.acquire)) {
        const conn = sip.synet.accept(listener) catch |err| {
            if (should_shutdown.load(.acquire)) break;
            return err;
        };

        setCurrentConnection(io, conn);
        handler(io, context, conn);
        clearCurrentConnection(io);
    }
}
