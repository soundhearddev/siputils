const std = @import("std");
extern fn get_unix_time() u32;

pub fn isRoot() void {
    const uid = std.os.linux.getuid();
    if (uid != 0) {
        std.debug.print("[✗] Dieses Programm muss als root ausgeführt werden (aktuell UID={d}).\n", .{uid});
        std.process.exit(1);
    }
}

fn run(gpa: std.mem.Allocator, io: std.Io, argv: []const []const u8) !std.process.RunResult {
    return std.process.run(gpa, io, .{ .argv = argv });
}

pub fn ensureDummyIface(gpa: std.mem.Allocator, io: std.Io, name: []const u8) ![]u8 {
    const check = try std.process.run(gpa, io, .{
        .argv = &.{ "ip", "link", "show", name },
    });
    defer gpa.free(check.stdout);
    defer gpa.free(check.stderr);

    if (check.term.exited != 0) {
        std.debug.print("[i] Dummy-Interface '{s}' nicht gefunden. Erstelle es...\n", .{name});

        const add = try std.process.run(gpa, io, .{
            .argv = &.{ "ip", "link", "add", name, "type", "dummy" },
        });
        gpa.free(add.stdout);
        gpa.free(add.stderr);

        const up = try std.process.run(gpa, io, .{
            .argv = &.{ "ip", "link", "set", name, "up" },
        });
        gpa.free(up.stdout);
        gpa.free(up.stderr);
    }

    return gpa.dupe(u8, name);
}

pub fn getDefaultIface(gpa: std.mem.Allocator, io: std.Io) ![]u8 {
    const result = try std.process.run(gpa, io, .{
        .argv = &.{ "ip", "-o", "-4", "route", "show", "default" },
    });
    defer gpa.free(result.stdout);
    defer gpa.free(result.stderr);

    var it = std.mem.splitScalar(u8, result.stdout, ' ');
    var found_dev = false;
    while (it.next()) |token| {
        const t = std.mem.trim(u8, token, "\n\r\t ");
        if (found_dev and t.len > 0) return gpa.dupe(u8, t);
        if (std.mem.eql(u8, t, "dev")) found_dev = true;
    }
    return error.NoDefaultInterface;
}

pub fn getPrefix(gpa: std.mem.Allocator, io: std.Io, iface: []const u8) ![]u8 {
    const result = try std.process.run(gpa, io, .{
        .argv = &.{ "ip", "-6", "addr", "show", iface },
    });
    defer gpa.free(result.stdout);
    defer gpa.free(result.stderr);

    var lines = std.mem.splitScalar(u8, result.stdout, '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t");
        if (!std.mem.startsWith(u8, trimmed, "inet6")) continue;
        if (std.mem.indexOf(u8, trimmed, "scope global") == null) continue;

        var toks = std.mem.splitScalar(u8, trimmed, ' ');
        _ = toks.next(); // "inet6"
        const addr_cidr = toks.next() orelse continue;

        const slash = std.mem.indexOf(u8, addr_cidr, "/") orelse addr_cidr.len;
        const addr = addr_cidr[0..slash];

        var colon_count: usize = 0;
        var prefix_end: usize = 0;
        for (addr, 0..) |c, i| {
            if (c == ':') {
                colon_count += 1;
                if (colon_count == 4) {
                    prefix_end = i + 1;
                    break;
                }
            }
        }
        if (prefix_end == 0) continue;
        return gpa.dupe(u8, addr[0..prefix_end]);
    }

    return error.NoPrefixFound;
}

pub fn generateAddress(gpa: std.mem.Allocator, prefix: []const u8) ![]u8 {
    const seed: u64 = @as(u64, get_unix_time());
    var prng = std.Random.DefaultPrng.init(seed);
    const rng = prng.random();
    const a = rng.int(u16);
    const b = rng.int(u16);
    const c = rng.int(u16);
    const d = rng.int(u16);
    return std.fmt.allocPrint(gpa, "{s}{x:0>4}:{x:0>4}:{x:0>4}:{x:0>4}", .{ prefix, a, b, c, d });
}

pub fn addAddress(gpa: std.mem.Allocator, io: std.Io, iface: []const u8, address: []const u8, ttl: ?u64) !bool {
    const addr_cidr = try std.fmt.allocPrint(gpa, "{s}/64", .{address});
    defer gpa.free(addr_cidr);

    var argv: std.ArrayListUnmanaged([]const u8) = .empty;
    defer argv.deinit(gpa);
    try argv.appendSlice(gpa, &.{ "ip", "-6", "addr", "add", addr_cidr, "dev", iface });

    var ttl_str: ?[]u8 = null;
    if (ttl) |t| {
        ttl_str = try std.fmt.allocPrint(gpa, "{d}", .{t});
        try argv.appendSlice(gpa, &.{ "valid_lft", ttl_str.?, "preferred_lft", ttl_str.? });
    }
    defer if (ttl_str) |s| gpa.free(s);

    const result = try std.process.run(gpa, io, .{ .argv = argv.items });
    defer gpa.free(result.stdout);
    defer gpa.free(result.stderr);

    return result.term.exited == 0;
}

pub fn currentAddresses(gpa: std.mem.Allocator, io: std.Io, iface: []const u8) !std.StringHashMap(void) {
    var set = std.StringHashMap(void).init(gpa);

    const result = try std.process.run(gpa, io, .{
        .argv = &.{ "ip", "-6", "addr", "show", iface },
    });
    defer gpa.free(result.stdout);
    defer gpa.free(result.stderr);

    var lines = std.mem.splitScalar(u8, result.stdout, '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t");
        if (!std.mem.startsWith(u8, trimmed, "inet6")) continue;

        var toks = std.mem.splitScalar(u8, trimmed, ' ');
        _ = toks.next();
        const addr_cidr = toks.next() orelse continue;
        const slash = std.mem.indexOf(u8, addr_cidr, "/") orelse addr_cidr.len;
        const addr = try gpa.dupe(u8, addr_cidr[0..slash]);
        try set.put(addr, {});
    }
    return set;
}







pub fn randomMeshAddr(io: std.Io) [16]u8 {
    const rng_src: std.Random.IoSource = .{ .io = io };
    const rand = rng_src.interface();
    var addr: [16]u8 = undefined;
    rand.bytes(&addr);
    return addr;
}
