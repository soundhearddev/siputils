const std = @import("std");
const utils = @import("utils.zig");

const DEBUG = true;
const ANZAHL_IPS: usize = 1;
const LEBENSDAUER_SEKUNDEN: ?u64 = 60;

fn buildAddress(gpa: std.mem.Allocator, io: std.Io, count: usize, prefix: []const u8, before: *std.StringHashMap(void), iface: []const u8, ttl: ?u64, init: std.process.Init) !std.ArrayListUnmanaged([]const u8) {
    var created: std.ArrayListUnmanaged([]const u8) = .empty;

    for (0..count) |_| {
        var new_addr = try utils.generateAddress(gpa, prefix, init);

        while (before.contains(new_addr)) {
            gpa.free(new_addr);
            new_addr = try utils.generateAddress(gpa, prefix, init);
        }

        const success = try utils.addAddress(gpa, io, iface, new_addr, ttl);
        if (success) {
            try created.append(gpa, new_addr);
            try before.put(new_addr, {});
            if (ttl) |t| {
                std.debug.print("[✓] {s} (TTL: {d}s)\n", .{ new_addr, t });
            } else {
                std.debug.print("[✓] {s} (Permanent)\n", .{new_addr});
            }
        } else {
            std.debug.print("[✗] Error at {s}\n", .{new_addr});
            gpa.free(new_addr);
        }
    }
    return created;
}

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;

    utils.isRoot();

    var interface: []u8 = undefined;
    if (DEBUG) {
        std.debug.print("[MODE] DEBUG mode active. Using dummy interface.\n", .{});
        interface = try utils.ensureDummyIface(gpa, io, "ipwrap0");
    } else {
        std.debug.print("[MODE] LIVE mode active. Determining default interface...\n", .{});
        interface = try utils.getDefaultIface(gpa, io);
        std.debug.print("[i] Default interface found: {s}\n", .{interface});
    }
    defer gpa.free(interface);

    var prefix: []u8 = undefined;
    if (utils.getPrefix(gpa, io, interface)) |p| {
        prefix = p;
    } else |_| {
        if (DEBUG) {
            prefix = try gpa.dupe(u8, "2001:db8:1234:5678:");
            std.debug.print("[i] Dummy has no prefix. Using test prefix: {s}\n", .{prefix});
        } else {
            std.process.exit(1);
        }
    }
    defer gpa.free(prefix);

    var already_assigned = try utils.currentAddresses(gpa, io, interface);
    defer {
        var it = already_assigned.keyIterator();
        while (it.next()) |key| gpa.free(key.*);
        already_assigned.deinit();
    }

    std.debug.print("\nStarting generation of {d} addresses on '{s}'...\n", .{ ANZAHL_IPS, interface });

    var created = try buildAddress(gpa, io, ANZAHL_IPS, prefix, &already_assigned, interface, LEBENSDAUER_SEKUNDEN, init);
    defer created.deinit(gpa);
}
