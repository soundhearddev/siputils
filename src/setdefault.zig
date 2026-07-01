const std = @import("std");
const keymng = @import("keymng.zig");

fn printUsage() void {
    std.debug.print(
        \\setdefault - Standard-Identity für sip-Tools verwalten
        \\
        \\  setdefault              zeigt aktuellen Default
        \\  setdefault <name>       setzt Default auf <name>
        \\
    , .{});
}

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const argv = try init.minimal.args.toSlice(init.arena.allocator());

    if (argv.len < 2) {
        var buf: [64]u8 = undefined;
        const current = keymng.readDefaultIdentity(&buf) catch {
            std.debug.print("Kein Default gesetzt.\n", .{});
            return;
        };
        std.debug.print("Aktueller Default: {s}\n", .{current});
        return;
    }

    const name = argv[1];

    if (!keymng.validName(name)) {
        std.debug.print("Ungültiger Identity-Name: {s}\n", .{name});
        return error.InvalidName;
    }

    if (!keymng.identityExists(io, name)) {
        std.debug.print("Identity '{s}' existiert nicht.\n", .{name});
        printUsage();
        return error.IdentityNotFound;
    }

    try keymng.setDefaultIdentity(name);
    std.debug.print("Default gesetzt auf: {s}\n", .{name});
}
