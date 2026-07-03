const std = @import("std");
const keymng = @import("keymng.zig");

fn printUsage() void {
    std.debug.print(
        \\setdefault - Manage the default identity for SIP tools
        \\
        \\  setdefault              Show the current default
        \\  setdefault <name>       Set the default to <name>
        \\
    , .{});
}

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const argv = try init.minimal.args.toSlice(init.arena.allocator());

    if (argv.len < 2) {
        var buf: [64]u8 = undefined;
        const current = keymng.readDefaultIdentity(&buf) catch {
            std.debug.print("No default identity is set.\n", .{});
            return;
        };
        std.debug.print("Current default: {s}\n", .{current});
        return;
    }

    const name = argv[1];

    if (!keymng.validName(name)) {
        std.debug.print("Invalid identity name: {s}\n", .{name});
        return error.InvalidName;
    }

    if (!keymng.identityExists(io, name)) {
        std.debug.print("Identity '{s}' does not exist.\n", .{name});
        printUsage();
        return error.IdentityNotFound;
    }

    try keymng.setDefaultIdentity(name);
    std.debug.print("Default identity set to: {s}\n", .{name});
}
