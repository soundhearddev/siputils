const std = @import("std");

pub fn main() !void {
    const input = "";

    if (input.len != 32) {
        std.debug.print("Error: expected 32 hex chars (16 bytes), got {d}\n", .{input.len});
        return;
    }

    var bytes: [16]u8 = undefined;

    for (0..16) |i| {
        bytes[i] = std.fmt.parseInt(u8, input[i * 2 .. i * 2 + 2], 16) catch {
            std.debug.print("Error: invalid hex at position {d}\n", .{i * 2});
            return;
        };
    }

    std.debug.print("hex: ", .{});
    for (bytes) |b| std.debug.print("{x:0>2} ", .{b});
    std.debug.print("\n", .{});

    std.debug.print("dec: ", .{});
    for (bytes) |b| std.debug.print("{d:0>3} ", .{b});
    std.debug.print("\n", .{});
}
