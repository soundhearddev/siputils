// eingelich abgelöst von sipreg.zig aber naja

const std = @import("std");
const Io = std.Io;
const utils = @import("siputils");
const registry = utils.registry;

const ViewCtx = struct {
    stdout: *Io.Writer,
    idx: usize = 1,
};

fn printRegistryEntry(ctx: *ViewCtx, entry: registry.RegistryEntry) !void {
    var ipv4_ipv6_buf: [80]u8 = undefined;

    // Zwei dedizierte Puffer mit exakter Größe für die jeweilige Funktion:
    var mesh_raw_buf: [registry.MESH_ADDR_SIZE * 2]u8 = undefined; // 32 Byte
    var mesh_grouped_buf: [registry.MESH_ADDR_SIZE * 2 + 3]u8 = undefined; // 35 Byte

    const addr_str = switch (entry.kind) {
        .ipv4 => blk: {
            const addr = entry.addr[0..4];
            break :blk try std.fmt.bufPrint(&ipv4_ipv6_buf, "{}.{}.{}.{}", .{
                addr[0], addr[1], addr[2], addr[3],
            });
        },
        .ipv6 => registry.formatIpv6(&ipv4_ipv6_buf, entry.addr[0..16].*),
        // Hier bekommt die Funktion jetzt exakt ihr gewünschtes *[32]u8
        .mesh => registry.formatMeshAddr(&mesh_raw_buf, entry.addr[0..16].*),
    };

    try ctx.stdout.print("{d}: {s}: {s}", .{ ctx.idx, entry.name(), addr_str });

    if (entry.has_mesh) {
        // Und hier bekommt die Grouped-Variante exakt ihr *[35]u8
        const mesh_str = registry.formatMeshAddrGrouped(&mesh_grouped_buf, entry.mesh_addr);
        try ctx.stdout.print(" [mesh: {s}]", .{mesh_str});
    }

    if (entry.isDiscovered()) {
        try ctx.stdout.writeAll(" (discovered)");
    }

    try ctx.stdout.writeAll("\n");
    ctx.idx += 1;
}

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    var stdout_buf: [4096]u8 = undefined;
    var stdout_w = Io.File.stdout().writer(io, &stdout_buf);
    const stdout = &stdout_w.interface;

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
