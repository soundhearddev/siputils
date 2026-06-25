const std = @import("std");
const sip = @import("sip");

pub fn randomMeshAddr(io: std.Io) [16]u8 {
    const rng_src: std.Random.IoSource = .{ .io = io };
    const rand = rng_src.interface();
    var addr: [16]u8 = undefined;
    rand.bytes(&addr);
    return addr;
}
pub fn randomConnId(io: std.Io) u64 {
    const rng_src: std.Random.IoSource = .{ .io = io };
    const rand = rng_src.interface();
    return rand.int(u64);
}

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const allocator = std.heap.page_allocator;

    const cwd = std.Io.Dir.cwd();
    const file = try cwd.openFile(io, "./dump/linux.svg", .{ .mode = .read_only });
    defer file.close(io);

    const file_size = (try file.stat(io)).size;
    const bytes = try allocator.alloc(u8, file_size);
    defer allocator.free(bytes);

    var fr = file.reader(io, bytes);
    try fr.interface.fill(file_size);

    const src = randomMeshAddr(init.io);
    const dst = randomMeshAddr(init.io);
    const conn_id = randomConnId(init.io);

    const total = sip.header.HEADER_SIZE + bytes.len;
    const buf = try allocator.alloc(u8, total);
    defer allocator.free(buf);

    const pkt = try sip.header.buildPacket(buf, src, dst, conn_id, .Data, bytes);

    std.debug.print("HEADER HEX:\n", .{});
    for (pkt[0..sip.header.HEADER_SIZE], 0..) |b, i| {
        std.debug.print("{d:0>3} ", .{b});
        if ((i + 1) % 8 == 0) std.debug.print("\n", .{});
    }
    std.debug.print("\nPaket gebaut: {d} Bytes\n", .{pkt.len});

    const parsed = try sip.header.parsePacket(pkt);
    std.debug.print("Payload: {d} Byte\n", .{parsed.payload.len});
    std.debug.print("Command: {}\n", .{parsed.command});
}
