const std = @import("std");
const Io = std.Io;
const fs = @import("filesystem.zig");

pub const REGISTRY_FILE = fs.get_bin_path() ++ "/registry.bin";
pub const SUFFIX = ".mesh";
// SIP-Adressen sind 16 Byte (siehe identity.baseAddress / Discovery-Paket-
// format in header.zig). Vorher stand hier 32 und die oberen 16 Byte waren
// überall im Code stumpfes Null-Padding (siehe toMeshAddr im Sniffer und
// der analoge Code in cmdhandler.zig) -- reine Verschwendung, die auch die
// Lesbarkeit der Registry-Anzeige unnötig aufgebläht hat.
pub const MESH_ADDR_SIZE: usize = 16;
pub const UNREG_PREFIX = "unreg:";

const MAGIC = "SDNS";
const VERSION: u8 = 1;
const HEADER_SIZE: usize = 16;
const RECORD_SIZE: usize = 128;
pub const MAX_NAME_LEN: usize = 64;

const FLAG_DELETED: u16 = 0x0001;
const FLAG_HAS_MESH: u16 = 0x0002;

pub const AddressKind = enum(u8) { mesh = 0, ipv4 = 1, ipv6 = 2 };

pub const Entry = struct {
    kind: AddressKind,
    mesh: [MESH_ADDR_SIZE]u8 = [_]u8{0} ** MESH_ADDR_SIZE,
    ipv4: [4]u8 = [_]u8{0} ** 4,
    ipv6: [16]u8 = [_]u8{0} ** 16,
    resolved_mesh: ?[MESH_ADDR_SIZE]u8 = null,

    pub fn fromIpv4(addr: [4]u8) Entry {
        var e = Entry{ .kind = .ipv4 };
        e.ipv4 = addr;
        return e;
    }

    pub fn fromIpv6(addr: [16]u8) Entry {
        var e = Entry{ .kind = .ipv6 };
        e.ipv6 = addr;
        return e;
    }

    pub fn fromMesh(addr: [MESH_ADDR_SIZE]u8) Entry {
        var e = Entry{ .kind = .mesh };
        e.mesh = addr;
        return e;
    }
};

pub const ResolveSource = enum {
    direct_ipv4,
    direct_ipv6,
    registry,
    registry_partial,
};

pub const ResolveResult = struct {
    source: ResolveSource,
    entry: Entry,
    matched_name_buf: [MAX_NAME_LEN]u8 = [_]u8{0} ** MAX_NAME_LEN,
    matched_name_len: usize = 0,

    pub fn matchedName(self: *const ResolveResult) []const u8 {
        return self.matched_name_buf[0..self.matched_name_len];
    }
};

pub const RegistryError = error{
    NameTooLong,
    Ambiguous,
    NotFound,
    RegistryFileTooLarge,
    CorruptFile,
};

pub const RegistryEntry = struct {
    name_buf: [MAX_NAME_LEN]u8,
    name_len: usize,
    kind: AddressKind,
    addr: [32]u8,
    mesh_addr: [MESH_ADDR_SIZE]u8,
    has_mesh: bool,

    pub fn name(self: *const RegistryEntry) []const u8 {
        return self.name_buf[0..self.name_len];
    }

    pub fn isDiscovered(self: *const RegistryEntry) bool {
        return isDiscoveredName(self.name());
    }
};

const Header = extern struct {
    magic: [4]u8,
    version: u8,
    _pad0: [3]u8 = [_]u8{0} ** 3,
    count: u32,
    _pad1: [4]u8 = [_]u8{0} ** 4,

    comptime {
        std.debug.assert(@sizeOf(Header) == HEADER_SIZE);
    }
};

const Record = extern struct {
    name: [65]u8,
    kind: u8,
    addr: [32]u8,
    mesh_addr: [MESH_ADDR_SIZE]u8 = [_]u8{0} ** MESH_ADDR_SIZE,
    flags: u16,
    _pad: [12]u8 = [_]u8{0} ** 12,

    comptime {
        std.debug.assert(@sizeOf(Record) == RECORD_SIZE);
    }

    fn isDeleted(self: *const Record) bool {
        return (self.flags & FLAG_DELETED) != 0;
    }

    fn hasMesh(self: *const Record) bool {
        return (self.flags & FLAG_HAS_MESH) != 0;
    }

    fn getName(self: *const Record) []const u8 {
        const len = std.mem.indexOfScalar(u8, &self.name, 0) orelse self.name.len;
        return self.name[0..len];
    }

    fn toEntry(self: *const Record) ?Entry {
        var e: Entry = switch (self.kind) {
            @intFromEnum(AddressKind.ipv4) => Entry.fromIpv4(self.addr[0..4].*),
            @intFromEnum(AddressKind.ipv6) => Entry.fromIpv6(self.addr[0..16].*),
            @intFromEnum(AddressKind.mesh) => Entry.fromMesh(self.addr[0..MESH_ADDR_SIZE].*),
            else => return null,
        };
        if (self.hasMesh()) {
            e.resolved_mesh = self.mesh_addr;
        }
        return e;
    }

    fn fromEntry(name: []const u8, entry: Entry) Record {
        var r = Record{
            .name = [_]u8{0} ** 65,
            .kind = @intFromEnum(entry.kind),
            .addr = [_]u8{0} ** 32,
            .mesh_addr = [_]u8{0} ** MESH_ADDR_SIZE,
            .flags = 0,
        };
        const copy_len = @min(name.len, 64);
        @memcpy(r.name[0..copy_len], name[0..copy_len]);
        switch (entry.kind) {
            .ipv4 => @memcpy(r.addr[0..4], &entry.ipv4),
            .ipv6 => @memcpy(r.addr[0..16], &entry.ipv6),
            .mesh => @memcpy(r.addr[0..MESH_ADDR_SIZE], &entry.mesh),
        }
        if (entry.resolved_mesh) |m| {
            r.mesh_addr = m;
            r.flags |= FLAG_HAS_MESH;
        }
        return r;
    }
};

pub fn discoveredName(buf: *[MAX_NAME_LEN]u8, ipv6: [16]u8) []const u8 {
    const s = std.fmt.bufPrint(buf, "{s}{x}", .{ UNREG_PREFIX, ipv6 }) catch unreachable;
    return s;
}

pub fn isDiscoveredName(name: []const u8) bool {
    return std.mem.startsWith(u8, name, UNREG_PREFIX);
}

pub fn registerDiscovered(io: Io, ipv6: [16]u8, mesh_addr: [MESH_ADDR_SIZE]u8) !void {
    var name_buf: [MAX_NAME_LEN]u8 = undefined;
    const wanted_name = discoveredName(&name_buf, ipv6);

    const f = try openOrCreate(io);
    defer f.close(io);

    var header = try readHeader(io, f);
    const total = try recordCount(io, f);

    var found_same_ipv6: bool = false;
    var same_ipv6_is_discovered: bool = false;
    var same_ipv6_idx: u32 = 0;

    for (0..total) |i| {
        const idx: u32 = @intCast(i);
        var rec = try readRecord(io, f, idx);
        if (rec.isDeleted()) continue;

        if (rec.hasMesh() and std.mem.eql(u8, &rec.mesh_addr, &mesh_addr)) {
            const rec_name = rec.getName();
            const is_target = rec.kind == @intFromEnum(AddressKind.ipv6) and std.mem.eql(u8, rec.addr[0..16], &ipv6);
            if (!is_target and isDiscoveredName(rec_name)) {
                rec.flags |= FLAG_DELETED;
                try writeRecord(io, f, idx, rec);
                if (header.count > 0) header.count -= 1;
                try writeHeader(io, f, header);
            }
        }

        if (rec.kind == @intFromEnum(AddressKind.ipv6) and std.mem.eql(u8, rec.addr[0..16], &ipv6)) {
            found_same_ipv6 = true;
            same_ipv6_idx = idx;
            same_ipv6_is_discovered = isDiscoveredName(rec.getName());
        }
    }

    if (found_same_ipv6) {
        if (!same_ipv6_is_discovered) {
            return;
        }
        var rec = try readRecord(io, f, same_ipv6_idx);
        rec.mesh_addr = mesh_addr;
        rec.flags |= FLAG_HAS_MESH;
        try writeRecord(io, f, same_ipv6_idx, rec);
        return;
    }

    var entry = Entry.fromIpv6(ipv6);
    entry.resolved_mesh = mesh_addr;
    const new_rec = Record.fromEntry(wanted_name, entry);

    const total_after = try recordCount(io, f);
    for (0..total_after) |i| {
        const idx: u32 = @intCast(i);
        const rec = try readRecord(io, f, idx);
        if (rec.isDeleted()) {
            try writeRecord(io, f, idx, new_rec);
            return;
        }
    }

    try writeRecord(io, f, total_after, new_rec);
    header.count += 1;
    try writeHeader(io, f, header);
}

pub fn forEachRecord(
    io: Io,
    comptime Context: type,
    ctx: Context,
    comptime callback: fn (ctx: Context, entry: RegistryEntry) anyerror!void,
) !void {
    const f = openReadOnly(io) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    defer f.close(io);

    _ = try readHeader(io, f);
    const total = try recordCount(io, f);

    for (0..total) |i| {
        const rec = try readRecord(io, f, @intCast(i));
        if (rec.isDeleted()) continue;

        var entry: RegistryEntry = undefined;
        const rec_name = rec.getName();
        entry.name_len = @min(rec_name.len, entry.name_buf.len);
        @memcpy(entry.name_buf[0..entry.name_len], rec_name[0..entry.name_len]);

        entry.kind = @enumFromInt(rec.kind);
        entry.addr = rec.addr;
        entry.mesh_addr = rec.mesh_addr;
        entry.has_mesh = rec.hasMesh();

        try callback(ctx, entry);
    }
}

fn openOrCreate(io: Io) !Io.File {
    const cwd = Io.Dir.cwd();
    return cwd.openFile(io, REGISTRY_FILE, .{ .mode = .read_write }) catch |err| switch (err) {
        error.FileNotFound => blk: {
            const dir_path = fs.get_bin_path();
            fs.createDirPath(io, dir_path) catch |dir_err| switch (dir_err) {
                error.PathAlreadyExists => {},
                else => return dir_err,
            };

            const sip_gid = try fs.lookupGroupGid(io, "sip");
            try fs.chmodPath(dir_path, 0o750);
            try fs.chownPath(dir_path, 0, sip_gid);

            const f = try cwd.createFile(io, REGISTRY_FILE, .{ .read = true });
            try fs.chmodFile(f, 0o760);
            try fs.chownFile(f, 0, sip_gid);

            const header = Header{
                .magic = MAGIC.*,
                .version = VERSION,
                .count = 0,
            };
            try f.writePositionalAll(io, std.mem.asBytes(&header), 0);
            break :blk f;
        },
        else => return err,
    };
}

fn openReadOnly(io: Io) !Io.File {
    const cwd = Io.Dir.cwd();
    return cwd.openFile(io, REGISTRY_FILE, .{ .mode = .read_only });
}

fn readHeader(io: Io, f: Io.File) !Header {
    var header: Header = undefined;
    const n = try f.readPositionalAll(io, std.mem.asBytes(&header), 0);
    if (n < HEADER_SIZE) return RegistryError.CorruptFile;
    if (!std.mem.eql(u8, &header.magic, MAGIC)) return RegistryError.CorruptFile;
    if (header.version != VERSION) return RegistryError.CorruptFile;
    return header;
}

fn writeHeader(io: Io, f: Io.File, header: Header) !void {
    try f.writePositionalAll(io, std.mem.asBytes(&header), 0);
}

fn readRecord(io: Io, f: Io.File, index: u32) !Record {
    var record: Record = undefined;
    const offset = HEADER_SIZE + @as(u64, index) * RECORD_SIZE;
    const n = try f.readPositionalAll(io, std.mem.asBytes(&record), offset);
    if (n < RECORD_SIZE) return RegistryError.CorruptFile;
    return record;
}

fn writeRecord(io: Io, f: Io.File, index: u32, record: Record) !void {
    const offset = HEADER_SIZE + @as(u64, index) * RECORD_SIZE;
    try f.writePositionalAll(io, std.mem.asBytes(&record), offset);
}

fn recordCount(io: Io, f: Io.File) !u32 {
    const stat = try f.stat(io);
    if (stat.size < HEADER_SIZE) return 0;
    return @intCast((stat.size - HEADER_SIZE) / RECORD_SIZE);
}

pub fn register(io: Io, name: []const u8, entry: Entry) !void {
    if (name.len == 0 or name.len > MAX_NAME_LEN) return RegistryError.NameTooLong;

    const f = try openOrCreate(io);
    defer f.close(io);

    var header = try readHeader(io, f);
    const total = try recordCount(io, f);

    for (0..total) |i| {
        var rec = try readRecord(io, f, @intCast(i));
        if (std.mem.eql(u8, rec.getName(), name)) {
            rec = Record.fromEntry(name, entry);
            try writeRecord(io, f, @intCast(i), rec);
            return;
        }
    }

    for (0..total) |i| {
        const rec = try readRecord(io, f, @intCast(i));
        if (rec.isDeleted()) {
            try writeRecord(io, f, @intCast(i), Record.fromEntry(name, entry));
            return;
        }
    }

    try writeRecord(io, f, total, Record.fromEntry(name, entry));
    header.count += 1;
    try writeHeader(io, f, header);
}

pub fn updateMeshAddress(io: Io, name: []const u8, mesh_addr: [MESH_ADDR_SIZE]u8) !void {
    if (name.len == 0 or name.len > MAX_NAME_LEN) return RegistryError.NameTooLong;

    const f = try openOrCreate(io);
    defer f.close(io);

    const total = try recordCount(io, f);

    for (0..total) |i| {
        var rec = try readRecord(io, f, @intCast(i));
        if (rec.isDeleted()) continue;
        if (std.mem.eql(u8, rec.getName(), name)) {
            rec.mesh_addr = mesh_addr;
            rec.flags |= FLAG_HAS_MESH;
            try writeRecord(io, f, @intCast(i), rec);
            return;
        }
    }

    return RegistryError.NotFound;
}

pub fn unregister(io: Io, name: []const u8) !void {
    const f = try openOrCreate(io);
    defer f.close(io);

    var header = try readHeader(io, f);
    const total = try recordCount(io, f);

    for (0..total) |i| {
        var rec = try readRecord(io, f, @intCast(i));
        if (!rec.isDeleted() and std.mem.eql(u8, rec.getName(), name)) {
            rec.flags |= FLAG_DELETED;
            try writeRecord(io, f, @intCast(i), rec);
            if (header.count > 0) header.count -= 1;
            try writeHeader(io, f, header);
            return;
        }
    }
    return RegistryError.NotFound;
}

pub fn compact(io: Io, allocator: std.mem.Allocator) !void {
    const f = try openOrCreate(io);
    defer f.close(io);

    const total = try recordCount(io, f);
    var active = std.ArrayList(Record).init(allocator);
    defer active.deinit();

    for (0..total) |i| {
        const rec = try readRecord(io, f, @intCast(i));
        if (!rec.isDeleted()) try active.append(rec);
    }

    const new_header = Header{
        .magic = MAGIC.*,
        .version = VERSION,
        .count = @intCast(active.items.len),
    };
    try writeHeader(io, f, new_header);
    for (active.items, 0..) |rec, i| {
        try writeRecord(io, f, @intCast(i), rec);
    }
    const new_size = HEADER_SIZE + active.items.len * RECORD_SIZE;
    try f.setEndPos(io, new_size);
}

pub fn resolve(io: Io, name: []const u8) !ResolveResult {
    if (name.len == 0) return RegistryError.NotFound;

    if (parseIpv6(name) catch null) |ipv6| return .{ .source = .direct_ipv6, .entry = Entry.fromIpv6(ipv6) };
    if (parseIpv4(name)) |ipv4| return .{ .source = .direct_ipv4, .entry = Entry.fromIpv4(ipv4) };

    const f = openReadOnly(io) catch |err| switch (err) {
        error.FileNotFound => return RegistryError.NotFound,
        else => return err,
    };
    defer f.close(io);
    _ = try readHeader(io, f);
    const total = try recordCount(io, f);

    for (0..total) |i| {
        const rec = try readRecord(io, f, @intCast(i));
        if (rec.isDeleted()) continue;
        if (std.mem.eql(u8, rec.getName(), name)) {
            return .{ .source = .registry, .entry = rec.toEntry() orelse continue };
        }
    }

    if (std.mem.endsWith(u8, name, SUFFIX)) {
        const without = name[0 .. name.len - SUFFIX.len];
        for (0..total) |i| {
            const rec = try readRecord(io, f, @intCast(i));
            if (rec.isDeleted()) continue;
            if (std.mem.eql(u8, rec.getName(), without)) {
                return .{ .source = .registry, .entry = rec.toEntry() orelse continue };
            }
        }
    } else {
        var buf: [MAX_NAME_LEN + SUFFIX.len]u8 = undefined;
        if (name.len + SUFFIX.len <= buf.len) {
            const with_suffix = std.fmt.bufPrint(&buf, "{s}{s}", .{ name, SUFFIX }) catch unreachable;
            for (0..total) |i| {
                const rec = try readRecord(io, f, @intCast(i));
                if (rec.isDeleted()) continue;
                if (std.mem.eql(u8, rec.getName(), with_suffix)) {
                    return .{ .source = .registry, .entry = rec.toEntry() orelse continue };
                }
            }
        }
    }

    var result = ResolveResult{ .source = .registry_partial, .entry = undefined };
    var match_count: usize = 0;
    for (0..total) |i| {
        const rec = try readRecord(io, f, @intCast(i));
        if (rec.isDeleted()) continue;
        const rec_name = rec.getName();
        if (std.mem.startsWith(u8, rec_name, name)) {
            match_count += 1;
            if (match_count == 1) {
                result.entry = rec.toEntry() orelse continue;
                result.matched_name_len = @min(rec_name.len, result.matched_name_buf.len);
                @memcpy(result.matched_name_buf[0..result.matched_name_len], rec_name[0..result.matched_name_len]);
            }
            if (match_count > 1) return RegistryError.Ambiguous;
        }
    }
    if (match_count == 1) return result;
    return RegistryError.NotFound;
}

pub fn looksLikeIpv6(text: []const u8) bool {
    return std.mem.indexOfScalar(u8, text, ':') != null;
}

pub fn parseIpv4(text: []const u8) ?[4]u8 {
    var result: [4]u8 = undefined;
    var it = std.mem.splitScalar(u8, text, '.');
    var idx: usize = 0;
    while (it.next()) |part| {
        if (idx >= 4) return null;
        if (part.len == 0 or part.len > 3) return null;
        result[idx] = std.fmt.parseInt(u8, part, 10) catch return null;
        idx += 1;
    }
    if (idx != 4) return null;
    return result;
}

pub fn parseIpv6(text: []const u8) ![16]u8 {
    var result: [16]u8 = [_]u8{0} ** 16;

    const double_colon = std.mem.indexOf(u8, text, "::");

    if (double_colon) |dc_pos| {
        const left = text[0..dc_pos];
        const right = text[dc_pos + 2 ..];

        var left_groups: [8]u16 = undefined;
        var left_count: usize = 0;
        if (left.len > 0) {
            var it = std.mem.splitScalar(u8, left, ':');
            while (it.next()) |part| {
                if (left_count >= 8) return error.InvalidIpv6Address;
                left_groups[left_count] = std.fmt.parseInt(u16, part, 16) catch return error.InvalidIpv6Address;
                left_count += 1;
            }
        }

        var right_groups: [8]u16 = undefined;
        var right_count: usize = 0;
        if (right.len > 0) {
            var it = std.mem.splitScalar(u8, right, ':');
            while (it.next()) |part| {
                if (right_count >= 8) return error.InvalidIpv6Address;
                right_groups[right_count] = std.fmt.parseInt(u16, part, 16) catch return error.InvalidIpv6Address;
                right_count += 1;
            }
        }

        if (left_count + right_count > 8) return error.InvalidIpv6Address;

        var groups: [8]u16 = [_]u16{0} ** 8;
        @memcpy(groups[0..left_count], left_groups[0..left_count]);
        @memcpy(groups[8 - right_count ..], right_groups[0..right_count]);

        for (groups, 0..) |g, i| {
            std.mem.writeInt(u16, result[i * 2 ..][0..2], g, .big);
        }
    } else {
        var it = std.mem.splitScalar(u8, text, ':');
        var idx: usize = 0;
        while (it.next()) |part| {
            if (idx >= 8) return error.InvalidIpv6Address;
            const g = std.fmt.parseInt(u16, part, 16) catch return error.InvalidIpv6Address;
            std.mem.writeInt(u16, result[idx * 2 ..][0..2], g, .big);
            idx += 1;
        }
        if (idx != 8) return error.InvalidIpv6Address;
    }

    return result;
}

pub fn parseMeshAddr(text: []const u8) ?[MESH_ADDR_SIZE]u8 {
    if (text.len != MESH_ADDR_SIZE * 2) return null;
    var out: [MESH_ADDR_SIZE]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, text) catch return null;
    return out;
}

fn parseGroups(text: []const u8, out: []u16) ?usize {
    var it = std.mem.splitScalar(u8, text, ':');
    var count: usize = 0;
    while (it.next()) |part| {
        if (count >= out.len) return null;
        if (part.len == 0 or part.len > 4) return null;
        out[count] = std.fmt.parseInt(u16, part, 16) catch return null;
        count += 1;
    }
    return count;
}

pub fn formatMeshAddr(buf: *[MESH_ADDR_SIZE * 2]u8, addr: [MESH_ADDR_SIZE]u8) []const u8 {
    const hex = std.fmt.bytesToHex(addr, .lower);
    @memcpy(buf, &hex);
    return buf[0..];
}

pub fn formatMeshAddrGrouped(buf: *[MESH_ADDR_SIZE * 2 + 3]u8, addr: [MESH_ADDR_SIZE]u8) []const u8 {
    var pos: usize = 0;
    var i: usize = 0;
    while (i < MESH_ADDR_SIZE) : (i += 4) {
        if (i > 0) {
            buf[pos] = ':';
            pos += 1;
        }
        const chunk_hex = std.fmt.bytesToHex(addr[i..][0..4], .lower);
        @memcpy(buf[pos..][0..8], &chunk_hex);
        pos += 8;
    }
    return buf[0..pos];
}

pub fn formatIpv6(buf: []u8, addr: [16]u8) []const u8 {
    var groups: [8]u16 = undefined;
    for (0..8) |i| groups[i] = (@as(u16, addr[i * 2]) << 8) | addr[i * 2 + 1];

    var best_start: usize = 0;
    var best_len: usize = 0;
    var run_start: usize = 0;
    var run_len: usize = 0;
    for (groups, 0..) |g, i| {
        if (g == 0) {
            if (run_len == 0) run_start = i;
            run_len += 1;
            if (run_len > best_len) {
                best_len = run_len;
                best_start = run_start;
            }
        } else {
            run_len = 0;
        }
    }

    var pos: usize = 0;

    if (best_len < 2) {
        for (groups, 0..) |g, i| {
            if (i > 0) {
                buf[pos] = ':';
                pos += 1;
            }
            const s = std.fmt.bufPrint(buf[pos..], "{x}", .{g}) catch unreachable;
            pos += s.len;
        }
        return buf[0..pos];
    }

    for (groups[0..best_start], 0..) |g, i| {
        if (i > 0) {
            buf[pos] = ':';
            pos += 1;
        }
        const s = std.fmt.bufPrint(buf[pos..], "{x}", .{g}) catch unreachable;
        pos += s.len;
    }

    buf[pos] = ':';
    buf[pos + 1] = ':';
    pos += 2;

    const right = groups[best_start + best_len ..];
    for (right, 0..) |g, i| {
        if (i > 0) {
            buf[pos] = ':';
            pos += 1;
        }
        const s = std.fmt.bufPrint(buf[pos..], "{x}", .{g}) catch unreachable;
        pos += s.len;
    }

    return buf[0..pos];
}

test "formatIpv6 komprimiert führenden Nulllauf (::1)" {
    var buf: [40]u8 = undefined;
    const addr = [_]u8{0} ** 15 ++ [_]u8{1};
    try std.testing.expectEqualStrings("::1", formatIpv6(&buf, addr));
}

test "formatIpv6 komprimiert alles auf ::" {
    var buf: [40]u8 = undefined;
    const addr = [_]u8{0} ** 16;
    try std.testing.expectEqualStrings("::", formatIpv6(&buf, addr));
}

test "formatIpv6 komprimiert mittigen Nulllauf" {
    var buf: [40]u8 = undefined;
    var addr = [_]u8{0} ** 16;
    addr[0] = 0x20;
    addr[1] = 0x01;
    addr[2] = 0x0d;
    addr[3] = 0xb8;
    addr[15] = 1;
    try std.testing.expectEqualStrings("2001:db8::1", formatIpv6(&buf, addr));
}

test "formatIpv6 ohne Nulllauf gibt alle 8 Gruppen aus" {
    var buf: [40]u8 = undefined;
    var addr: [16]u8 = undefined;
    for (0..8) |i| {
        addr[i * 2] = 0;
        addr[i * 2 + 1] = @intCast(i + 1);
    }
    try std.testing.expectEqualStrings("1:2:3:4:5:6:7:8", formatIpv6(&buf, addr));
}

test "formatIpv6 einzelne Nullgruppe wird NICHT komprimiert (RFC 5952)" {
    var buf: [40]u8 = undefined;
    var addr: [16]u8 = undefined;
    for (0..8) |i| {
        addr[i * 2] = 0;
        addr[i * 2 + 1] = @intCast(i + 1);
    }
    addr[2] = 0;
    addr[3] = 0;
    try std.testing.expectEqualStrings("1:0:3:4:5:6:7:8", formatIpv6(&buf, addr));
}

test "formatIpv6 roundtrip mit parseIpv6" {
    var buf: [40]u8 = undefined;
    const addr = [_]u8{ 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 2 };
    const formatted = formatIpv6(&buf, addr);
    const parsed = try parseIpv6(formatted);
    try std.testing.expectEqualSlices(u8, &addr, &parsed);
}

test "formatMeshAddrGrouped gruppiert alle 4 Bytes mit ':'" {
    var buf: [MESH_ADDR_SIZE * 2 + 3]u8 = undefined;
    var addr: [MESH_ADDR_SIZE]u8 = undefined;
    for (0..MESH_ADDR_SIZE) |i| addr[i] = @intCast(i);
    const s = formatMeshAddrGrouped(&buf, addr);

    try std.testing.expectEqual(@as(usize, 35), s.len);
    try std.testing.expect(std.mem.startsWith(u8, s, "00010203:"));
}
