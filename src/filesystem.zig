const std = @import("std");
const Io = std.Io;

pub fn get_bin_path() []const u8 {
    const PATH = "/etc/sip/bin";

    return PATH;
}

pub fn get_config_path() []const u8 {
    const PATH = "/etc/sip/sipd.conf";

    return PATH;
}

pub fn get_key_root_path() []const u8 {
    const PATH = "/etc/sip/keys";

    return PATH;
}

pub const FsError = error{
    ChmodFailed,
    ChownFailed,
    PathRootMissing,
    InvalidPath,
};

pub const SymlinkError = error{
    SymlinkFailed,
    ReadLinkFailed,
    BufferTooSmall,
};

pub fn stripLeadingSlash(path: []const u8) []const u8 {
    return if (path.len > 0 and path[0] == '/') path[1..] else path;
}

pub fn openRoot(io: std.Io) !Io.Dir {
    return try Io.Dir.openDirAbsolute(io, "/", .{});
}

pub fn dirExists(io: std.Io, abs_path: []const u8) bool {
    var root_dir = openRoot(io) catch return false;
    defer root_dir.close(io);

    const rel = stripLeadingSlash(abs_path);
    var d = root_dir.openDir(io, rel, .{}) catch return false;
    d.close(io);
    return true;
}

pub fn fileExists(io: std.Io, abs_path: []const u8) bool {
    const cwd = Io.Dir.cwd();
    const f = cwd.openFile(io, abs_path, .{}) catch return false;
    f.close(io);
    return true;
}

pub fn createDirPath(io: std.Io, path: []const u8) !void {
    const cwd = Io.Dir.cwd();
    try cwd.createDirPath(io, path);
}

pub fn chmodPath(path: []const u8, mode: u32) !void {
    var path_c_buf: [320]u8 = undefined;
    const path_c = try std.fmt.bufPrint(&path_c_buf, "{s}\x00", .{path});

    const rc = std.os.linux.syscall2(.chmod, @intFromPtr(path_c.ptr), mode);
    if (rc != 0) return FsError.ChmodFailed;
}

pub fn chmodFile(file: Io.File, mode: u32) !void {
    const rc = std.os.linux.syscall2(.fchmod, @intCast(file.handle), mode);
    if (rc != 0) return FsError.ChmodFailed;
}

pub fn chownPath(path: []const u8, uid: u32, gid: u32) !void {
    var path_c_buf: [320]u8 = undefined;
    const path_c = try std.fmt.bufPrint(&path_c_buf, "{s}\x00", .{path});

    const rc = std.os.linux.syscall3(.chown, @intFromPtr(path_c.ptr), uid, gid);
    if (rc != 0) return FsError.ChownFailed;
}

pub fn chownFile(file: Io.File, uid: u32, gid: u32) !void {
    const rc = std.os.linux.syscall3(.fchown, @intCast(file.handle), uid, gid);
    if (rc != 0) return FsError.ChownFailed;
}

pub const GroupLookupError = error{
    GroupNotFound,
    GroupFileUnreadable,
    MalformedGroupEntry,
};

pub fn lookupGroupGid(io: std.Io, group_name: []const u8) !u32 {
    const cwd = Io.Dir.cwd();
    const f = cwd.openFile(io, "/etc/group", .{}) catch return GroupLookupError.GroupFileUnreadable;
    defer f.close(io);

    var buf: [8192]u8 = undefined;
    const n = try f.readPositionalAll(io, &buf, 0);
    const content = buf[0..n];

    var line_it = std.mem.splitScalar(u8, content, '\n');
    while (line_it.next()) |line| {
        if (line.len == 0) continue;

        var field_it = std.mem.splitScalar(u8, line, ':');
        const name_field = field_it.next() orelse continue;
        if (!std.mem.eql(u8, name_field, group_name)) continue;

        _ = field_it.next() orelse return GroupLookupError.MalformedGroupEntry;
        const gid_field = field_it.next() orelse return GroupLookupError.MalformedGroupEntry;

        return std.fmt.parseInt(u32, gid_field, 10) catch return GroupLookupError.MalformedGroupEntry;
    }

    return GroupLookupError.GroupNotFound;
}

pub fn readFileExact(io: std.Io, abs_path: []const u8, buf: []u8) !void {
    const cwd = Io.Dir.cwd();
    const f = try cwd.openFile(io, abs_path, .{});
    defer f.close(io);
    _ = try f.readPositionalAll(io, buf, 0);
}

pub fn readFileExactRel(io: std.Io, root_dir: *Io.Dir, rel_path: []const u8, buf: []u8) !void {
    const f = try root_dir.openFile(io, rel_path, .{});
    defer f.close(io);
    _ = try f.readPositionalAll(io, buf, 0);
}

pub fn readFileBytes(io: std.Io, allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    var file = try std.Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);

    const stat = try file.stat(io);

    const data = try allocator.alloc(u8, stat.size);
    errdefer allocator.free(data);

    _ = try file.readPositionalAll(io, data, 0);

    return data;
}

pub fn writeNewFile(io: std.Io, abs_path: []const u8, mode: u32, content: []const u8) !void {
    const cwd = Io.Dir.cwd();
    const f = try cwd.createFile(io, abs_path, .{});
    defer f.close(io);

    try chmodFile(f, mode);

    var buf: [256]u8 = undefined;
    var w = f.writer(io, &buf);
    try w.interface.writeAll(content);
    try w.flush();
}

pub fn writeNewFileOwned(io: std.Io, abs_path: []const u8, mode: u32, uid: u32, gid: u32, content: []const u8) !void {
    const cwd = Io.Dir.cwd();
    const f = try cwd.createFile(io, abs_path, .{});
    defer f.close(io);

    try chmodFile(f, mode);
    try chownFile(f, uid, gid);

    var buf: [256]u8 = undefined;
    var w = f.writer(io, &buf);
    try w.interface.writeAll(content);
    try w.flush();
}

pub fn deleteTree(io: std.Io, path: []const u8) !void {
    const cwd = Io.Dir.cwd();
    try cwd.deleteTree(io, path);
}

pub fn openIterableDir(io: std.Io, path: []const u8) !Io.Dir {
    const cwd = Io.Dir.cwd();
    return cwd.openDir(io, path, .{ .iterate = true });
}

pub fn forEachEntry(
    io: std.Io,
    dir: *Io.Dir,
    comptime Context: type,
    ctx: Context,
    comptime callback: fn (ctx: Context, entry: Io.Dir.Entry) anyerror!void,
) !void {
    var it = dir.iterate();
    while (try it.next(io)) |entry| {
        try callback(ctx, entry);
    }
}

pub fn createSymlink(target: []const u8, link_path: []const u8) !void {
    var target_c_buf: [320]u8 = undefined;
    const target_c = try std.fmt.bufPrint(&target_c_buf, "{s}\x00", .{target});

    var link_c_buf: [320]u8 = undefined;
    const link_c = try std.fmt.bufPrint(&link_c_buf, "{s}\x00", .{link_path});

    const rc = std.os.linux.syscall2(.symlink, @intFromPtr(target_c.ptr), @intFromPtr(link_c.ptr));
    if (rc != 0) return SymlinkError.SymlinkFailed;
}

pub fn replaceSymlink(target: []const u8, link_path: []const u8) !void {
    var link_c_buf: [320]u8 = undefined;
    const link_c = try std.fmt.bufPrint(&link_c_buf, "{s}\x00", .{link_path});

    _ = std.os.linux.syscall1(.unlink, @intFromPtr(link_c.ptr));

    try createSymlink(target, link_path);
}

pub fn readSymlink(link_path: []const u8, buf: []u8) ![]const u8 {
    var link_c_buf: [320]u8 = undefined;
    const link_c = try std.fmt.bufPrint(&link_c_buf, "{s}\x00", .{link_path});

    const rc = std.os.linux.syscall3(.readlink, @intFromPtr(link_c.ptr), @intFromPtr(buf.ptr), buf.len);
    if (rc < 0) return SymlinkError.ReadLinkFailed;

    const len: usize = @intCast(rc);
    if (len > buf.len) return SymlinkError.BufferTooSmall;
    return buf[0..len];
}
