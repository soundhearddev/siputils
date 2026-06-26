const std = @import("std");
const Io = std.Io;
const identity = @import("sip").identity;

pub const KEY_ROOT = "/etc/sip";

pub const KeystoreError = error{
    IdentityNotFound,
    IdentityAlreadyExists,
    InvalidName,
    PasswordMismatch,
    ChmodFailed,
};

pub const IdentityEntry = struct {
    name_buf: [64]u8,
    name_len: usize,
    public: [32]u8,
    valid: bool,

    pub fn name(self: *const IdentityEntry) []const u8 {
        return self.name_buf[0..self.name_len];
    }
};

pub fn identityDir(buf: []u8, name: []const u8) ![]const u8 {
    return std.fmt.bufPrint(buf, "{s}/{s}", .{ KEY_ROOT, name });
}

pub fn privatePath(buf: []u8, name: []const u8) ![]const u8 {
    return std.fmt.bufPrint(buf, "{s}/{s}/private.key", .{ KEY_ROOT, name });
}

pub fn publicPath(buf: []u8, name: []const u8) ![]const u8 {
    return std.fmt.bufPrint(buf, "{s}/{s}/public.key", .{ KEY_ROOT, name });
}

pub fn validName(name: []const u8) bool {
    if (name.len == 0 or name.len > 64) return false;
    for (name) |c| {
        const ok = std.ascii.isAlphanumeric(c) or c == '-' or c == '_' or c == '.';
        if (!ok) return false;
    }
    return true;
}

pub fn identityExists(io: std.Io, name: []const u8) bool {
    var dir_buf: [300]u8 = undefined;
    const dpath = identityDir(&dir_buf, name) catch return false;
    const cwd = Io.Dir.cwd();
    var d = cwd.openDir(io, dpath, .{}) catch return false;
    d.close(io);
    return true;
}

pub fn createIdentity(io: std.Io, name: []const u8, password: []const u8) !identity.KeyPair {
    if (identityExists(io, name)) return KeystoreError.IdentityAlreadyExists;
    const kp = identity.generateKeyPair(io);
    return try storeIdentity(io, name, kp, password);
}

pub fn loadIdentity(io: std.Io, name: []const u8, password: []const u8) !identity.KeyPair {
    var priv_path_buf: [300]u8 = undefined;
    var pub_path_buf: [300]u8 = undefined;
    const priv_path = try privatePath(&priv_path_buf, name);
    const pub_path = try publicPath(&pub_path_buf, name);

    const cwd = Io.Dir.cwd();

    var raw: [identity.ENCRYPTED_PRIVATE_LEN]u8 = undefined;
    {
        const f = cwd.openFile(io, priv_path, .{}) catch return KeystoreError.IdentityNotFound;
        defer f.close(io);
        _ = try f.readPositionalAll(io, &raw, 0);
    }

    var pub_bytes: [32]u8 = undefined;
    {
        const f = cwd.openFile(io, pub_path, .{}) catch return KeystoreError.IdentityNotFound;
        defer f.close(io);
        _ = try f.readPositionalAll(io, &pub_bytes, 0);
    }

    const secret = try identity.decryptPrivateKey(&raw, password);
    return identity.KeyPair{ .public = pub_bytes, .secret = secret };
}

pub fn loadPublicOnly(io: std.Io, name: []const u8) ![32]u8 {
    var pub_path_buf: [300]u8 = undefined;
    const pub_path = try publicPath(&pub_path_buf, name);
    const cwd = Io.Dir.cwd();
    const f = cwd.openFile(io, pub_path, .{}) catch return KeystoreError.IdentityNotFound;
    defer f.close(io);
    var pub_bytes: [32]u8 = undefined;
    _ = try f.readPositionalAll(io, &pub_bytes, 0);
    return identity.parsePublicKey(&pub_bytes);
}

pub fn deleteIdentity(io: std.Io, name: []const u8) !void {
    if (!identityExists(io, name)) return KeystoreError.IdentityNotFound;
    var dir_buf: [300]u8 = undefined;
    const dpath = try identityDir(&dir_buf, name);
    const cwd = Io.Dir.cwd();
    try cwd.deleteTree(io, dpath);
}

pub fn changePassword(io: std.Io, name: []const u8, old_password: []const u8, new_password: []const u8) !identity.KeyPair {
    const kp = try loadIdentity(io, name, old_password);

    var dir_buf: [300]u8 = undefined;
    const dpath = try identityDir(&dir_buf, name);
    const cwd = Io.Dir.cwd();
    try cwd.deleteTree(io, dpath);

    return try storeIdentity(io, name, kp, new_password);
}

fn storeIdentity(io: std.Io, name: []const u8, kp: identity.KeyPair, password: []const u8) !identity.KeyPair {
    var dir_buf: [300]u8 = undefined;
    const dir = try identityDir(&dir_buf, name);

    const cwd = Io.Dir.cwd();
    cwd.createDirPath(io, KEY_ROOT) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
    {
        var path_c_buf: [320]u8 = undefined;
        const dir_c = try std.fmt.bufPrint(&path_c_buf, "{s}\x00", .{KEY_ROOT});

        const rc = std.os.linux.syscall2(.chmod, @intFromPtr(dir_c.ptr), 0o700);

        if (rc != 0) return KeystoreError.ChmodFailed;
    }

    cwd.createDirPath(io, dir) catch |err| switch (err) {
        error.PathAlreadyExists => return KeystoreError.IdentityAlreadyExists,
        else => return err,
    };
    {
        var path_c_buf: [320]u8 = undefined;
        const dir_c = try std.fmt.bufPrint(&path_c_buf, "{s}\x00", .{dir});

        const rc = std.os.linux.syscall2(.chmod, @intFromPtr(dir_c.ptr), 0o700);
        if (rc != 0) return KeystoreError.ChmodFailed;
    }

    const rng_src: std.Random.IoSource = .{ .io = io };
    const rand = rng_src.interface();

    var salt: [16]u8 = undefined;
    var nonce: [std.crypto.aead.aes_gcm.Aes256Gcm.nonce_length]u8 = undefined;
    rand.bytes(&salt);
    rand.bytes(&nonce);

    var blob: [identity.ENCRYPTED_PRIVATE_LEN]u8 = undefined;
    try identity.encryptPrivateKey(&blob, kp.secret, password, salt, nonce);

    var priv_path_buf: [300]u8 = undefined;
    var pub_path_buf: [300]u8 = undefined;
    const priv_path = try privatePath(&priv_path_buf, name);
    const pub_path = try publicPath(&pub_path_buf, name);

    {
        const f = try cwd.createFile(io, priv_path, .{});
        defer f.close(io);
        const rc = std.os.linux.syscall2(.fchmod, @intCast(f.handle), 0o600);
        if (rc != 0) return KeystoreError.ChmodFailed;
        var buf: [256]u8 = undefined;
        var w = f.writer(io, &buf);
        try w.interface.writeAll(&blob);
        try w.flush();
    }
    {
        const f = try cwd.createFile(io, pub_path, .{});
        defer f.close(io);
        const rc = std.os.linux.syscall2(.fchmod, @intCast(f.handle), 0o644);
        if (rc != 0) return KeystoreError.ChmodFailed;
        var buf: [64]u8 = undefined;
        var w = f.writer(io, &buf);
        try w.interface.writeAll(&kp.public);
        try w.flush();
    }

    return kp;
}

pub const ListError = error{KeyRootMissing} || anyerror;

pub fn forEachIdentity(
    io: std.Io,
    comptime Context: type,
    ctx: Context,
    comptime callback: fn (ctx: Context, entry: IdentityEntry) anyerror!void,
) !void {
    const cwd = Io.Dir.cwd();
    var dir = cwd.openDir(io, KEY_ROOT, .{ .iterate = true }) catch {
        return ListError.KeyRootMissing;
    };
    defer dir.close(io);

    var it = dir.iterate();
    while (try it.next(io)) |entry| {
        if (entry.kind != .directory) continue;

        var ie: IdentityEntry = undefined;
        ie.name_len = @min(entry.name.len, ie.name_buf.len);
        @memcpy(ie.name_buf[0..ie.name_len], entry.name[0..ie.name_len]);

        if (loadPublicOnly(io, entry.name)) |pub_bytes| {
            ie.public = pub_bytes;
            ie.valid = true;
        } else |_| {
            ie.public = [_]u8{0} ** 32;
            ie.valid = false;
        }

        try callback(ctx, ie);
    }
}
