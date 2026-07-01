const std = @import("std");
const Io = std.Io;
const identity = @import("sip").identity;
const registry = @import("registry.zig");
const fs = @import("filesystem.zig");

pub const DEFAULT_LINK_NAME = "default";

pub const CONFIG_ROOT = "/etc/sip";
pub const KEY_ROOT = "/keys";

pub const ROOT = CONFIG_ROOT ++ KEY_ROOT;

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
    return std.fmt.bufPrint(buf, "{s}/{s}", .{ ROOT, name });
}

pub fn privatePath(buf: []u8, name: []const u8) ![]const u8 {
    return std.fmt.bufPrint(buf, "{s}/{s}/private.key", .{ ROOT, name });
}

pub fn publicPath(buf: []u8, name: []const u8) ![]const u8 {
    return std.fmt.bufPrint(buf, "{s}/{s}/public.key", .{ ROOT, name });
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
    return fs.dirExists(io, dpath);
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

    var root_dir = try fs.openRoot(io);
    defer root_dir.close(io);

    const rel_priv = fs.stripLeadingSlash(priv_path);
    const rel_pub = fs.stripLeadingSlash(pub_path);

    var raw: [identity.ENCRYPTED_PRIVATE_LEN]u8 = undefined;
    fs.readFileExactRel(io, &root_dir, rel_priv, &raw) catch return KeystoreError.IdentityNotFound;

    var pub_bytes: [32]u8 = undefined;
    fs.readFileExactRel(io, &root_dir, rel_pub, &pub_bytes) catch return KeystoreError.IdentityNotFound;

    const secret = try identity.decryptPrivateKey(&raw, password);
    return identity.KeyPair{ .public = pub_bytes, .secret = secret };
}

pub fn loadPublicOnly(io: std.Io, name: []const u8) ![32]u8 {
    var pub_path_buf: [300]u8 = undefined;
    const pub_path = try publicPath(&pub_path_buf, name);

    var pub_bytes: [32]u8 = undefined;
    fs.readFileExact(io, pub_path, &pub_bytes) catch return KeystoreError.IdentityNotFound;
    return identity.parsePublicKey(&pub_bytes);
}

pub fn deleteIdentity(io: std.Io, name: []const u8) !void {
    if (!identityExists(io, name)) return KeystoreError.IdentityNotFound;
    var dir_buf: [300]u8 = undefined;
    const dpath = try identityDir(&dir_buf, name);
    try fs.deleteTree(io, dpath);
}

pub fn changePassword(io: std.Io, name: []const u8, old_password: []const u8, new_password: []const u8) !identity.KeyPair {
    const kp = try loadIdentity(io, name, old_password);

    var dir_buf: [300]u8 = undefined;
    const dpath = try identityDir(&dir_buf, name);
    try fs.deleteTree(io, dpath);

    return try storeIdentity(io, name, kp, new_password);
}

fn storeIdentity(io: std.Io, name: []const u8, kp: identity.KeyPair, password: []const u8) !identity.KeyPair {
    var dir_buf: [300]u8 = undefined;
    const dir = try identityDir(&dir_buf, name);

    const sip_gid = fs.lookupGroupGid(io, "sip") catch return KeystoreError.ChmodFailed;

    fs.createDirPath(io, ROOT) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        error.AccessDenied => {
            std.debug.print("Fehler: Kein Schreibzugriff auf '{s}'\n", .{ROOT});
            return err;
        },
        else => return err,
    };
    fs.chmodPath(ROOT, 0o755) catch return KeystoreError.ChmodFailed;
    fs.chownPath(ROOT, 0, sip_gid) catch return KeystoreError.ChmodFailed;

    fs.createDirPath(io, dir) catch |err| switch (err) {
        error.PathAlreadyExists => return KeystoreError.IdentityAlreadyExists,
        error.AccessDenied => {
            std.debug.print("Fehler: Kein Schreibzugriff auf '{s}'\n", .{dir});
            return err;
        },
        else => return err,
    };
    fs.chmodPath(dir, 0o755) catch return KeystoreError.ChmodFailed;
    fs.chownPath(dir, 0, sip_gid) catch return KeystoreError.ChmodFailed;

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

    fs.writeNewFileOwned(io, priv_path, 0o644, 0, sip_gid, &blob) catch return KeystoreError.ChmodFailed;
    fs.writeNewFileOwned(io, pub_path, 0o644, 0, sip_gid, &kp.public) catch return KeystoreError.ChmodFailed;

    const addr = try registry.parseIpv6("::1");
    try registry.register(io, name, registry.Entry.fromIpv6(addr));

    return kp;
}

pub const ListError = error{KeyRootMissing} || anyerror;

pub fn forEachIdentity(
    io: std.Io,
    comptime Context: type,
    ctx: Context,
    comptime callback: fn (ctx: Context, entry: IdentityEntry) anyerror!void,
) !void {
    var dir = fs.openIterableDir(io, ROOT) catch {
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

fn defaultLinkPath(buf: []u8) ![]const u8 {
    return std.fmt.bufPrint(buf, "{s}/{s}", .{ ROOT, DEFAULT_LINK_NAME });
}

pub fn setDefaultIdentity(name: []const u8) !void {
    var link_path_buf: [300]u8 = undefined;
    const link_path = try defaultLinkPath(&link_path_buf);
    try fs.replaceSymlink(name, link_path);
}

pub fn readDefaultIdentity(buf: []u8) ![]const u8 {
    var link_path_buf: [300]u8 = undefined;
    const link_path = try defaultLinkPath(&link_path_buf);
    return fs.readSymlink(link_path, buf) catch |err| switch (err) {
        error.ReadLinkFailed => return KeystoreError.IdentityNotFound,
        else => return err,
    };
}
