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

// ============================================================================
// TrustStore: globale Peer-Whitelist auf Basis von Ed25519 Public Keys.
//
// Sicherheitsmodell: default-deny, silent-drop.
// Ein Peer, dessen Public Key nicht in dieser Liste steht, wird nirgendwo
// im System beantwortet -- keine Fehlermeldung, kein Response-Paket, keine
// sichtbare Reaktion. Das Einpflegen eines neuen Peers geschieht ausschliesslich
// manuell (sipctl trust <pubkey_hex> <label>), es gibt keinen automatischen
// TOFU-Mechanismus und keine Server-seitige Anzeige unbekannter Verbindungsversuche.
//
// Speicherformat: eigene Binaerdatei (trust.bin), gleiches Header+Record
// Schema wie registry.zig -- feste Satzlaenge, FLAG_DELETED statt Compaction
// bei jedem Remove, damit ein Absturz mitten im Schreiben nie die ganze
// Datei korrumpiert.
// ============================================================================

pub const TRUST_FILE = CONFIG_ROOT ++ "/trust.bin";

const TRUST_MAGIC = "SPTR";
const TRUST_VERSION: u8 = 1;
const TRUST_HEADER_SIZE: usize = 16;
const TRUST_MAX_LABEL_LEN: usize = 63;

const TRUST_FLAG_DELETED: u16 = 0x0001;

pub const TrustError = error{
    LabelTooLong,
    AlreadyTrusted,
    NotFound,
    CorruptFile,
    InvalidPubkeyHex,
};

const TrustHeader = extern struct {
    magic: [4]u8,
    version: u8,
    _pad0: [3]u8 = [_]u8{0} ** 3,
    count: u32,
    _pad1: [4]u8 = [_]u8{0} ** 4,

    comptime {
        std.debug.assert(@sizeOf(TrustHeader) == TRUST_HEADER_SIZE);
    }
};

const TrustRecord = extern struct {
    pubkey: [32]u8,
    label: [64]u8, // NUL-terminiert / -gepolstert
    flags: u16,

    fn isDeleted(self: *const TrustRecord) bool {
        return (self.flags & TRUST_FLAG_DELETED) != 0;
    }

    fn getLabel(self: *const TrustRecord) []const u8 {
        const len = std.mem.indexOfScalar(u8, &self.label, 0) orelse self.label.len;
        return self.label[0..len];
    }
};

// Die tatsächliche Satzgröße wird vom Compiler übernommen statt manuell
// geraten -- das macht ein Auseinanderlaufen von Struct-Layout (inkl.
// jeglichem Alignment-Padding, das extern struct hinzufügt) und der
// Konstante strukturell unmöglich.
const TRUST_RECORD_SIZE: usize = @sizeOf(TrustRecord);

/// Ein einzelner Eintrag der Trust-Liste, zum Auflisten/Anzeigen.
pub const TrustedPeer = struct {
    pubkey: [32]u8,
    label_buf: [64]u8,
    label_len: usize,

    pub fn label(self: *const TrustedPeer) []const u8 {
        return self.label_buf[0..self.label_len];
    }
};

fn trustOpenOrCreate(io: Io) !Io.File {
    const cwd = Io.Dir.cwd();
    return cwd.openFile(io, TRUST_FILE, .{ .mode = .read_write }) catch |err| switch (err) {
        error.FileNotFound => blk: {
            fs.createDirPath(io, CONFIG_ROOT) catch |dir_err| switch (dir_err) {
                error.PathAlreadyExists => {},
                else => return dir_err,
            };

            const sip_gid = try fs.lookupGroupGid(io, "sip");

            const f = try cwd.createFile(io, TRUST_FILE, .{ .read = true });
            try fs.chmodFile(f, 0o640);
            try fs.chownFile(f, 0, sip_gid);

            const header = TrustHeader{
                .magic = TRUST_MAGIC.*,
                .version = TRUST_VERSION,
                .count = 0,
            };
            try f.writePositionalAll(io, std.mem.asBytes(&header), 0);
            break :blk f;
        },
        else => return err,
    };
}

fn trustOpenReadOnly(io: Io) !Io.File {
    const cwd = Io.Dir.cwd();
    return cwd.openFile(io, TRUST_FILE, .{ .mode = .read_only });
}

fn trustReadHeader(io: Io, f: Io.File) !TrustHeader {
    var header: TrustHeader = undefined;
    const n = try f.readPositionalAll(io, std.mem.asBytes(&header), 0);
    if (n < TRUST_HEADER_SIZE) return TrustError.CorruptFile;
    if (!std.mem.eql(u8, &header.magic, TRUST_MAGIC)) return TrustError.CorruptFile;
    if (header.version != TRUST_VERSION) return TrustError.CorruptFile;
    return header;
}

fn trustWriteHeader(io: Io, f: Io.File, header: TrustHeader) !void {
    try f.writePositionalAll(io, std.mem.asBytes(&header), 0);
}

fn trustReadRecord(io: Io, f: Io.File, index: u32) !TrustRecord {
    var record: TrustRecord = undefined;
    const offset = TRUST_HEADER_SIZE + @as(u64, index) * TRUST_RECORD_SIZE;
    const n = try f.readPositionalAll(io, std.mem.asBytes(&record), offset);
    if (n < TRUST_RECORD_SIZE) return TrustError.CorruptFile;
    return record;
}

fn trustWriteRecord(io: Io, f: Io.File, index: u32, record: TrustRecord) !void {
    const offset = TRUST_HEADER_SIZE + @as(u64, index) * TRUST_RECORD_SIZE;
    try f.writePositionalAll(io, std.mem.asBytes(&record), offset);
}

fn trustRecordCount(io: Io, f: Io.File) !u32 {
    const stat = try f.stat(io);
    if (stat.size < TRUST_HEADER_SIZE) return 0;
    return @intCast((stat.size - TRUST_HEADER_SIZE) / TRUST_RECORD_SIZE);
}

/// Fuegt einen neuen vertrauenswuerdigen Peer hinzu (per Public Key).
/// Schlaegt fehl, wenn der Key bereits eingetragen ist.
pub fn trustPeer(io: Io, pubkey: [32]u8, label: []const u8) !void {
    if (label.len > TRUST_MAX_LABEL_LEN) return TrustError.LabelTooLong;

    const f = try trustOpenOrCreate(io);
    defer f.close(io);

    var header = try trustReadHeader(io, f);
    const total = try trustRecordCount(io, f);

    for (0..total) |i| {
        const rec = try trustReadRecord(io, f, @intCast(i));
        if (!rec.isDeleted() and std.mem.eql(u8, &rec.pubkey, &pubkey)) {
            return TrustError.AlreadyTrusted;
        }
    }

    var new_rec = TrustRecord{
        .pubkey = pubkey,
        .label = [_]u8{0} ** 64,
        .flags = 0,
    };
    @memcpy(new_rec.label[0..label.len], label);

    // Freien (geloeschten) Slot wiederverwenden, sonst anhaengen.
    for (0..total) |i| {
        const rec = try trustReadRecord(io, f, @intCast(i));
        if (rec.isDeleted()) {
            try trustWriteRecord(io, f, @intCast(i), new_rec);
            header.count += 1;
            try trustWriteHeader(io, f, header);
            return;
        }
    }

    try trustWriteRecord(io, f, total, new_rec);
    header.count += 1;
    try trustWriteHeader(io, f, header);
}

/// Entfernt einen Peer aus der Whitelist (soft-delete via Flag).
pub fn untrustPeer(io: Io, pubkey: [32]u8) !void {
    const f = try trustOpenOrCreate(io);
    defer f.close(io);

    var header = try trustReadHeader(io, f);
    const total = try trustRecordCount(io, f);

    for (0..total) |i| {
        var rec = try trustReadRecord(io, f, @intCast(i));
        if (!rec.isDeleted() and std.mem.eql(u8, &rec.pubkey, &pubkey)) {
            rec.flags |= TRUST_FLAG_DELETED;
            try trustWriteRecord(io, f, @intCast(i), rec);
            if (header.count > 0) header.count -= 1;
            try trustWriteHeader(io, f, header);
            return;
        }
    }
    return TrustError.NotFound;
}

/// Die zentrale Sicherheitspruefung: darf dieser Public Key ueberhaupt reden?
/// Wird von der Action-/Request-Verarbeitung VOR jeder Signaturpruefung und
/// VOR jeder Antwort aufgerufen. Bei `false` folgt: nichts. Kein Fehlerpaket,
/// kein nach aussen sichtbares Antwortverhalten.
pub fn isTrusted(io: Io, pubkey: [32]u8) bool {
    const f = trustOpenReadOnly(io) catch return false;
    defer f.close(io);

    const total = trustRecordCount(io, f) catch return false;

    for (0..total) |i| {
        const rec = trustReadRecord(io, f, @intCast(i)) catch return false;
        if (rec.isDeleted()) continue;
        if (std.mem.eql(u8, &rec.pubkey, &pubkey)) return true;
    }
    return false;
}

/// Iteriert ueber alle aktiven (nicht geloeschten) Trust-Eintraege, z.B. fuer
/// `sipctl trust list`.
pub fn forEachTrustedPeer(
    io: Io,
    comptime Context: type,
    ctx: Context,
    comptime callback: fn (ctx: Context, entry: TrustedPeer) anyerror!void,
) !void {
    const f = trustOpenReadOnly(io) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    defer f.close(io);

    const total = try trustRecordCount(io, f);

    for (0..total) |i| {
        const rec = try trustReadRecord(io, f, @intCast(i));
        if (rec.isDeleted()) continue;

        var entry: TrustedPeer = undefined;
        entry.pubkey = rec.pubkey;
        const lbl = rec.getLabel();
        entry.label_len = @min(lbl.len, entry.label_buf.len);
        @memcpy(entry.label_buf[0..entry.label_len], lbl[0..entry.label_len]);

        try callback(ctx, entry);
    }
}

/// Parst einen Hex-String (64 Zeichen) zu einem 32-Byte Public Key.
/// Praktisch fuer CLI-Eingaben wie `sipctl trust <hex> <label>`.
pub fn parsePubkeyHex(text: []const u8) ![32]u8 {
    if (text.len != 64) return TrustError.InvalidPubkeyHex;
    var out: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, text) catch return TrustError.InvalidPubkeyHex;
    return out;
}

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
            std.debug.print("Error: No write access to '{s}'\n", .{ROOT});
            return err;
        },
        else => return err,
    };
    fs.chmodPath(ROOT, 0o755) catch return KeystoreError.ChmodFailed;
    fs.chownPath(ROOT, 0, sip_gid) catch return KeystoreError.ChmodFailed;

    fs.createDirPath(io, dir) catch |err| switch (err) {
        error.PathAlreadyExists => return KeystoreError.IdentityAlreadyExists,
        error.AccessDenied => {
            std.debug.print("Error: No write access to '{s}'\n", .{dir});
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
