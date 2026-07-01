const std = @import("std");
const sip = @import("sip");

const Ed25519 = std.crypto.sign.Ed25519;

/// Vordefinierte Server-Actions. u8 -> feste, bekannte Menge.
/// Die konkrete Ausführung ist hier bewusst simpel/egal (siehe Aufgabenstellung) -
/// der Fokus liegt auf Auth/Verifizierung des Aufrufs.
pub const Action = enum(u8) {
    ping = 0x01,
    status = 0x02,
    reload_config = 0x03,
    shutdown = 0x04,
    _,
};

pub const ACTION_REQUEST_VERSION: u8 = 1;

/// Fehler, die bei der Verifizierung eines Action-Requests auftreten koennen.
pub const ActionError = error{
    UnknownAction,
    NotAuthorized,
    InvalidSignature,
    StaleRequest,
    ReplayedNonce,
    MalformedRequest,
} || std.mem.Allocator.Error;

/// Der SIP-Payload fuer .Data Pakete, die eine Action ausloesen sollen.
/// Wire-Format (alles big-endian wo relevant):
///
///   [0]      u8   version           (= ACTION_REQUEST_VERSION)
///   [1]      u8   action_id
///   [2..10)  u64  nonce             (big endian, client-random)
///   [10..18) i64  timestamp_unix    (big endian, Sekunden seit Epoch)
///   [18..19) u8   arg_len
///   [19..19+arg_len) arg bytes      (actionspezifisch, hier ungenutzt/optional)
///   [..]     [64]u8 ed25519 signature ueber alle vorherigen Bytes
///             plus conn_id (u64 BE) und seq_num (u32 BE) des SIP-Pakets,
///             damit die Signatur an die konkrete Verbindung gebunden ist.
pub const ActionRequest = struct {
    version: u8,
    action: Action,
    nonce: u64,
    timestamp: i64,
    arg: []const u8,
    signature: [Ed25519.Signature.encoded_length]u8,

    /// Bytes, die tatsaechlich signiert wurden (ohne die Signatur selbst),
    /// mit conn_id/seq_num des SIP-Transports als Bindung angehaengt.
    fn signedMessage(
        buf: []u8,
        version: u8,
        action: Action,
        nonce: u64,
        timestamp: i64,
        arg: []const u8,
        conn_id: u64,
        seq_num: u32,
    ) []u8 {
        var w: usize = 0;
        buf[w] = version;
        w += 1;
        buf[w] = @intFromEnum(action);
        w += 1;
        std.mem.writeInt(u64, buf[w..][0..8], nonce, .big);
        w += 8;
        std.mem.writeInt(i64, buf[w..][0..8], timestamp, .big);
        w += 8;
        buf[w] = @intCast(arg.len);
        w += 1;
        @memcpy(buf[w..][0..arg.len], arg);
        w += arg.len;
        std.mem.writeInt(u64, buf[w..][0..8], conn_id, .big);
        w += 8;
        std.mem.writeInt(u32, buf[w..][0..4], seq_num, .big);
        w += 4;
        return buf[0..w];
    }

    /// Baut einen signierten Request und serialisiert ihn direkt in `out`.
    /// Gibt die genutzte Slice-Laenge zurueck.
    pub fn buildSigned(
        out: []u8,
        keys: sip.identity.KeyPair,
        action: Action,
        nonce: u64,
        timestamp: i64,
        arg: []const u8,
        conn_id: u64,
        seq_num: u32,
    ) !usize {
        if (arg.len > 255) return ActionError.MalformedRequest;

        var msg_buf: [1 + 1 + 8 + 8 + 1 + 255 + 8 + 4]u8 = undefined;
        const msg = signedMessage(&msg_buf, ACTION_REQUEST_VERSION, action, nonce, timestamp, arg, conn_id, seq_num);

        const sk = try Ed25519.SecretKey.fromBytes(keys.secret);
        const kp = try Ed25519.KeyPair.fromSecretKey(sk);
        const sig = try kp.sign(msg, null);
        const sig_bytes = sig.toBytes();

        const header_len = 1 + 1 + 8 + 8 + 1;
        const total_len = header_len + arg.len + sig_bytes.len;
        if (out.len < total_len) return ActionError.MalformedRequest;

        var w: usize = 0;
        out[w] = ACTION_REQUEST_VERSION;
        w += 1;
        out[w] = @intFromEnum(action);
        w += 1;
        std.mem.writeInt(u64, out[w..][0..8], nonce, .big);
        w += 8;
        std.mem.writeInt(i64, out[w..][0..8], timestamp, .big);
        w += 8;
        out[w] = @intCast(arg.len);
        w += 1;
        @memcpy(out[w..][0..arg.len], arg);
        w += arg.len;
        @memcpy(out[w..][0..sig_bytes.len], &sig_bytes);
        w += sig_bytes.len;

        return w;
    }

    /// Parst einen rohen Payload in ein ActionRequest (ohne Signaturpruefung).
    pub fn parse(payload: []const u8) ActionError!ActionRequest {
        const header_len = 1 + 1 + 8 + 8 + 1;
        if (payload.len < header_len) return ActionError.MalformedRequest;

        var r: usize = 0;
        const version = payload[r];
        r += 1;
        const action: Action = @enumFromInt(payload[r]);
        r += 1;
        const nonce = std.mem.readInt(u64, payload[r..][0..8], .big);
        r += 8;
        const timestamp = std.mem.readInt(i64, payload[r..][0..8], .big);
        r += 8;
        const arg_len = payload[r];
        r += 1;

        if (r + arg_len + Ed25519.Signature.encoded_length != payload.len) {
            return ActionError.MalformedRequest;
        }

        const arg = payload[r .. r + arg_len];
        r += arg_len;

        var signature: [Ed25519.Signature.encoded_length]u8 = undefined;
        @memcpy(&signature, payload[r..][0..Ed25519.Signature.encoded_length]);

        return ActionRequest{
            .version = version,
            .action = action,
            .nonce = nonce,
            .timestamp = timestamp,
            .arg = arg,
            .signature = signature,
        };
    }

    /// Prueft die Signatur gegen den erwarteten Public Key des Peers und
    /// bindet sie an conn_id/seq_num des SIP-Transportpakets, in dem sie ankam.
    pub fn verify(
        self: ActionRequest,
        peer_identity_pubkey: [32]u8,
        conn_id: u64,
        seq_num: u32,
    ) ActionError!void {
        if (self.version != ACTION_REQUEST_VERSION) return ActionError.MalformedRequest;

        var msg_buf: [1 + 1 + 8 + 8 + 1 + 255 + 8 + 4]u8 = undefined;
        const msg = signedMessage(&msg_buf, self.version, self.action, self.nonce, self.timestamp, self.arg, conn_id, seq_num);

        const pk = Ed25519.PublicKey.fromBytes(peer_identity_pubkey) catch {
            return ActionError.InvalidSignature;
        };
        const sig = Ed25519.Signature.fromBytes(self.signature);
        sig.verify(msg, pk) catch {
            return ActionError.InvalidSignature;
        };
    }
};

/// Antwort auf einen Action-Request.
/// Wire-Format: [1]u8 ok(1)/err(0) [2..4)u16 msg_len [msg bytes]
pub const ActionResponse = struct {
    ok: bool,
    message: []const u8,

    pub fn encode(self: ActionResponse, out: []u8) ![]u8 {
        if (out.len < 3 + self.message.len) return error.BufferTooSmall;
        out[0] = if (self.ok) 1 else 0;
        std.mem.writeInt(u16, out[1..3], @intCast(self.message.len), .big);
        @memcpy(out[3..][0..self.message.len], self.message);
        return out[0 .. 3 + self.message.len];
    }

    pub fn decode(data: []const u8) !ActionResponse {
        if (data.len < 3) return error.MalformedResponse;
        const ok = data[0] == 1;
        const msg_len = std.mem.readInt(u16, data[1..3], .big);
        if (3 + msg_len != data.len) return error.MalformedResponse;
        return .{ .ok = ok, .message = data[3..] };
    }
};

/// Maximales Alter (Sekunden) eines Requests, bevor er als "stale" abgelehnt wird.
/// Schuetzt zusammen mit dem Nonce-Cache vor Replay-Angriffen.
pub const MAX_REQUEST_AGE_SECONDS: i64 = 30;

/// Einfacher In-Memory Replay-Schutz: (peer_address, nonce) Paare mit Ablaufzeit.
/// Bewusst simpel gehalten (linear scan + Ringpuffer), reicht fuer moderate Lastprofile.
pub const NonceCache = struct {
    pub const Entry = struct {
        addr: [16]u8,
        nonce: u64,
        expires_at: i64,
        used: bool = false,
    };

    entries: []Entry,
    next: usize = 0,

    pub fn init(buf: []Entry) NonceCache {
        for (buf) |*e| e.used = false;
        return .{ .entries = buf, .next = 0 };
    }

    /// Gibt true zurueck wenn die Nonce neu ist (also der Request akzeptiert wird)
    /// und merkt sie sich dabei. Gibt false zurueck bei Replay.
    pub fn checkAndInsert(self: *NonceCache, addr: [16]u8, nonce: u64, now: i64) bool {
        for (self.entries) |*e| {
            if (e.used and e.expires_at > now and std.mem.eql(u8, &e.addr, &addr) and e.nonce == nonce) {
                return false; // replay
            }
        }
        const slot = &self.entries[self.next];
        slot.* = .{ .addr = addr, .nonce = nonce, .expires_at = now + MAX_REQUEST_AGE_SECONDS, .used = true };
        self.next = (self.next + 1) % self.entries.len;
        return true;
    }
};

/// Server-seitige Autorisierungstabelle: welche mesh-Adressen duerfen welche Action ausfuehren.
/// Bewusst statisch/im Code definiert (siehe Aufgabenstellung: Actions selbst sind erstmal egal,
/// es geht um sauberes Rechte-Management).
pub const KnownClient = struct {
    addr: [16]u8,
    pubkey: [32]u8,
};

pub const ActionAllowlist = struct {
    action: Action,
    allowed_clients: []const KnownClient,
};

pub fn isAuthorized(allowlist: []const ActionAllowlist, action: Action, peer_addr: [16]u8) ActionError!void {
    for (allowlist) |entry| {
        if (entry.action == action) {
            for (entry.allowed_clients) |client| {
                if (std.mem.eql(u8, &client.addr, &peer_addr)) return;
            }
            return ActionError.NotAuthorized;
        }
    }
    return ActionError.UnknownAction;
}

const testing = std.testing;

test "ActionRequest sign/verify roundtrip" {
    const io = testing.io;
    const kp = sip.identity.generateKeyPair(io);

    var buf: [512]u8 = undefined;
    const len = try ActionRequest.buildSigned(&buf, kp, .ping, 12345, 1_700_000_000, "", 999, 3);
    const req = try ActionRequest.parse(buf[0..len]);

    try testing.expectEqual(Action.ping, req.action);
    try testing.expectEqual(@as(u64, 12345), req.nonce);

    try req.verify(kp.public, 999, 3);
}

test "ActionRequest verify lehnt falsche conn_id ab (Bindung schlaegt fehl)" {
    const io = testing.io;
    const kp = sip.identity.generateKeyPair(io);

    var buf: [512]u8 = undefined;
    const len = try ActionRequest.buildSigned(&buf, kp, .status, 1, 1_700_000_000, "", 111, 0);
    const req = try ActionRequest.parse(buf[0..len]);

    try testing.expectError(ActionError.InvalidSignature, req.verify(kp.public, 222, 0));
}

test "ActionRequest verify lehnt falschen Public Key ab" {
    const io = testing.io;
    const kp = sip.identity.generateKeyPair(io);
    const other_kp = sip.identity.generateKeyPair(io);

    var buf: [512]u8 = undefined;
    const len = try ActionRequest.buildSigned(&buf, kp, .status, 1, 1_700_000_000, "", 5, 0);
    const req = try ActionRequest.parse(buf[0..len]);

    try testing.expectError(ActionError.InvalidSignature, req.verify(other_kp.public, 5, 0));
}

test "isAuthorized erlaubt gelistete Adresse und lehnt andere ab" {
    const addr_a = [_]u8{0xAA} ** 16;
    const addr_b = [_]u8{0xBB} ** 16;

    const allowlist = [_]ActionAllowlist{
        .{ .action = .reload_config, .allowed = &[_][16]u8{addr_a} },
    };

    try isAuthorized(&allowlist, .reload_config, addr_a);
    try testing.expectError(ActionError.NotAuthorized, isAuthorized(&allowlist, .reload_config, addr_b));
    try testing.expectError(ActionError.UnknownAction, isAuthorized(&allowlist, .shutdown, addr_a));
}

test "NonceCache erkennt Replay" {
    var buf: [8]NonceCache.Entry = undefined;
    var cache = NonceCache.init(&buf);
    const addr = [_]u8{0x01} ** 16;

    try testing.expect(cache.checkAndInsert(addr, 42, 1000));
    try testing.expect(!cache.checkAndInsert(addr, 42, 1001)); // replay
    try testing.expect(cache.checkAndInsert(addr, 43, 1001)); // andere nonce ok
}

test "ActionResponse encode/decode roundtrip" {
    const resp = ActionResponse{ .ok = true, .message = "pong" };
    var buf: [64]u8 = undefined;
    const encoded = try resp.encode(&buf);
    const decoded = try ActionResponse.decode(encoded);
    try testing.expect(decoded.ok);
    try testing.expectEqualSlices(u8, "pong", decoded.message);
}
