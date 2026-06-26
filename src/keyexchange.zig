const std = @import("std");
const sip = @import("sip");
const keystore = @import("keystore.zig");

const X25519 = std.crypto.dh.X25519;
const Ed25519 = std.crypto.sign.Ed25519;
const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const PUBLIC_KEY_SIZE = X25519.public_length;
pub const SECRET_KEY_SIZE = X25519.secret_length;
pub const SIGNATURE_SIZE = Ed25519.Signature.encoded_length;
pub const IDENTITY_PUBLIC_KEY_SIZE = 32;
pub const DERIVED_KEY_SIZE = 32;
pub const SIP_ADDRESS_SIZE = 16;

pub const KeyExchangeError = error{
    InvalidPeerPublicKey,
    InvalidPeerSignature,
    IdentityMismatch,
} || sip.identity.SipError;

pub const Identity = struct {
    keys: sip.identity.KeyPair,
    address: [SIP_ADDRESS_SIZE]u8,

    pub fn create(io: std.Io, name: []const u8, password: []const u8) !Identity {
        const keys = try keystore.createIdentity(io, name, password);
        return .{ .keys = keys, .address = sip.identity.baseAddress(keys.public) };
    }

    pub fn load(io: std.Io, name: []const u8, password: []const u8) !Identity {
        const keys = try keystore.loadIdentity(io, name, password);
        return .{ .keys = keys, .address = sip.identity.baseAddress(keys.public) };
    }

    pub fn formatAddress(self: Identity, buf: []u8) ![]const u8 {
        return sip.identity.formatSipAddress(buf, self.address);
    }
};

pub const EphemeralKeyPair = struct {
    secret_key: [SECRET_KEY_SIZE]u8,
    public_key: [PUBLIC_KEY_SIZE]u8,

    pub fn generate(io: std.Io) !EphemeralKeyPair {
        var secret_key: [SECRET_KEY_SIZE]u8 = undefined;
        try io.randomSecure(&secret_key);

        const public_key = try X25519.recoverPublicKey(secret_key);

        return .{
            .secret_key = secret_key,
            .public_key = public_key,
        };
    }

    pub fn deinit(self: *EphemeralKeyPair) void {
        std.crypto.secureZero(u8, &self.secret_key);
    }
};

pub const HandshakeMessage = struct {
    identity_public_key: [IDENTITY_PUBLIC_KEY_SIZE]u8,
    ephemeral_public_key: [PUBLIC_KEY_SIZE]u8,
    signature: [SIGNATURE_SIZE]u8,

    const Self = @This();

    pub fn create(identity: Identity, ephemeral: EphemeralKeyPair) !Self {
        const sk = try Ed25519.SecretKey.fromBytes(identity.keys.secret);
        const kp = try Ed25519.KeyPair.fromSecretKey(sk);
        const sig = try kp.sign(&ephemeral.public_key, null);

        return .{
            .identity_public_key = identity.keys.public,
            .ephemeral_public_key = ephemeral.public_key,
            .signature = sig.toBytes(),
        };
    }

    pub fn verify(self: Self) KeyExchangeError!void {
        const pk = Ed25519.PublicKey.fromBytes(self.identity_public_key) catch {
            return KeyExchangeError.InvalidPeerPublicKey;
        };
        const sig = Ed25519.Signature.fromBytes(self.signature);
        sig.verify(&self.ephemeral_public_key, pk) catch {
            return KeyExchangeError.InvalidPeerSignature;
        };
    }

    pub fn peerAddress(self: Self) [SIP_ADDRESS_SIZE]u8 {
        return sip.identity.baseAddress(self.identity_public_key);
    }
};

pub const SessionKeys = struct {
    tx: [DERIVED_KEY_SIZE]u8,
    rx: [DERIVED_KEY_SIZE]u8,
    peer_address: [SIP_ADDRESS_SIZE]u8,
    conn_id: u64,

    pub fn deinit(self: *SessionKeys) void {
        std.crypto.secureZero(u8, &self.tx);
        std.crypto.secureZero(u8, &self.rx);
    }
};

pub fn completeHandshake(
    local_identity: Identity,
    local_ephemeral: EphemeralKeyPair,
    peer_message: HandshakeMessage,
    expected_peer_address: ?[SIP_ADDRESS_SIZE]u8,
) KeyExchangeError!SessionKeys {
    try peer_message.verify();

    const peer_address = peer_message.peerAddress();
    if (expected_peer_address) |expected| {
        if (!std.mem.eql(u8, &expected, &peer_address)) {
            return KeyExchangeError.IdentityMismatch;
        }
    }

    const shared_secret = X25519.scalarmult(
        local_ephemeral.secret_key,
        peer_message.ephemeral_public_key,
    ) catch {
        return KeyExchangeError.InvalidPeerPublicKey;
    };

    var transcript: [SIP_ADDRESS_SIZE * 2 + PUBLIC_KEY_SIZE * 2]u8 = undefined;
    const local_address = local_identity.address;
    const a_first = std.mem.lessThan(u8, &local_address, &peer_address);

    if (a_first) {
        @memcpy(transcript[0..16], &local_address);
        @memcpy(transcript[16..32], &peer_address);
        @memcpy(transcript[32..64], &local_ephemeral.public_key);
        @memcpy(transcript[64..96], &peer_message.ephemeral_public_key);
    } else {
        @memcpy(transcript[0..16], &peer_address);
        @memcpy(transcript[16..32], &local_address);
        @memcpy(transcript[32..64], &peer_message.ephemeral_public_key);
        @memcpy(transcript[64..96], &local_ephemeral.public_key);
    }

    const prk = HkdfSha256.extract(&transcript, &shared_secret);

    var key_a_to_b: [DERIVED_KEY_SIZE]u8 = undefined;
    var key_b_to_a: [DERIVED_KEY_SIZE]u8 = undefined;
    HkdfSha256.expand(&key_a_to_b, "sip-handshake a->b", prk);
    HkdfSha256.expand(&key_b_to_a, "sip-handshake b->a", prk);

    var conn_id_bytes: [8]u8 = undefined;
    HkdfSha256.expand(&conn_id_bytes, "sip-handshake conn-id", prk);
    const conn_id = std.mem.readInt(u64, &conn_id_bytes, .big);

    const tx = if (a_first) key_a_to_b else key_b_to_a;
    const rx = if (a_first) key_b_to_a else key_a_to_b;

    return .{
        .tx = tx,
        .rx = rx,
        .peer_address = peer_address,
        .conn_id = conn_id,
    };
}

test "handshake derives matching, opposite-direction session keys" {
    const io = std.testing.io;

    var alice_eph = try EphemeralKeyPair.generate(io);
    defer alice_eph.deinit();
    var bob_eph = try EphemeralKeyPair.generate(io);
    defer bob_eph.deinit();

    const alice_id_kp = Ed25519.KeyPair.generate(io);
    const bob_id_kp = Ed25519.KeyPair.generate(io);

    const alice_identity = sip.identity.KeyPair{
        .public = alice_id_kp.public_key.toBytes(),
        .secret = alice_id_kp.secret_key.toBytes(),
    };
    const bob_identity = sip.identity.KeyPair{
        .public = bob_id_kp.public_key.toBytes(),
        .secret = bob_id_kp.secret_key.toBytes(),
    };

    const alice = Identity{ .keys = alice_identity, .address = sip.identity.baseAddress(alice_identity.public) };
    const bob = Identity{ .keys = bob_identity, .address = sip.identity.baseAddress(bob_identity.public) };

    const msg_from_alice = try HandshakeMessage.create(alice, alice_eph);
    const msg_from_bob = try HandshakeMessage.create(bob, bob_eph);

    var alice_session = try completeHandshake(alice, alice_eph, msg_from_bob, bob.address);
    defer alice_session.deinit();
    var bob_session = try completeHandshake(bob, bob_eph, msg_from_alice, alice.address);
    defer bob_session.deinit();

    try std.testing.expectEqualSlices(u8, &alice_session.tx, &bob_session.rx);
    try std.testing.expectEqualSlices(u8, &alice_session.rx, &bob_session.tx);
    try std.testing.expectEqualSlices(u8, &alice_session.peer_address, &bob.address);
    try std.testing.expectEqualSlices(u8, &bob_session.peer_address, &alice.address);
}

test "tampered ephemeral key fails signature verification" {
    const io = std.testing.io;

    var eph = try EphemeralKeyPair.generate(io);
    defer eph.deinit();

    const id_kp = Ed25519.KeyPair.generate(io);
    const identity = Identity{
        .keys = .{ .public = id_kp.public_key.toBytes(), .secret = id_kp.secret_key.toBytes() },
        .address = sip.identity.baseAddress(id_kp.public_key.toBytes()),
    };

    var msg = try HandshakeMessage.create(identity, eph);
    msg.ephemeral_public_key[0] ^= 0xff;

    try std.testing.expectError(KeyExchangeError.InvalidPeerSignature, msg.verify());
}

test "unexpected peer identity is rejected" {
    const io = std.testing.io;

    var alice_eph = try EphemeralKeyPair.generate(io);
    defer alice_eph.deinit();
    var bob_eph = try EphemeralKeyPair.generate(io);
    defer bob_eph.deinit();
    var mallory_eph = try EphemeralKeyPair.generate(io);
    defer mallory_eph.deinit();

    const alice_id_kp = Ed25519.KeyPair.generate(io);
    const mallory_id_kp = Ed25519.KeyPair.generate(io);

    const alice = Identity{
        .keys = .{ .public = alice_id_kp.public_key.toBytes(), .secret = alice_id_kp.secret_key.toBytes() },
        .address = sip.identity.baseAddress(alice_id_kp.public_key.toBytes()),
    };
    const mallory = Identity{
        .keys = .{ .public = mallory_id_kp.public_key.toBytes(), .secret = mallory_id_kp.secret_key.toBytes() },
        .address = sip.identity.baseAddress(mallory_id_kp.public_key.toBytes()),
    };

    const msg_from_mallory = try HandshakeMessage.create(mallory, mallory_eph);
    const bob_id_kp = Ed25519.KeyPair.generate(io);
    const expected_bob_address = sip.identity.baseAddress(bob_id_kp.public_key.toBytes());

    try std.testing.expectError(
        KeyExchangeError.IdentityMismatch,
        completeHandshake(alice, alice_eph, msg_from_mallory, expected_bob_address),
    );
}
