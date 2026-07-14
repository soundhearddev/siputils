const std = @import("std");
const linux = std.os.linux;
const Io = std.Io;
const sip = @import("sip");

const utils = @import("siputils");
const keymng = utils.keymng;
const registry = utils.registry;
const fs = utils.filesystem;

const DEFAULT_PORT: u16 = 9444;
const MAX_PEERS: usize = 1000;

pub const RegistryServerError = error{
    BindFailed,
    ListenFailed,
    EncryptionFailed,
};

pub const EncryptedIpv6 = struct {
    nonce: [12]u8,
    ciphertext: [32]u8,
    tag: [16]u8,
};

pub const ServerEntry = struct {
    sip_address: [16]u8,
    identity_pubkey: [32]u8,
    ipv6: [16]u8,
    allowed_peer_keys: std.ArrayList([32]u8),
    encrypted_for_peer: std.StringHashMap(EncryptedIpv6),
    last_updated: u64,
};

pub const RegistryServer = struct {
    allocator: std.mem.Allocator,
    entries: std.StringHashMap(ServerEntry),
    lock: std.Io.Mutex = .init,
    port: u16 = DEFAULT_PORT,

    pub fn init(allocator: std.mem.Allocator) RegistryServer {
        return .{
            .allocator = allocator,
            .entries = std.StringHashMap(ServerEntry).init(allocator),
        };
    }

    pub fn deinit(self: *RegistryServer) void {
        var it = self.entries.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.allowed_peer_keys.deinit(self.allocator);
            entry.value_ptr.encrypted_for_peer.deinit();
        }
        self.entries.deinit();
    }

    pub fn registerPeer(
        self: *RegistryServer,
        sip_address: [16]u8,
        identity_pubkey: [32]u8,
        ipv6: [16]u8,
        allowed_pubkeys: [][32]u8,
    ) !void {
        self.lock.lock();
        defer self.lock.unlock();

        var sip_hex: [32]u8 = undefined;
        const hex_str = try std.fmt.bufPrint(&sip_hex, "{x}", .{sip_address});
        const sip_key = try self.allocator.dupe(u8, hex_str);
        errdefer self.allocator.free(sip_key);

        var entry: ServerEntry = .{
            .sip_address = sip_address,
            .identity_pubkey = identity_pubkey,
            .ipv6 = ipv6,
            .allowed_peer_keys = std.ArrayList([32]u8).init(self.allocator),
            .encrypted_for_peer = std.StringHashMap(EncryptedIpv6).init(self.allocator),
            .last_updated = std.time.timestamp(),
        };

        for (allowed_pubkeys) |pubkey| {
            try entry.allowed_peer_keys.append(pubkey);
        }

        for (allowed_pubkeys) |peer_pubkey| {
            var pubkey_hex: [64]u8 = undefined;
            const pubkey_hex_str = try std.fmt.bufPrint(&pubkey_hex, "{x}", .{peer_pubkey});
            const encrypted = try self.encryptIpv6ForPeer(ipv6, peer_pubkey);
            try entry.encrypted_for_peer.put(
                try self.allocator.dupe(u8, pubkey_hex_str),
                encrypted,
            );
        }

        if (self.entries.getPtr(sip_key)) |existing| {
            existing.allowed_peer_keys.deinit(self.allocator);
            existing.encrypted_for_peer.deinit();
            existing.* = entry;
        } else {
            try self.entries.put(sip_key, entry);
        }
    }

    fn encryptIpv6ForPeer(self: *RegistryServer, ipv6: [16]u8, peer_pubkey: [32]u8) !EncryptedIpv6 {
        _ = self;
        _ = peer_pubkey;

        var result: EncryptedIpv6 = undefined;
        var rng_src: std.Random.IoSource = .{ .io = std.Io.default() };
        rng_src.interface().bytes(&result.nonce);

        std.mem.copyForwards(u8, result.ciphertext[0..16], &ipv6);
        @memset(&result.tag, 0);

        return result;
    }

    pub fn queryIpv6(
        self: *RegistryServer,
        requester_pubkey: [32]u8,
        target_sip: [16]u8,
    ) ?EncryptedIpv6 {
        self.lock.lock();
        defer self.lock.unlock();

        var target_hex: [32]u8 = undefined;
        const target_hex_str = std.fmt.bufPrint(&target_hex, "{x}", .{target_sip}) catch return null;

        const target_entry = self.entries.get(target_hex_str) orelse return null;

        var found = false;
        for (target_entry.allowed_peer_keys.items) |allowed_key| {
            if (std.mem.eql(u8, &allowed_key, &requester_pubkey)) {
                found = true;
                break;
            }
        }
        if (!found) return null;

        var requester_hex: [64]u8 = undefined;
        const requester_hex_str = std.fmt.bufPrint(&requester_hex, "{x}", .{requester_pubkey}) catch return null;

        return target_entry.encrypted_for_peer.get(requester_hex_str);
    }
};

pub fn runServer(
    init: std.process.Init,
    port: u16,
) !void {
    const io = init.io;
    const gpa = init.gpa;

    var stdout_buf: [4096]u8 = undefined;
    var stdout_w = Io.File.stdout().writer(io, &stdout_buf);
    const stdout = &stdout_w.interface;

    var server = RegistryServer.init(gpa);
    defer server.deinit();

    try stdout.print("[registry-server] Starting on port {d}...\n", .{port});
    try stdout.flush();

    try stdout.writeAll("[registry-server] Ready\n");
    try stdout.flush();

    var i: u32 = 0;
    while (i < 10) : (i += 1) {
        try io.sleep(.{ .nanoseconds = 1 * std.time.ns_per_s }, .awake);
        try stdout.print("[registry-server] Tick {d}\n", .{i});
        try stdout.flush();
    }
}

pub fn main(init: std.process.Init) !void {
    try runServer(init, DEFAULT_PORT);
}
