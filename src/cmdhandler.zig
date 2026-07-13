const std = @import("std");
const sip = @import("sip");
const keymng = @import("keymng.zig");
const Io = std.Io;
const registry = @import("registry.zig");
const fs = @import("filesystem.zig");

pub const ArgIter = struct {
    argv: []const [:0]const u8,
    idx: *usize,

    pub fn next(self: *ArgIter) ?[]const u8 {
        if (self.idx.* >= self.argv.len) return null;
        const a = self.argv[self.idx.*];
        self.idx.* += 1;
        return a;
    }
};

pub const CliError = error{
    MissingArgument,
};

const PasswordSource = struct {
    flag: ?[]const u8 = null,
    env_name: []const u8 = "SIP_PASSWORD",
};

const ResolvedMessage = struct {
    bytes: []const u8,
    owned: bool,

    fn deinit(self: ResolvedMessage, allocator: std.mem.Allocator) void {
        if (self.owned) {
            allocator.free(self.bytes);
        }
    }
};

pub fn resolveMessage(io: std.Io, allocator: std.mem.Allocator, raw: []const u8) !ResolvedMessage {
    if (raw.len > 0 and raw[0] == '@') {
        const path = raw[1..];
        std.debug.print("[debug] --message starts with '@', reading file: \"{s}\"\n", .{path});
        const data = try fs.readFileBytes(io, allocator, path);
        std.debug.print("[debug] returning resolved Message\n", .{});
        return ResolvedMessage{ .bytes = data, .owned = true };
    }
    std.debug.print("[client] --message is treated as raw text ({d} bytes)\n", .{raw.len});
    return ResolvedMessage{ .bytes = raw, .owned = false };
}

fn readPasswordInteractive(io: std.Io, stdout: *Io.Writer, prompt: []const u8, out: []u8) ![]const u8 {
    try stdout.writeAll(prompt);
    try stdout.flush();

    const stdin_fd: std.posix.fd_t = std.posix.STDIN_FILENO;
    var old_termios: std.posix.termios = undefined;
    var have_old = false;

    if (std.posix.tcgetattr(stdin_fd)) |t| {
        old_termios = t;
        have_old = true;
        var raw = t;
        raw.lflag.ECHO = false;
        std.posix.tcsetattr(stdin_fd, .FLUSH, raw) catch {};
    } else |_| {}

    defer if (have_old) {
        std.posix.tcsetattr(stdin_fd, .FLUSH, old_termios) catch {};
    };

    var stdin_buf: [256]u8 = undefined;
    var stdin_r = Io.File.stdin().reader(io, &stdin_buf);
    const reader = &stdin_r.interface;

    const line = reader.takeDelimiterExclusive('\n') catch |err| switch (err) {
        error.EndOfStream => "",
        else => return err,
    };
    try stdout.writeAll("\n");
    try stdout.flush();

    const trimmed = std.mem.trim(u8, line, " \t\r");
    if (trimmed.len > out.len) return error.NoSpaceLeft;
    @memcpy(out[0..trimmed.len], trimmed);
    return out[0..trimmed.len];
}

pub fn resolvePassword(
    io: std.Io,
    stdout: *Io.Writer,
    env_map: *const std.process.Environ.Map,
    src: PasswordSource,
    buf: []u8,
    confirm: bool,
) ![]const u8 {
    if (src.flag) |p| {
        if (p.len > buf.len) return error.NoSpaceLeft;
        @memcpy(buf[0..p.len], p);
        return buf[0..p.len];
    }
    if (env_map.get(src.env_name)) |env_pw| {
        if (env_pw.len > buf.len) return error.NoSpaceLeft;
        @memcpy(buf[0..env_pw.len], env_pw);
        return buf[0..env_pw.len];
    }

    const pw = try readPasswordInteractive(io, stdout, "Password: ", buf);
    if (confirm) {
        var confirm_buf: [256]u8 = undefined;
        const pw2 = try readPasswordInteractive(io, stdout, "Confirm password: ", &confirm_buf);
        if (!std.mem.eql(u8, pw, pw2)) return error.PasswordMismatch;
    }
    return pw;
}

pub const ctl = struct {
    pub fn cmdNew(io: std.Io, stdout: *Io.Writer, env_map: *const std.process.Environ.Map, args: *ArgIter) !void {
        const name = args.next() orelse return CliError.MissingArgument;
        if (!keymng.validName(name)) {
            try stdout.writeAll("Error: Invalid name (only a-z, A-Z, 0-9, -, _, .)\n");
            try stdout.flush();
            return;
        }

        var pw_buf: [256]u8 = undefined;
        const password = try resolvePassword(io, stdout, env_map, .{}, &pw_buf, true);

        const kp = keymng.createIdentity(io, name, password) catch |err| switch (err) {
            keymng.KeystoreError.IdentityAlreadyExists => {
                try stdout.print("Error: Identity '{s}' already exists.\n", .{name});
                try stdout.flush();
                return;
            },
            error.AccessDenied => {
                try stdout.writeAll("Error: Sudo required.\n");
                try stdout.flush();
                return;
            },
            else => return err,
        };

        const base = sip.identity.baseAddress(kp.public);
        var addr_buf: [80]u8 = undefined;
        const addr = try sip.identity.formatSipAddress(&addr_buf, name, base);

        try stdout.print("[+] Identity '{s}' created\n", .{name});
        try stdout.print("    sip-address: {s}\n", .{addr});
        try stdout.print("    public-key : {x}\n", .{kp.public});
        try stdout.flush();
    }

    pub fn cmdShow(io: std.Io, stdout: *Io.Writer, args: *ArgIter) !void {
        const name = args.next() orelse return CliError.MissingArgument;

        const pub_bytes = keymng.loadPublicOnly(io, name) catch |err| switch (err) {
            keymng.KeystoreError.IdentityNotFound => {
                try stdout.print("Error: Identity '{s}' not found.\n", .{name});
                try stdout.flush();
                return;
            },
            else => return err,
        };
        const base = sip.identity.baseAddress(pub_bytes);
        var addr_buf: [80]u8 = undefined;
        const addr = try sip.identity.formatSipAddress(&addr_buf, name, base);

        var dir_buf: [300]u8 = undefined;
        const dpath = try keymng.identityDir(&dir_buf, name);

        try stdout.print("name        : {s}\n", .{name});
        try stdout.print("sip-address : {s}\n", .{addr});
        try stdout.print("public-key  : {x}\n", .{pub_bytes});
        try stdout.print("base-addr   : {x}\n", .{base});
        try stdout.print("keydir      : {s}\n", .{dpath});
        try stdout.flush();
    }

    pub fn cmdId(io: std.Io, stdout: *Io.Writer, args: *ArgIter) !void {
        const name = args.next() orelse return CliError.MissingArgument;
        const pub_bytes = keymng.loadPublicOnly(io, name) catch |err| switch (err) {
            keymng.KeystoreError.IdentityNotFound => {
                try stdout.print("Error: Identity '{s}' not found.\n", .{name});
                try stdout.flush();
                return;
            },
            else => return err,
        };

        var nonce: [16]u8 = undefined;
        const rng_src: std.Random.IoSource = .{ .io = io };
        rng_src.interface().bytes(&nonce);

        const id = sip.identity.genId(pub_bytes, nonce);
        try stdout.print("{x}\n", .{id});
        try stdout.flush();
    }

    pub fn cmdExport(io: std.Io, stdout: *Io.Writer, args: *ArgIter) !void {
        const name = args.next() orelse return CliError.MissingArgument;
        const pub_bytes = keymng.loadPublicOnly(io, name) catch |err| switch (err) {
            keymng.KeystoreError.IdentityNotFound => {
                try stdout.print("Error: Identity '{s}' not found.\n", .{name});
                try stdout.flush();
                return;
            },
            else => return err,
        };
        const base = sip.identity.baseAddress(pub_bytes);
        var addr_buf: [80]u8 = undefined;
        const addr = try sip.identity.formatSipAddress(&addr_buf, name, base);
        try stdout.print("{s} {x}\n", .{ addr, pub_bytes });
        try stdout.flush();
    }

    pub fn cmdRemove(io: std.Io, stdout: *Io.Writer, args: *ArgIter) !void {
        const name = args.next() orelse return CliError.MissingArgument;

        keymng.deleteIdentity(io, name) catch |err| switch (err) {
            keymng.KeystoreError.IdentityNotFound => {
                try stdout.print("Error: Identity '{s}' not found.\n", .{name});
                try stdout.flush();
                return;
            },
            error.AccessDenied => {
                try stdout.writeAll("Error: Sudo required.\n");
                try stdout.flush();
                return;
            },
            else => return err,
        };

        try stdout.print("[-] Identity '{s}' deleted\n", .{name});
        try stdout.flush();
    }

    pub fn cmdPasswd(io: std.Io, stdout: *Io.Writer, env_map: *const std.process.Environ.Map, args: *ArgIter) !void {
        const name = args.next() orelse return CliError.MissingArgument;

        try stdout.writeAll("Current ");
        try stdout.flush();
        var old_pw_buf: [256]u8 = undefined;
        const old_pw = try resolvePassword(io, stdout, env_map, .{}, &old_pw_buf, false);

        try stdout.writeAll("New ");
        try stdout.flush();
        var new_pw_buf: [256]u8 = undefined;
        const new_pw = try resolvePassword(io, stdout, env_map, .{}, &new_pw_buf, true);

        _ = keymng.changePassword(io, name, old_pw, new_pw) catch |err| switch (err) {
            keymng.KeystoreError.IdentityNotFound => {
                try stdout.print("Error: Identity '{s}' not found.\n", .{name});
                try stdout.flush();
                return;
            },
            sip.identity.SipError.DecryptionFailed => {
                try stdout.writeAll("Error: Wrong password.\n");
                try stdout.flush();
                return;
            },
            error.AccessDenied => {
                try stdout.writeAll("Error: Sudo required.\n");
                try stdout.flush();
                return;
            },
            else => return err,
        };

        try stdout.print("[+] Password for '{s}' changed\n", .{name});
        try stdout.flush();
    }
    pub fn cmdSend(io: std.Io, allocator: std.mem.Allocator, stdout: *Io.Writer, env_map: *const std.process.Environ.Map, args: *ArgIter) !void {
        const identity_name = args.next() orelse {
            try stdout.flush();
            return;
        };

        const host = args.next() orelse {
            try stdout.flush();
            return;
        };

        var port: u16 = 9443;
        var message: ?[]const u8 = null;

        while (args.next()) |arg| {
            if (std.mem.eql(u8, arg, "--port")) {
                if (args.next()) |port_str| {
                    port = std.fmt.parseInt(u16, port_str, 10) catch {
                        try stdout.writeAll("Error: Invalid port\n");
                        try stdout.flush();
                        return;
                    };
                }
            } else {
                message = arg;
                break;
            }
        }

        if (message == null) {
            try stdout.writeAll("Error: No message provided\n");
            try stdout.flush();
            return;
        }

        var pw_buf: [256]u8 = undefined;
        const password = try resolvePassword(io, stdout, env_map, .{}, &pw_buf, false);

        const keys = keymng.loadIdentity(io, identity_name, password) catch |err| {
            try stdout.print("Error loading identity: {}\n", .{err});
            try stdout.flush();
            return;
        };

        const local_addr = sip.identity.baseAddress(keys.public);

        const resolved_host = registry.resolve(io, host) catch |err| switch (err) {
            registry.RegistryError.NotFound => {
                try stdout.print("Error: Host/name '{s}' not found.\n", .{host});
                try stdout.flush();
                return;
            },
            registry.RegistryError.Ambiguous => {
                try stdout.print("Error: Name '{s}' is ambiguous (multiple matches).\n", .{host});
                try stdout.flush();
                return;
            },
            else => return err,
        };

        const is_v6 = resolved_host.entry.kind == .ipv6;

        const sock = if (is_v6)
            try sip.synet.createTcpSocketFamily(std.posix.AF.INET6)
        else
            try sip.synet.createTcpSocket();
        defer sip.synet.close(sock);

        std.debug.print("[debug] connecting to {s}:{d}...\n", .{ host, port });

        switch (resolved_host.entry.kind) {
            .ipv6 => {
                const addr6 = sip.synet.buildSockaddrIn6(resolved_host.entry.ipv6, port);
                try sip.synet.connect6(sock, &addr6);
            },
            .ipv4 => {
                const ip4 = resolved_host.entry.ipv4;
                const addr4 = sip.synet.buildSockaddrIn(ip4, port);
                try sip.synet.connect(sock, &addr4);
            },
            .mesh => {
                try stdout.writeAll("Error: Mesh addresses are not supported for 'send' yet.\n");
                try stdout.flush();
                return;
            },
        }

        var disc_buf: [sip.header.OUTER_HEADER_SIZE]u8 = undefined;
        var src: [16]u8 = undefined;
        @memcpy(&src, &local_addr);
        const disc_pkt = try sip.header.buildDiscoveryPacket(&disc_buf, src, [_]u8{0} ** 16);

        try sip.synet.sendAll(sock, disc_pkt);

        var reply_buf: [34]u8 = undefined;
        try sip.synet.recvExact(sock, &reply_buf);

        if (reply_buf[0] != sip.header.MAGIC) return error.InvalidMagic;

        var peer_address: [16]u8 = undefined;
        @memcpy(&peer_address, reply_buf[2..18]);
        std.debug.print("[debug] Peer SIP address: {x}\n", .{peer_address});

        if (resolved_host.source == .registry or resolved_host.source == .registry_partial) {
            var mesh_buf: [registry.MESH_ADDR_SIZE]u8 = [_]u8{0} ** registry.MESH_ADDR_SIZE;
            @memcpy(mesh_buf[0..16], &peer_address);

            const lookup_name = if (resolved_host.source == .registry_partial)
                resolved_host.matchedName()
            else
                host;

            registry.updateMeshAddress(io, lookup_name, mesh_buf) catch {};
        }

        var session = try sip.handshake.performKeyExchange(io, allocator, sock, keys, local_addr, true, peer_address);
        defer session.deinit();
        std.debug.print("[debug] Key exchange completed.\n", .{});
        const key = session.tx;

        const resolved = try resolveMessage(io, allocator, message.?);
        defer resolved.deinit(allocator);
        const payload = resolved.bytes;

        const mesh_src = local_addr;
        const mesh_dst = peer_address;

        const packet_list = try sip.fragmentation.fragmentPayload(
            io,
            allocator,
            mesh_src,
            mesh_dst,
            session.conn_id,
            payload,
            key,
        );
        defer packet_list.deinit();

        for (packet_list.items, 0..) |wire_packet, idx| {
            std.debug.print("[debug] Sending packet {d}/{d} (size: {d} bytes)...\n", .{ idx + 1, packet_list.items.len, wire_packet.len });
            try sip.synet.sendAll(sock, wire_packet);
        }

        std.debug.print("[debug] Transfer completed. All packets sent.\n", .{});
    }

    pub fn cmdTrust(io: std.Io, stdout: *Io.Writer, args: *ArgIter) !void {
        const addr_hex = args.next() orelse {
            try stdout.flush();
            return;
        };
        const label = args.next() orelse {
            try stdout.flush();
            return;
        };

        const addr = keymng.parseAddrHex(addr_hex) catch {
            try stdout.writeAll("Error: Invalid address (expected 32 hex characters).\n");
            try stdout.flush();
            return;
        };

        keymng.trustPeer(io, addr, label) catch |err| switch (err) {
            keymng.TrustError.AlreadyTrusted => {
                try stdout.print("Error: Address is already trusted.\n", .{});
                try stdout.flush();
                return;
            },
            keymng.TrustError.LabelTooLong => {
                try stdout.writeAll("Error: Label too long.\n");
                try stdout.flush();
                return;
            },
            error.AccessDenied => {
                try stdout.writeAll("Error: Sudo required.\n");
                try stdout.flush();
                return;
            },
            else => return err,
        };

        try stdout.print("[+] Peer trusted: {s} ({x})\n", .{ label, addr });
        try stdout.flush();
    }

    pub fn cmdUntrust(io: std.Io, stdout: *Io.Writer, args: *ArgIter) !void {
        const addr_hex = args.next() orelse {
            try stdout.flush();
            return;
        };

        const addr = keymng.parseAddrHex(addr_hex) catch {
            try stdout.writeAll("Error: Invalid address (expected 32 hex characters).\n");
            try stdout.flush();
            return;
        };

        keymng.untrustPeer(io, addr) catch |err| switch (err) {
            keymng.TrustError.NotFound => {
                try stdout.writeAll("Error: This address is not on the trust list.\n");
                try stdout.flush();
                return;
            },
            error.AccessDenied => {
                try stdout.writeAll("Error: Sudo required.\n");
                try stdout.flush();
                return;
            },
            else => return err,
        };

        try stdout.print("[-] Peer removed: {x}\n", .{addr});
        try stdout.flush();
    }

    const TrustListCtx = struct { stdout: *Io.Writer };

    fn printTrustedPeer(ctx: TrustListCtx, entry: keymng.TrustedPeer) !void {
        try ctx.stdout.print("{x}  {s}\n", .{ entry.addr, entry.label() });
    }

    pub fn cmdTrustList(io: std.Io, stdout: *Io.Writer) !void {
        try keymng.forEachTrustedPeer(io, TrustListCtx, .{ .stdout = stdout }, printTrustedPeer);
        try stdout.flush();
    }
};
