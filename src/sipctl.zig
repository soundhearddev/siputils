const std = @import("std");
const sip = @import("sip");
const keymng = @import("keymng.zig");
const Io = std.Io;
const registry = @import("registry.zig");

const CliError = error{
    MissingArgument,
};

const ArgIter = struct {
    argv: []const [:0]const u8,
    idx: *usize,

    fn next(self: *ArgIter) ?[]const u8 {
        if (self.idx.* >= self.argv.len) return null;
        const a = self.argv[self.idx.*];
        self.idx.* += 1;
        return a;
    }
};

var config = struct { verbose: bool }{ .verbose = false };

fn verbosePrint(verbose: bool, comptime fmt: []const u8, args: anytype) void {
    if (verbose) {
        std.debug.print(fmt, args);
    }
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

const PasswordSource = struct {
    flag: ?[]const u8 = null,
    env_name: []const u8 = "SIP_PASSWORD",
};

fn resolvePassword(
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

    const pw = try readPasswordInteractive(io, stdout, "Passwort: ", buf);
    if (confirm) {
        var confirm_buf: [256]u8 = undefined;
        const pw2 = try readPasswordInteractive(io, stdout, "Passwort bestätigen: ", &confirm_buf);
        if (!std.mem.eql(u8, pw, pw2)) return error.PasswordMismatch;
    }
    return pw;
}

const ListCtx = struct {
    stdout: *Io.Writer,
    verbose: bool,
    idx: usize = 1,
};

pub fn formatSipAddress(buf: []u8, name: []const u8, base: [16]u8) ![]const u8 {
    return std.fmt.bufPrint(buf, "{s}.{x}", .{ name, base });
}

fn printIdentityEntry(ctx: *ListCtx, entry: keymng.IdentityEntry, name: []const u8) !void {
    if (!entry.valid) {
        try ctx.stdout.print("{d}: {s}: <kein gültiger public key>\n", .{ ctx.idx, entry.name() });
        ctx.idx += 1;
        return;
    }

    const base = sip.identity.baseAddress(entry.public);
    var addr_buf: [80]u8 = undefined;
    const addr = try formatSipAddress(&addr_buf, name, base);

    if (ctx.verbose) {
        try ctx.stdout.print("{d}: {s}\n", .{ ctx.idx, entry.name() });
        try ctx.stdout.print("    sip-address: {s}\n", .{addr});
        try ctx.stdout.print("    public-key : {x}\n", .{entry.public});
        try ctx.stdout.print("    base-addr  : {x}\n", .{base});
        var dir_buf: [300]u8 = undefined;
        const dpath = try keymng.identityDir(&dir_buf, entry.name());
        try ctx.stdout.print("    keydir     : {s}\n", .{dpath});
        try ctx.stdout.writeAll("\n");
    } else {
        try ctx.stdout.print("{d}: {s}: {x}\n", .{ ctx.idx, entry.name(), base });
    }
    ctx.idx += 1;
}

fn listIdentities(io: std.Io, stdout: *Io.Writer, verbose: bool) !void {
    var ctx = ListCtx{ .stdout = stdout, .verbose = verbose };

    keymng.forEachIdentity(io, *ListCtx, &ctx, struct {
        fn cb(c: *ListCtx, entry: keymng.IdentityEntry) !void {
            try printIdentityEntry(c, entry, entry.name());
        }
    }.cb) catch |err| switch (err) {
        keymng.ListError.KeyRootMissing => {
            try stdout.writeAll("Keine Identitäten gefunden. (Ordner 'keys/' existiert nicht)\n");
            try stdout.writeAll("Erstelle eine mit: sipctl new <name>\n");
            try stdout.flush();
            return;
        },
        else => return err,
    };

    if (ctx.idx == 1) {
        try stdout.writeAll("Keine Identitäten gefunden.\n");
        try stdout.writeAll("Erstelle eine mit: sipctl new <name>\n");
    }
    try stdout.flush();
}

fn cmdNew(io: std.Io, stdout: *Io.Writer, env_map: *const std.process.Environ.Map, args: *ArgIter) !void {
    const name = args.next() orelse return CliError.MissingArgument;
    if (!keymng.validName(name)) {
        try stdout.writeAll("Fehler: Ungültiger Name (nur a-z, A-Z, 0-9, -, _, .)\n");
        try stdout.flush();
        return;
    }

    var pw_buf: [256]u8 = undefined;
    const password = try resolvePassword(io, stdout, env_map, .{}, &pw_buf, true);

    const kp = keymng.createIdentity(io, name, password) catch |err| switch (err) {
        keymng.KeystoreError.IdentityAlreadyExists => {
            try stdout.print("Fehler: Identität '{s}' existiert bereits.\n", .{name});
            try stdout.flush();
            return;
        },
        error.AccessDenied => {
            try stdout.writeAll("Fehler: Sudo erforderlich. Versuche: sudo sipctl new <name>\n");
            try stdout.flush();
            return;
        },
        else => return err,
    };

    const base = sip.identity.baseAddress(kp.public);
    var addr_buf: [80]u8 = undefined;
    const addr = try formatSipAddress(&addr_buf, name, base);

    try stdout.print("[+] Identität '{s}' erstellt\n", .{name});
    try stdout.print("    sip-address: {s}\n", .{addr});
    try stdout.print("    public-key : {x}\n", .{kp.public});
    try stdout.flush();
}

fn cmdShow(io: std.Io, stdout: *Io.Writer, args: *ArgIter) !void {
    const name = args.next() orelse return CliError.MissingArgument;

    const pub_bytes = keymng.loadPublicOnly(io, name) catch |err| switch (err) {
        keymng.KeystoreError.IdentityNotFound => {
            try stdout.print("Fehler: Identität '{s}' nicht gefunden.\n", .{name});
            try stdout.flush();
            return;
        },
        else => return err,
    };
    const base = sip.identity.baseAddress(pub_bytes);
    var addr_buf: [80]u8 = undefined;
    const addr = try formatSipAddress(&addr_buf, name, base);

    var dir_buf: [300]u8 = undefined;
    const dpath = try keymng.identityDir(&dir_buf, name);

    try stdout.print("name        : {s}\n", .{name});
    try stdout.print("sip-address : {s}\n", .{addr});
    try stdout.print("public-key  : {x}\n", .{pub_bytes});
    try stdout.print("base-addr   : {x}\n", .{base});
    try stdout.print("keydir      : {s}\n", .{dpath});
    try stdout.flush();
}

fn cmdId(io: std.Io, stdout: *Io.Writer, args: *ArgIter) !void {
    const name = args.next() orelse return CliError.MissingArgument;
    const pub_bytes = keymng.loadPublicOnly(io, name) catch |err| switch (err) {
        keymng.KeystoreError.IdentityNotFound => {
            try stdout.print("Fehler: Identität '{s}' nicht gefunden.\n", .{name});
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

fn cmdExport(io: std.Io, stdout: *Io.Writer, args: *ArgIter) !void {
    const name = args.next() orelse return CliError.MissingArgument;
    const pub_bytes = keymng.loadPublicOnly(io, name) catch |err| switch (err) {
        keymng.KeystoreError.IdentityNotFound => {
            try stdout.print("Fehler: Identität '{s}' nicht gefunden.\n", .{name});
            try stdout.flush();
            return;
        },
        else => return err,
    };
    const base = sip.identity.baseAddress(pub_bytes);
    var addr_buf: [80]u8 = undefined;
    const addr = try formatSipAddress(&addr_buf, name, base);
    try stdout.print("{s} {x}\n", .{ addr, pub_bytes });
    try stdout.flush();
}

fn cmdRemove(io: std.Io, stdout: *Io.Writer, args: *ArgIter) !void {
    const name = args.next() orelse return CliError.MissingArgument;

    keymng.deleteIdentity(io, name) catch |err| switch (err) {
        keymng.KeystoreError.IdentityNotFound => {
            try stdout.print("Fehler: Identität '{s}' nicht gefunden.\n", .{name});
            try stdout.flush();
            return;
        },
        error.AccessDenied => {
            try stdout.writeAll("Fehler: Sudo erforderlich. Versuche: sudo sipctl rm <name>\n");
            try stdout.flush();
            return;
        },
        else => return err,
    };

    try stdout.print("[-] Identität '{s}' gelöscht\n", .{name});
    try stdout.flush();
}

fn cmdPasswd(io: std.Io, stdout: *Io.Writer, env_map: *const std.process.Environ.Map, args: *ArgIter) !void {
    const name = args.next() orelse return CliError.MissingArgument;

    try stdout.writeAll("Aktuelles ");
    try stdout.flush();
    var old_pw_buf: [256]u8 = undefined;
    const old_pw = try resolvePassword(io, stdout, env_map, .{}, &old_pw_buf, false);

    try stdout.writeAll("Neues ");
    try stdout.flush();
    var new_pw_buf: [256]u8 = undefined;
    const new_pw = try resolvePassword(io, stdout, env_map, .{}, &new_pw_buf, true);

    _ = keymng.changePassword(io, name, old_pw, new_pw) catch |err| switch (err) {
        keymng.KeystoreError.IdentityNotFound => {
            try stdout.print("Fehler: Identität '{s}' nicht gefunden.\n", .{name});
            try stdout.flush();
            return;
        },
        sip.identity.SipError.DecryptionFailed => {
            try stdout.writeAll("Fehler: Falsches Passwort.\n");
            try stdout.flush();
            return;
        },
        error.AccessDenied => {
            try stdout.writeAll("Fehler: Sudo erforderlich. Versuche: sudo sipctl passwd <name>\n");
            try stdout.flush();
            return;
        },
        else => return err,
    };

    try stdout.print("[+] Passwort für '{s}' geändert\n", .{name});
    try stdout.flush();
}

fn readFileBytes(io: std.Io, allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    var file = try std.Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);

    const stat = try file.stat(io);
    verbosePrint(config.verbose, "[sipctl] readFileBytes: \"{s}\" ist {d} Byte groß\n", .{ path, stat.size });

    const data = try allocator.alloc(u8, stat.size);
    errdefer allocator.free(data);

    _ = try file.readPositionalAll(io, data, 0);

    return data;
}

const ResolvedMessage = struct {
    bytes: []const u8,
    owned: bool,

    fn deinit(self: ResolvedMessage, allocator: std.mem.Allocator) void {
        if (self.owned) {
            allocator.free(self.bytes);
        }
    }
};

fn resolveMessage(io: std.Io, allocator: std.mem.Allocator, raw: []const u8) !ResolvedMessage {
    if (raw.len > 0 and raw[0] == '@') {
        const path = raw[1..];
        verbosePrint(config.verbose, "[sipctl] --message beginnt mit '@', lese Datei: \"{s}\"\n", .{path});
        const data = try readFileBytes(io, allocator, path);
        verbosePrint(config.verbose, "[sipctl] Datei gelesen, {d} Bytes\n", .{data.len});
        return ResolvedMessage{ .bytes = data, .owned = true };
    }
    verbosePrint(config.verbose, "[sipctl] --message wird als roher Text behandelt ({d} Byte)\n", .{raw.len});
    return ResolvedMessage{ .bytes = raw, .owned = false };
}

fn sendFramed(sock: sip.synet.Socket, data: []const u8) !void {
    verbosePrint(config.verbose, "[sipctl] sendFramed: schreibe {d} Byte (+4 Byte Längenpräfix)\n", .{data.len});

    var len_buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &len_buf, @intCast(data.len), .big);
    try sip.synet.sendAll(sock, &len_buf);
    try sip.synet.sendAll(sock, data);
    verbosePrint(config.verbose, "[sipctl] sendFramed: fertig gesendet\n", .{});
}

fn recvFramed(allocator: std.mem.Allocator, sock: sip.synet.Socket) ![]u8 {
    var len_buf: [4]u8 = undefined;
    try sip.synet.recvExact(sock, &len_buf);
    const len = std.mem.readInt(u32, &len_buf, .big);

    const MAX_FRAME_SIZE: u32 = 256 * 1024 * 1024;
    verbosePrint(config.verbose, "[sipctl] recvFramed: Längenpräfix sagt {d} Byte\n", .{len});
    if (len > MAX_FRAME_SIZE) {
        std.debug.print("[sipctl] recvFramed: ABBRUCH, {d} Byte > Maximum {d}\n", .{ len, MAX_FRAME_SIZE });
        return error.FrameTooLarge;
    }

    const buf = try allocator.alloc(u8, len);
    errdefer allocator.free(buf);
    try sip.synet.recvExact(sock, buf);
    verbosePrint(config.verbose, "[sipctl] recvFramed: {d} Byte vollständig empfangen\n", .{buf.len});
    return buf;
}

fn performKeyExchange(io: std.Io, allocator: std.mem.Allocator, sock: sip.synet.Socket, local_keys: sip.identity.KeyPair, local_address: [16]u8, is_initiator: bool, peer_address: ?[16]u8) !sip.handshake.SessionKeys {
    verbosePrint(config.verbose, "[sipctl-keyexchange] Generiere ephemeres Schlüsselpaar...\n", .{});
    var local_ephemeral = try sip.handshake.EphemeralKeyPair.generate(io);
    defer local_ephemeral.deinit();

    verbosePrint(config.verbose, "[sipctl-keyexchange] Erstelle HandshakeMessage...\n", .{});
    const local_msg = try sip.handshake.HandshakeMessage.create(local_keys, local_ephemeral);
    var peer_msg: sip.handshake.HandshakeMessage = undefined;

    if (is_initiator) {
        verbosePrint(config.verbose, "[sipctl-keyexchange] [initiator] Sende HandshakeMessage...\n", .{});
        var local_msg_buf: [sip.handshake.IDENTITY_PUBLIC_KEY_SIZE + sip.handshake.PUBLIC_KEY_SIZE + sip.handshake.SIGNATURE_SIZE]u8 = undefined;
        @memcpy(local_msg_buf[0..sip.handshake.IDENTITY_PUBLIC_KEY_SIZE], &local_msg.identity_public_key);
        @memcpy(
            local_msg_buf[sip.handshake.IDENTITY_PUBLIC_KEY_SIZE .. sip.handshake.IDENTITY_PUBLIC_KEY_SIZE + sip.handshake.PUBLIC_KEY_SIZE],
            &local_msg.ephemeral_public_key,
        );
        @memcpy(
            local_msg_buf[sip.handshake.IDENTITY_PUBLIC_KEY_SIZE + sip.handshake.PUBLIC_KEY_SIZE ..],
            &local_msg.signature,
        );
        try sendFramed(sock, &local_msg_buf);

        verbosePrint(config.verbose, "[sipctl-keyexchange] [initiator] Warte auf Peer-Message...\n", .{});
        const peer_buf = try recvFramed(allocator, sock);
        defer allocator.free(peer_buf);

        const expected_msg_len = sip.handshake.IDENTITY_PUBLIC_KEY_SIZE + sip.handshake.PUBLIC_KEY_SIZE + sip.handshake.SIGNATURE_SIZE;
        if (peer_buf.len != expected_msg_len) {
            verbosePrint(config.verbose, "[ERROR] [sipctl-keyexchange] Ungültige Message-Länge: {d} (erwartet {d})\n", .{ peer_buf.len, expected_msg_len });
            return error.InvalidPeerMessage;
        }

        @memcpy(&peer_msg.identity_public_key, peer_buf[0..sip.handshake.IDENTITY_PUBLIC_KEY_SIZE]);
        @memcpy(
            &peer_msg.ephemeral_public_key,
            peer_buf[sip.handshake.IDENTITY_PUBLIC_KEY_SIZE .. sip.handshake.IDENTITY_PUBLIC_KEY_SIZE + sip.handshake.PUBLIC_KEY_SIZE],
        );
        @memcpy(
            &peer_msg.signature,
            peer_buf[sip.handshake.IDENTITY_PUBLIC_KEY_SIZE + sip.handshake.PUBLIC_KEY_SIZE ..],
        );
    } else {
        verbosePrint(config.verbose, "[sipctl-keyexchange] [responder] Warte auf Peer-Message...\n", .{});
        const peer_buf = try recvFramed(allocator, sock);
        defer allocator.free(peer_buf);

        const expected_msg_len = sip.handshake.IDENTITY_PUBLIC_KEY_SIZE + sip.handshake.PUBLIC_KEY_SIZE + sip.handshake.SIGNATURE_SIZE;
        if (peer_buf.len != expected_msg_len) {
            std.debug.print("[sipctl-keyexchange] Ungültige Message-Länge: {d} (erwartet {d})\n", .{ peer_buf.len, expected_msg_len });
            return error.InvalidPeerMessage;
        }

        @memcpy(&peer_msg.identity_public_key, peer_buf[0..sip.handshake.IDENTITY_PUBLIC_KEY_SIZE]);
        @memcpy(
            &peer_msg.ephemeral_public_key,
            peer_buf[sip.handshake.IDENTITY_PUBLIC_KEY_SIZE .. sip.handshake.IDENTITY_PUBLIC_KEY_SIZE + sip.handshake.PUBLIC_KEY_SIZE],
        );
        @memcpy(
            &peer_msg.signature,
            peer_buf[sip.handshake.IDENTITY_PUBLIC_KEY_SIZE + sip.handshake.PUBLIC_KEY_SIZE ..],
        );

        verbosePrint(config.verbose, "[sipctl-keyexchange] [responder] Sende HandshakeMessage...\n", .{});
        var local_msg_buf: [sip.handshake.IDENTITY_PUBLIC_KEY_SIZE + sip.handshake.PUBLIC_KEY_SIZE + sip.handshake.SIGNATURE_SIZE]u8 = undefined;
        @memcpy(local_msg_buf[0..sip.handshake.IDENTITY_PUBLIC_KEY_SIZE], &local_msg.identity_public_key);
        @memcpy(
            local_msg_buf[sip.handshake.IDENTITY_PUBLIC_KEY_SIZE .. sip.handshake.IDENTITY_PUBLIC_KEY_SIZE + sip.handshake.PUBLIC_KEY_SIZE],
            &local_msg.ephemeral_public_key,
        );
        @memcpy(
            local_msg_buf[sip.handshake.IDENTITY_PUBLIC_KEY_SIZE + sip.handshake.PUBLIC_KEY_SIZE ..],
            &local_msg.signature,
        );
        try sendFramed(sock, &local_msg_buf);
    }

    verbosePrint(config.verbose, "[sipctl-keyexchange] Verifiziere Peer-Signatur...\n", .{});
    try peer_msg.verify();

    verbosePrint(config.verbose, "[sipctl-keyexchange] Peer-Identität verifiziert. Leite Session-Keys ab...\n", .{});

    const session = try sip.handshake.completeHandshake(
        local_keys,
        local_address,
        local_ephemeral,
        peer_msg,
        peer_address,
    );

    var addr_buf: [64]u8 = undefined;
    const addr_str = try formatSipAddress(&addr_buf, "sip1", session.peer_address);
    std.debug.print("[sipctl] Peer-Adresse: {s}\n", .{addr_str});
    std.debug.print("[sipctl] Connection ID generiert: {d}\n", .{session.conn_id});

    return session;
}

fn cmdSend(io: std.Io, allocator: std.mem.Allocator, stdout: *Io.Writer, env_map: *const std.process.Environ.Map, args: *ArgIter) !void {
    const identity_name = args.next() orelse {
        try stdout.writeAll("Verwendung: sipctl send <identity> <host> [--port PORT] <message>\n");
        try stdout.flush();
        return;
    };

    const host = args.next() orelse {
        try stdout.writeAll("Verwendung: sipctl send <identity> <host> [--port PORT] <message>\n");
        try stdout.flush();
        return;
    };

    var port: u16 = 9443;
    var message: ?[]const u8 = null;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--port")) {
            if (args.next()) |port_str| {
                port = std.fmt.snt(u16, port_str, 10) catch {
                    try stdout.writeAll("Fehler: Ungültiger Port\n");
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
        try stdout.writeAll("Fehler: Keine Nachricht angegeben\n");
        try stdout.flush();
        return;
    }

    var pw_buf: [256]u8 = undefined;
    const password = try resolvePassword(io, stdout, env_map, .{}, &pw_buf, false);

    const keys = keymng.loadIdentity(io, identity_name, password) catch |err| {
        try stdout.print("Fehler beim Laden der Identität: {}\n", .{err});
        try stdout.flush();
        return;
    };

    var addr_buf: [64]u8 = undefined;
    const local_addr = sip.identity.baseAddress(keys.public);
    const addr_str = try formatSipAddress(&addr_buf, identity_name, local_addr);
    verbosePrint(config.verbose, "[sipctl] Meine SIP-Adresse: {s}\n", .{addr_str});

    const resolved_host = registry.resolve(io, allocator, host) catch |err| switch (err) {
        registry.RegistryError.NotFound => {
            try stdout.print("Fehler: Host/Name '{s}' nicht gefunden.\n", .{host});
            try stdout.flush();
            return;
        },
        registry.RegistryError.Ambiguous => {
            try stdout.print("Fehler: Name '{s}' ist mehrdeutig (mehrere Treffer).\n", .{host});
            try stdout.flush();
            return;
        },
        else => return err,
    };

    verbosePrint(config.verbose, "[sipctl] aufgelöst über: {s}\n", .{@tagName(resolved_host.source)});

    const is_v6 = resolved_host.entry.kind == .ipv6;

    const sock = if (is_v6)
        try sip.synet.createTcpSocketFamily(std.posix.AF.INET6)
    else
        try sip.synet.createTcpSocket();
    defer sip.synet.close(sock);
    verbosePrint(config.verbose, "[sipctl] Socket erstellt (fd={d})\n", .{sock});

    std.debug.print("[sipctl] verbinde zu {s}:{d}...\n", .{ host, port });

    switch (resolved_host.entry.kind) {
        .ipv6 => {
            const addr6 = sip.synet.buildSockaddrIn6(resolved_host.entry.ipv6, port);
            try sip.synet.connect6(sock, &addr6);
        },
        .ipv4 => {
            const ip4 = resolved_host.entry.ipv4;
            verbosePrint(config.verbose, "[sipctl] aufgelöste IPv4-Bytes: {d}.{d}.{d}.{d}\n", .{ ip4[0], ip4[1], ip4[2], ip4[3] });
            const addr4 = sip.synet.buildSockaddrIn(ip4, port);
            try sip.synet.connect(sock, &addr4);
        },
        .mesh => {
            try stdout.writeAll("Fehler: Mesh-Adressen werden für 'send' noch nicht unterstützt.\n");
            try stdout.flush();
            return;
        },
    }
    std.debug.print("[sipctl] TCP-Verbindung hergestellt\n", .{});

    var disc_buf: [sip.header.OUTER_HEADER_SIZE]u8 = undefined;
    var src: [16]u8 = undefined;
    @memcpy(&src, &local_addr);
    const disc_pkt = try sip.header.buildDiscoveryPacket(&disc_buf, src, [_]u8{0} ** 16);

    try sip.synet.sendAll(sock, disc_pkt);
    verbosePrint(config.verbose, "[sipctl] Discovery gesendet\n", .{});

    var reply_buf: [34]u8 = undefined;
    try sip.synet.recvExact(sock, &reply_buf);

    if (reply_buf[0] != sip.header.MAGIC) return error.InvalidMagic;

    var peer_address: [16]u8 = undefined;
    @memcpy(&peer_address, reply_buf[2..18]);
    std.debug.print("[sipctl] Peer SIP-Adresse: {x}\n", .{peer_address});

    if (resolved_host.source == .registry or resolved_host.source == .registry_partial) {
        var mesh_buf: [registry.MESH_ADDR_SIZE]u8 = [_]u8{0} ** registry.MESH_ADDR_SIZE;
        @memcpy(mesh_buf[0..16], &peer_address);

        const lookup_name = if (resolved_host.source == .registry_partial)
            resolved_host.matchedName()
        else
            host;

        registry.updateMeshAddress(io, lookup_name, mesh_buf) catch |err| {
            verbosePrint(config.verbose, "[sipctl] Mesh-Adresse für '{s}' konnte nicht aktualisiert werden: {any}\n", .{ lookup_name, err });
        };
    }

    verbosePrint(config.verbose, "[sipctl] verbunden, starte Schlüsselaustausch...\n", .{});
    var session = try performKeyExchange(io, allocator, sock, keys, local_addr, true, peer_address);
    defer session.deinit();
    std.debug.print("[sipctl] Schlüsselaustausch abgeschlossen.\n", .{});

    const key = session.tx;

    const resolved = try resolveMessage(io, allocator, message.?);
    defer resolved.deinit(allocator);
    const payload = resolved.bytes;

    const mesh_src = local_addr;
    const mesh_dst = peer_address;

    verbosePrint(config.verbose, "[sipctl] Teile Payload mit sip.fragmentation auf...\n", .{});

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

    verbosePrint(config.verbose, "[sipctl] Payload in {d} Chunks aufgeteilt. Sende...\n", .{packet_list.items.len});

    for (packet_list.items, 0..) |wire_packet, idx| {
        std.debug.print("[sipctl] Sende Paket {d}/{d} (Größe: {d} Bytes)...\n", .{ idx + 1, packet_list.items.len, wire_packet.len });
        try sip.synet.sendAll(sock, wire_packet);
    }

    std.debug.print("[sipctl] Transfer abgeschlossen. Alle Pakete gesendet.\n", .{});
}

fn printHelp(stdout: *Io.Writer) !void {
    try stdout.writeAll(
        \\sipctl - SIP Identitäts- und Adressverwaltung
        \\
        \\Identitätsverwaltung:
        \\  sipctl                      Adressen kompakt auflisten (wie 'ip a')
        \\  sipctl -v, --verbose        Adressen mit Details auflisten
        \\  sipctl list                 Alias für obiges
        \\
        \\  sipctl new <name>           Neue Identität erstellen
        \\  sipctl show <name>          Details zu einer Identität anzeigen
        \\  sipctl id <name>            Neue zufällige Session-/Peer-ID generieren
        \\  sipctl export <name>        SIP-Adresse + Public Key ausgeben
        \\  sipctl passwd <name>        Passwort einer Identität ändern
        \\  sipctl rm <name>            Identität löschen
        \\
        \\Nachrichtenverwaltung:
        \\  sipctl send <identity> <host> [--port PORT] <message>
        \\                              Nachricht an Server senden
        \\                              Wenn <message> mit '@' beginnt, wird Dateiinhalt gesendet
        \\
        \\  sipctl -h, --help           Diese Hilfe anzeigen
        \\
        \\Passwort-Optionen (new/passwd/send):
        \\  --password <pw>             Passwort direkt übergeben
        \\  SIP_PASSWORD Env-Variable    Passwort über Umgebungsvariable
        \\  (sonst interaktiver, versteckter Prompt)
        \\
    );
    try stdout.flush();
}

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.gpa;

    var stdout_buf: [4096]u8 = undefined;
    var stdout_w = Io.File.stdout().writer(io, &stdout_buf);
    const stdout = &stdout_w.interface;

    const arena_alloc = init.arena.allocator();
    const argv = try init.minimal.args.toSlice(arena_alloc);

    var arg_idx: usize = 1;
    var args = ArgIter{ .argv = argv, .idx = &arg_idx };

    var cmd: ?[]const u8 = null;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            try printHelp(stdout);
            return;
        } else if (std.mem.eql(u8, arg, "-v") or std.mem.eql(u8, arg, "--verbose")) {
            config.verbose = true;
        } else {
            cmd = arg;

            if (std.mem.eql(u8, arg, "list")) {
                continue;
            }
            break;
        }
    }

    if (cmd == null or std.mem.eql(u8, cmd.?, "list")) {
        try listIdentities(io, stdout, config.verbose);
        return;
    }

    const final_cmd = cmd.?;

    if (std.mem.eql(u8, final_cmd, "new")) {
        cmdNew(io, stdout, init.environ_map, &args) catch |err| switch (err) {
            CliError.MissingArgument => try stdout.writeAll("Verwendung: sipctl new <name>\n"),
            else => return err,
        };
        try stdout.flush();
    } else if (std.mem.eql(u8, final_cmd, "show")) {
        cmdShow(io, stdout, &args) catch |err| switch (err) {
            CliError.MissingArgument => try stdout.writeAll("Verwendung: sipctl show <name>\n"),
            else => return err,
        };
        try stdout.flush();
    } else if (std.mem.eql(u8, final_cmd, "id")) {
        cmdId(io, stdout, &args) catch |err| switch (err) {
            CliError.MissingArgument => try stdout.writeAll("Verwendung: sipctl id <name>\n"),
            else => return err,
        };
        try stdout.flush();
    } else if (std.mem.eql(u8, final_cmd, "export")) {
        cmdExport(io, stdout, &args) catch |err| switch (err) {
            CliError.MissingArgument => try stdout.writeAll("Verwendung: sipctl export <name>\n"),
            else => return err,
        };
        try stdout.flush();
    } else if (std.mem.eql(u8, final_cmd, "rm") or std.mem.eql(u8, final_cmd, "remove") or std.mem.eql(u8, final_cmd, "delete")) {
        cmdRemove(io, stdout, &args) catch |err| switch (err) {
            CliError.MissingArgument => try stdout.writeAll("Verwendung: sipctl rm <name>\n"),
            else => return err,
        };
        try stdout.flush();
    } else if (std.mem.eql(u8, final_cmd, "passwd")) {
        cmdPasswd(io, stdout, init.environ_map, &args) catch |err| switch (err) {
            CliError.MissingArgument => try stdout.writeAll("Verwendung: sipctl passwd <name>\n"),
            else => return err,
        };
        try stdout.flush();
    } else if (std.mem.eql(u8, final_cmd, "send")) {
        cmdSend(io, gpa, stdout, init.environ_map, &args) catch |err| {
            std.debug.print("Fehler beim Senden: {}\n", .{err});
        };
    } else {
        try stdout.print("Unbekannter Befehl: '{s}'\n", .{final_cmd});
        try stdout.writeAll("Siehe 'sipctl --help' für Hilfe.\n");
        try stdout.flush();
    }
}
