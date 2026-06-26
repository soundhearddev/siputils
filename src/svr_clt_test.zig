const std = @import("std");
const sip = @import("sip");
const keystore = @import("keystore.zig");

const DEFAULT_PORT: u16 = 9443;

const Mode = enum { server, client };

const Args = struct {
    mode: Mode,
    host: []const u8,
    port: u16,
    message: []const u8,
    use_v6: bool,
    output_path: ?[]const u8,
    identity_name: []const u8,
    verbose: bool,
};
const lang = "en";

//zurzeit kaputt oder so glibc update

// fn getLang() []const u8 {
//     // const lang = std.c.getenv("LANG");
//     if (lang) |l| {
//         return std.mem.span(l);
//     }
//     return "en";
// }

fn verbosePrint(verbose: bool, comptime fmt: []const u8, args: anytype) void {
    if (verbose) {
        std.debug.print(fmt, args);
    }
}

fn printUsage() void {
    if (std.mem.startsWith(u8, lang, "de")) {
        std.debug.print(
            \\Verwendung:
            \\  server_cli --listen [--port PORT] --identity NAME
            \\  server_cli --connect [--host HOST] [--port PORT] --message TEXT --identity NAME
            \\
            \\Optionen:
            \\  --listen          Server-Modus: wartet auf eine eingehende Verbindung
            \\  --connect         Client-Modus: verbindet sich zu einem Server
            \\  --identity NAME   SIP-Identitätsname (wird bei Bedarf erstellt)
            \\  --host HOST       Ziel-Host im Client-Modus (Standard: 127.0.0.1)
            \\  --port PORT       Port (Standard: {d})
            \\  --message TEXT    SIP-Payload (roher Text); mit @PFAD wird stattdessen
            \\                    der Inhalt der Datei unter PFAD als Payload gesendet        
            \\  --v6              Server: auf IPv6 (::) statt IPv4 (0.0.0.0) lauschen
            \\  --output PATH     Server: empfangenen Payload zusätzlich in Datei PATH schreiben
            \\  --help            Diese Hilfe anzeigen
        , .{DEFAULT_PORT});
    } else {
        std.debug.print(
            \\Usage:
            \\  server_cli --listen [--port PORT] --identity NAME
            \\  server_cli --connect [--host HOST] [--port PORT] --message TEXT --identity NAME
            \\
            \\Options:
            \\  --listen          Server mode: waits for an incoming connection
            \\  --connect         Client mode: connects to a server
            \\  --identity NAME   SIP identity name (will be created if needed)
            \\  --host HOST       Target host in client mode (default: 127.0.0.1)
            \\  --port PORT       Port (default: {d})
            \\  --message TEXT    SIP payload (raw text); if prefixed with @PATH, the
            \\                    content of the file at PATH is sent instead
            \\  --v6              Server: listen on IPv6 (::) instead of IPv4 (0.0.0.0)
            \\  --output PATH    Server: additionally write received payload to file PATH
            \\  --help           Show this help message
            \\  --verbose         Show more information
        , .{DEFAULT_PORT});
    }
}

fn parseArgs(allocator: std.mem.Allocator, raw_args: []const []const u8) !Args {
    var mode: ?Mode = null;
    var host: []const u8 = "127.0.0.1";
    var port: u16 = DEFAULT_PORT;
    var message: []const u8 = "";
    var use_v6: bool = false;
    var output_path: ?[]const u8 = null;
    var identity_name: ?[]const u8 = null;
    var verbose: bool = false;

    var i: usize = 1;
    while (i < raw_args.len) {
        const arg = raw_args[i];

        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            printUsage();
            std.process.exit(0);
        } else if (std.mem.eql(u8, arg, "--listen")) {
            mode = .server;
            i += 1;
        } else if (std.mem.eql(u8, arg, "--connect")) {
            mode = .client;
            i += 1;
        } else if (std.mem.eql(u8, arg, "--identity")) {
            if (i + 1 >= raw_args.len) return error.MissingArgumentValue;
            identity_name = raw_args[i + 1];
            i += 2;
        } else if (std.mem.eql(u8, arg, "--host")) {
            if (i + 1 >= raw_args.len) return error.MissingArgumentValue;
            host = raw_args[i + 1];
            i += 2;
        } else if (std.mem.eql(u8, arg, "--port")) {
            if (i + 1 >= raw_args.len) return error.MissingArgumentValue;
            port = std.fmt.parseInt(u16, raw_args[i + 1], 10) catch return error.InvalidPort;
            i += 2;
        } else if (std.mem.eql(u8, arg, "--message")) {
            if (i + 1 >= raw_args.len) return error.MissingArgumentValue;
            message = raw_args[i + 1];
            i += 2;
        } else if (std.mem.eql(u8, arg, "--v6")) {
            use_v6 = true;
            i += 1;
        } else if (std.mem.eql(u8, arg, "--output")) {
            if (i + 1 >= raw_args.len) return error.MissingArgumentValue;
            output_path = raw_args[i + 1];
            i += 2;
        } else if (std.mem.eql(u8, arg, "--verbose")) {
            verbose = true;
            i += 1;
        } else {
            std.debug.print("Unbekanntes Argument: {s}\n", .{arg});
            return error.UnknownArgument;
        }
    }

    const resolved_mode = mode orelse return error.MissingMode;
    if (resolved_mode == .client and message.len == 0) {
        return error.MissingMessage;
    }
    const resolved_identity = identity_name orelse return error.MissingIdentity;

    _ = allocator;

    return Args{
        .mode = resolved_mode,
        .host = host,
        .port = port,
        .message = message,
        .use_v6 = use_v6,
        .output_path = output_path,
        .identity_name = resolved_identity,
        .verbose = verbose,
    };
}

fn parseIpv4(text: []const u8) ![4]u8 {
    var result: [4]u8 = undefined;
    var it = std.mem.splitScalar(u8, text, '.');
    var idx: usize = 0;
    while (it.next()) |part| {
        if (idx >= 4) return error.InvalidIpv4Address;
        result[idx] = std.fmt.parseInt(u8, part, 10) catch return error.InvalidIpv4Address;
        idx += 1;
    }
    if (idx != 4) return error.InvalidIpv4Address;
    return result;
}

fn parseIpv6(text: []const u8) ![16]u8 {
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

    std.debug.print("[debug] IPv6 geparst: {x}\n", .{result});
    return result;
}

fn looksLikeIpv6(text: []const u8) bool {
    return std.mem.indexOfScalar(u8, text, ':') != null;
}

fn readFileBytes(io: std.Io, allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    var file = try std.Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);

    const stat = try file.stat(io);
    std.debug.print("[debug] readFileBytes: \"{s}\" ist {d} Byte gross\n", .{ path, stat.size });

    std.debug.print("[debug] allocating data\n", .{});
    const data = try allocator.alloc(u8, stat.size);
    errdefer allocator.free(data);
    std.debug.print("[debug] data allocated\n", .{});

    std.debug.print("[debug] reading file position\n", .{});

    _ = try file.readPositionalAll(io, data, 0);

    std.debug.print("[debug] returning data\n", .{});

    return data;
}

fn writeFileBytes(io: std.Io, path: []const u8, data: []const u8) !void {
    var file = try std.Io.Dir.cwd().createFile(io, path, .{});
    defer file.close(io);

    var buf: [4096]u8 = undefined;
    var w = file.writer(io, &buf);
    try w.interface.writeAll(data);
    try w.flush();
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
        std.debug.print("[client] --message beginnt mit '@', lese Datei: \"{s}\"\n", .{path});
        const data = try readFileBytes(io, allocator, path);
        std.debug.print("[debug] returning resolved Message\n", .{});
        return ResolvedMessage{ .bytes = data, .owned = true };
    }
    std.debug.print("[client] --message wird als roher Text behandelt ({d} Byte)\n", .{raw.len});
    return ResolvedMessage{ .bytes = raw, .owned = false };
}

fn sendFramed(sock: sip.synet.Socket, data: []const u8, verbose: bool) !void {
    verbosePrint(verbose, "[debug] sendFramed: schreibe {d} Byte (+4 Byte Längenpräfix)\n", .{data.len});

    var len_buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &len_buf, @intCast(data.len), .big);
    try sip.synet.sendAll(sock, &len_buf);
    try sip.synet.sendAll(sock, data);
    std.debug.print("[debug] sendFramed: fertig gesendet\n", .{});
}

fn recvFramed(allocator: std.mem.Allocator, sock: sip.synet.Socket) ![]u8 {
    var len_buf: [4]u8 = undefined;
    try sip.synet.recvExact(sock, &len_buf);
    const len = std.mem.readInt(u32, &len_buf, .big);

    const MAX_FRAME_SIZE: u32 = 256 * 1024 * 1024;
    std.debug.print("[debug] recvFramed: Längenpräfix sagt {d} Byte\n", .{len});
    if (len > MAX_FRAME_SIZE) {
        std.debug.print("[debug] recvFramed: ABBRUCH, {d} Byte > Maximum {d}\n", .{ len, MAX_FRAME_SIZE });
        return error.FrameTooLarge;
    }

    const buf = try allocator.alloc(u8, len);
    errdefer allocator.free(buf);
    try sip.synet.recvExact(sock, buf);
    std.debug.print("[debug] recvFramed: {d} Byte vollständig empfangen\n", .{buf.len});
    return buf;
}

fn promptPassword(allocator: std.mem.Allocator, prompt_text: []const u8) ![]u8 {
    std.debug.print("{s}: ", .{prompt_text});
    const stdin_fd = std.posix.STDIN_FILENO;
    var buf: [1024]u8 = undefined;
    const n = std.posix.read(stdin_fd, &buf) catch |err| {
        std.debug.print("Error reading password: {}\n", .{err});
        return error.ReadPasswordFailed;
    };

    var len = n;
    if (len > 0 and buf[len - 1] == '\n') {
        len -= 1;
    }

    const password = try allocator.alloc(u8, len);
    @memcpy(password, buf[0..len]);
    return password;
}

fn loadOrCreateIdentity(
    io: std.Io,
    allocator: std.mem.Allocator,
    identity_name: []const u8,
) !sip.identity.KeyPair {
    if (keystore.identityExists(io, identity_name)) {
        std.debug.print("[sip] Identität '{s}' existiert, laden...\n", .{identity_name});
        const password = try promptPassword(allocator, "[sip] Passwort");
        defer allocator.free(password);

        return keystore.loadIdentity(io, identity_name, password) catch |err| {
            std.debug.print("[sip] Fehler beim Laden der Identität: {}\n", .{err});
            return err;
        };
    } else {
        std.debug.print("[sip] Identität '{s}' existiert nicht, erstelle neue...\n", .{identity_name});

        if (!keystore.validName(identity_name)) {
            std.debug.print("[sip] Ungültiger Identitätsname (erlaubt: alphanumerisch, -, _, .)\n", .{});
            return error.InvalidIdentityName;
        }

        const password = try promptPassword(allocator, "[sip] Wähle ein Passwort");
        defer allocator.free(password);

        const password_confirm = try promptPassword(allocator, "[sip] Passwort bestätigen");
        defer allocator.free(password_confirm);

        if (!std.mem.eql(u8, password, password_confirm)) {
            std.debug.print("[sip] Passwörter stimmen nicht überein!\n", .{});
            return error.PasswordMismatch;
        }

        // NEU
        return keystore.createIdentity(io, identity_name, password) catch |err| {
            std.debug.print("[sip] Fehler beim Erstellen der Identität: {}\n", .{err});
            return err;
        };
    }
}

fn performKeyExchange(io: std.Io, allocator: std.mem.Allocator, sock: sip.synet.Socket, local_keys: sip.identity.KeyPair, local_address: [16]u8, is_initiator: bool, peer_address: ?[16]u8, verbose: bool) !sip.handshake.SessionKeys {
    verbosePrint(verbose, "[keyexchange] Generiere ephemeres Schlüsselpaar...\n", .{});
    var local_ephemeral = try sip.handshake.EphemeralKeyPair.generate(io);
    defer local_ephemeral.deinit();

    verbosePrint(verbose, "[keyexchange] Erstelle HandshakeMessage...\n", .{});
    const local_msg = try sip.handshake.HandshakeMessage.create(local_keys, local_ephemeral);
    var peer_msg: sip.handshake.HandshakeMessage = undefined;

    if (is_initiator) {
        std.debug.print("[keyexchange] [initiator] Sende HandshakeMessage...\n", .{});
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
        try sendFramed(sock, &local_msg_buf, verbose);

        verbosePrint(verbose, "[keyexchange] [initiator] Warte auf Peer-Message...\n", .{});
        const peer_buf = try recvFramed(allocator, sock);
        defer allocator.free(peer_buf);

        const expected_msg_len = sip.handshake.IDENTITY_PUBLIC_KEY_SIZE + sip.handshake.PUBLIC_KEY_SIZE + sip.handshake.SIGNATURE_SIZE;
        if (peer_buf.len != expected_msg_len) {
            std.debug.print("[ERROR] [keyexchange] Ungültige Message-Länge: {d} (erwartet {d})\n", .{ peer_buf.len, expected_msg_len });
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
        std.debug.print("[keyexchange] [responder] Warte auf Peer-Message...\n", .{});
        const peer_buf = try recvFramed(allocator, sock);
        defer allocator.free(peer_buf);

        const expected_msg_len = sip.handshake.IDENTITY_PUBLIC_KEY_SIZE + sip.handshake.PUBLIC_KEY_SIZE + sip.handshake.SIGNATURE_SIZE;
        if (peer_buf.len != expected_msg_len) {
            std.debug.print("[keyexchange] Ungültige Message-Länge: {d} (erwartet {d})\n", .{ peer_buf.len, expected_msg_len });
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

        std.debug.print("[keyexchange] [responder] Sende HandshakeMessage...\n", .{});
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
        try sendFramed(sock, &local_msg_buf, verbose);
    }

    verbosePrint(verbose, "[keyexchange] Verifiziere Peer-Signatur...\n", .{});
    try peer_msg.verify();

    verbosePrint(verbose, "[keyexchange] Peer-Identität verifiziert. Leite Session-Keys ab...\n", .{});

    const session = try sip.handshake.completeHandshake(
        local_keys,
        local_address,
        local_ephemeral,
        peer_msg,
        peer_address,
    );

    var addr_buf: [64]u8 = undefined;
    const addr_str = try sip.identity.formatSipAddress(&addr_buf, session.peer_address);
    std.debug.print("[keyexchange] Peer-Adresse: {s}\n", .{addr_str});
    std.debug.print("[keyexchange] Connection ID generiert: {d}\n", .{session.conn_id});

    return session;
}

fn runServer(
    io: std.Io,
    allocator: std.mem.Allocator,
    port: u16,
    use_v6: bool,
    output_path: ?[]const u8,
    verbose: bool,
    keys: sip.identity.KeyPair,
) !void {
    var addr_buf: [64]u8 = undefined;
    const addr = sip.identity.baseAddress(keys.public);
    const addr_str = try sip.identity.formatSipAddress(&addr_buf, addr);

    verbosePrint(verbose, "[server] Meine SIP-Adresse: {s}\n", .{addr_str});

    verbosePrint(verbose, "[server] Modus: {s}\n", .{if (use_v6) "IPv6 (::)" else "IPv4 (0.0.0.0)"});

    const listener = if (use_v6)
        try sip.synet.createTcpSocketFamily(std.posix.AF.INET6)
    else
        try sip.synet.createTcpSocket();
    defer sip.synet.close(listener);
    verbosePrint(verbose, "[server] Socket erstellt (fd={d})\n", .{listener});

    if (use_v6) {
        const bind_addr = sip.synet.buildSockaddrIn6([_]u8{0} ** 16, port);
        try sip.synet.bind6(listener, &bind_addr);
    } else {
        const bind_addr = sip.synet.buildSockaddrIn(.{ 0, 0, 0, 0 }, port);
        try sip.synet.bind(listener, &bind_addr);
    }
    verbosePrint(verbose, "[server] gebunden an Port {d}\n", .{port});
    try sip.synet.listen(listener, 1);
    verbosePrint(verbose, "[server] lauscht (backlog=1)\n", .{});

    std.debug.print("[server] warte auf Verbindung auf Port {d}...\n", .{port});

    const conn = try sip.synet.accept(listener);
    defer sip.synet.close(conn);

    std.debug.print("[server] Verbindung angenommen, starte Schlüsselaustausch...\n", .{});

    var disc_buf: [34]u8 = undefined;
    try sip.synet.recvExact(conn, &disc_buf);

    if (disc_buf[0] != sip.header.MAGIC) return error.InvalidMagic;
    if (disc_buf[1] != @intFromEnum(sip.protocol.Command.discovery)) return error.InvalidDiscovery;

    var disc_src: [16]u8 = undefined;
    @memcpy(&disc_src, disc_buf[2..18]);
    std.debug.print("[server] Discovery von meshsrc: {x}\n", .{disc_src});

    var reply_buf: [34]u8 = undefined;
    var srv_src: [16]u8 = undefined;
    @memcpy(&srv_src, &addr);

    const reply = try sip.header.buildDiscoveryPacket(&reply_buf, srv_src, disc_src);
    try sip.synet.sendAll(conn, reply);
    std.debug.print("[server] Discovery-Reply gesendet\n", .{});

    var session = try performKeyExchange(io, allocator, conn, keys, addr, false, null, verbose);
    defer session.deinit();
    const key = session.rx;
    std.debug.print("[server] Schlüsselaustausch abgeschlossen.\n", .{});

    var reassembler = sip.translation.Reassembler.init(io, allocator, "/tmp/sip");
    defer reassembler.deinit();

    const chunk_paths: [][]u8 = blk: {
        while (true) {
            const pkt = sip.translation.readInboundPacket(conn, allocator, key) catch |err| {
                if (err == error.ConnectionClosed or err == error.SocketError) {
                    std.debug.print("[server] Verbindung geschlossen (keine Chunks mehr).\n", .{});
                    return error.Aborted;
                }
                std.debug.print("[ERROR] [server] Lesen fehlgeschlagen: {}\n", .{err});
                return err;
            };
            defer sip.translation.freeInboundPacket(allocator, pkt);

            switch (try reassembler.feed(pkt.parsed)) {
                .pending => continue,
                .complete => |paths| break :blk paths,
            }
        }
    };
    defer {
        for (chunk_paths) |p| allocator.free(p);
        allocator.free(chunk_paths);
    }

    verbosePrint(verbose, "[server] Transfer komplett, {d} Chunks empfangen.\n", .{chunk_paths.len});

    // TODO: OUTPUT handling verbessern und eifnach FIXEN!!!!
    if (output_path) |path| {
        var out = try std.Io.Dir.cwd().createFile(io, path, .{});
        defer out.close(io);
        var out_buf: [4096]u8 = undefined;
        var w = out.writer(io, &out_buf);

        for (chunk_paths) |chunk_path| {
            var cf = try std.Io.Dir.cwd().openFile(io, chunk_path, .{});
            defer cf.close(io);

            while (true) {
                var stream_buf: [8192]u8 = undefined;

                const n = try std.posix.read(cf.handle, &stream_buf);
                if (n == 0) break;

                try w.interface.writeAll(stream_buf[0..n]);
            }

            try std.Io.Dir.cwd().deleteFile(io, chunk_path);
        }
        try w.flush();
        std.debug.print("[server] Payload erfolgreich gespeichert unter: \"{s}\"\n", .{path});
    } else {
        var stdout_buf: [4096]u8 = undefined;
        var stdout_writer = std.Io.File.stdout().writer(io, &stdout_buf);

        for (chunk_paths) |chunk_path| {
            var cf = try std.Io.Dir.cwd().openFile(io, chunk_path, .{});
            defer cf.close(io);

            while (true) {
                var stream_buf: [8192]u8 = undefined;
                const n = try std.posix.read(cf.handle, &stream_buf);
                if (n == 0) break;

                try stdout_writer.interface.writeAll(stream_buf[0..n]);
            }

            try std.Io.Dir.cwd().deleteFile(io, chunk_path);
        }
        try stdout_writer.flush();
    }
}

fn runClient(io: std.Io, allocator: std.mem.Allocator, host: []const u8, port: u16, message: []const u8, identity_name: []const u8, verbose: bool) !void {
    const keys = try loadOrCreateIdentity(io, allocator, identity_name);
    var addr_buf: [64]u8 = undefined;
    const local_addr = sip.identity.baseAddress(keys.public);
    const addr_str = try sip.identity.formatSipAddress(&addr_buf, local_addr);
    verbosePrint(verbose, "[client] Meine SIP-Adresse: {s}\n", .{addr_str});

    const is_v6 = looksLikeIpv6(host);
    verbosePrint(verbose, "[client] erkannte Adressfamilie: {s}\n", .{if (is_v6) "IPv6" else "IPv4"});

    const sock = if (is_v6)
        try sip.synet.createTcpSocketFamily(std.posix.AF.INET6)
    else
        try sip.synet.createTcpSocket();
    defer sip.synet.close(sock);
    verbosePrint(verbose, "[client] Socket erstellt (fd={d})\n", .{sock});

    verbosePrint(verbose, "[client] verbinde zu {s}:{d}...\n", .{ host, port });

    if (is_v6) {
        const ip6 = try parseIpv6(host);
        const addr6 = sip.synet.buildSockaddrIn6(ip6, port);
        try sip.synet.connect6(sock, &addr6);
    } else {
        const ip4 = try parseIpv4(host);
        verbosePrint(verbose, "[client] geparste IPv4-Bytes: {d}.{d}.{d}.{d}\n", .{ ip4[0], ip4[1], ip4[2], ip4[3] });
        const addr4 = sip.synet.buildSockaddrIn(ip4, port);
        try sip.synet.connect(sock, &addr4);
    }
    std.debug.print("[client] TCP-Verbindung hergestellt\n", .{});

    var disc_buf: [sip.header.OUTER_HEADER_SIZE]u8 = undefined;
    var src: [16]u8 = undefined;
    @memcpy(&src, &local_addr);
    const disc_pkt = try sip.header.buildDiscoveryPacket(&disc_buf, src, [_]u8{0} ** 16);

    try sip.synet.sendAll(sock, disc_pkt);
    std.debug.print("[client] Discovery gesendet\n", .{});

    var reply_buf: [34]u8 = undefined;
    try sip.synet.recvExact(sock, &reply_buf);

    if (reply_buf[0] != sip.header.MAGIC) return error.InvalidMagic;

    var peer_address: [16]u8 = undefined;
    @memcpy(&peer_address, reply_buf[2..18]);
    verbosePrint(verbose, "[client] Peer SIP-Adresse: {x}\n", .{peer_address});

    verbosePrint(verbose, "[client] verbunden, starte Schlüsselaustausch...\n", .{});
    var session = try performKeyExchange(io, allocator, sock, keys, local_addr, true, peer_address, verbose);
    defer session.deinit();
    std.debug.print("[client] Schlüsselaustausch abgeschlossen.\n", .{});

    const key = session.tx;

    const resolved = try resolveMessage(io, allocator, message);
    verbosePrint(verbose, "[debug] resolving allocated \n", .{});
    defer resolved.deinit(allocator);
    const payload = resolved.bytes;
    verbosePrint(verbose, "[debug] allocated resolved \n", .{});

    const mesh_src = local_addr;
    const mesh_dst = peer_address;

    verbosePrint(verbose, "[client] Teile Payload mit sip.fragmentation auf...\n", .{});

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

    verbosePrint(verbose, "[client] Payload in {d} Chunks aufgeteilt. Sende...\n", .{packet_list.items.len});

    for (packet_list.items, 0..) |wire_packet, idx| {
        verbosePrint(verbose, "[client] Sende Paket {d}/{d} (Größe: {d} Bytes)...\n", .{ idx + 1, packet_list.items.len, wire_packet.len });

        try sip.synet.sendAll(sock, wire_packet);
    }

    std.debug.print("[client] Transfer abgeschlossen. Alle Pakete gesendet.\n", .{});
}
pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.gpa;

    const raw_args = try init.minimal.args.toSlice(init.arena.allocator());

    const args = parseArgs(gpa, raw_args) catch |err| {
        std.debug.print("Argument-Fehler: {}\n\n", .{err});
        printUsage();
        std.process.exit(1);
    };

    switch (args.mode) {
        .server => {
            const keys = try loadOrCreateIdentity(io, gpa, args.identity_name);
            try runServer(io, gpa, args.port, args.use_v6, args.output_path, args.verbose, keys);
        },
        .client => try runClient(io, gpa, args.host, args.port, args.message, args.identity_name, args.verbose),
    }
}
