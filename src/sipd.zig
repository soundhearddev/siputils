const std = @import("std");
const sip = @import("sip");
const keymng = @import("keymng.zig");
const fs = @import("filesystem.zig");
// ---------------------------------------------------------------------------
// Konstanten
// ---------------------------------------------------------------------------

const CONFIG_PATH: []const u8 = fs.get_config_path();
const DEFAULT_PORT: u16 = 9443;
const DEFAULT_PIDFILE: []const u8 = "/run/sipd.pid";
const DEFAULT_RUNTIME_DIR: []const u8 = "/run/sipd";
const MAX_FRAME_SIZE: u32 = 256 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Konfiguration
// ---------------------------------------------------------------------------
fn verbosePrint(verbose: bool, comptime fmt: []const u8, args: anytype) void {
    if (verbose) {
        std.debug.print(fmt, args);
    }
}

const DaemonConfig = struct {
    identity_name: []const u8,
    host: ?[]const u8 = null,
    port: u16 = DEFAULT_PORT,
    use_v6: bool = false,
    output_path: ?[]const u8 = null,
    verbose: bool = false,
    pidfile: []const u8 = DEFAULT_PIDFILE,
    runtime_dir: []const u8 = DEFAULT_RUNTIME_DIR,
};

// ---------------------------------------------------------------------------
//   # Kommentar
//   identity_name = identity
//   host          = 0.0.0.0
//   port          = 9443
//   use_v6        = false
//   output_path   = /var/spool/sip/payload
//   verbose       = true
//   pidfile       = /run/sipd.pid
//   runtime_dir   = /run/sipd
// ---------------------------------------------------------------------------

pub fn formatSipAddress(buf: []u8, name: []const u8, base: [16]u8) ![]const u8 {
    return std.fmt.bufPrint(buf, "{s}{x}", .{ name, base });
}

fn loadConfig(io: std.Io, allocator: std.mem.Allocator, path: []const u8) !DaemonConfig {
    const cwd = std.Io.Dir.cwd();
    const raw = cwd.readFileAlloc(io, path, allocator, .unlimited) catch |err| {
        std.debug.print("[sipd] Fehler: Kann Konfiguration nicht öffnen: {s} ({any})\n", .{ path, err });
        return err;
    };
    defer allocator.free(raw);

    var identity_name: ?[]u8 = null;
    var host: ?[]u8 = null;
    var port: u16 = DEFAULT_PORT;
    var use_v6: bool = false;
    var output_path: ?[]u8 = null;
    var verbose: bool = false;
    var pidfile: []u8 = try allocator.dupe(u8, DEFAULT_PIDFILE);
    var runtime_dir: []u8 = try allocator.dupe(u8, DEFAULT_RUNTIME_DIR);

    var lines = std.mem.splitScalar(u8, raw, '\n');
    var line_nr: usize = 0;

    errdefer {
        if (identity_name) |n| allocator.free(n);
        if (host) |h| allocator.free(h);
        if (output_path) |o| allocator.free(o);
        allocator.free(pidfile);
        allocator.free(runtime_dir);
    }

    while (lines.next()) |line_raw| {
        line_nr += 1;
        const line = std.mem.trim(u8, line_raw, " \t\r");

        if (line.len == 0 or line[0] == '#') continue;

        const eq = std.mem.indexOfScalar(u8, line, '=') orelse {
            std.debug.print("[sipd] Warnung: Zeile {d} ignoriert (kein '='): {s}\n", .{ line_nr, line });
            continue;
        };

        const key = std.mem.trim(u8, line[0..eq], " \t");
        const val = std.mem.trim(u8, line[eq + 1 ..], " \t");

        if (std.mem.eql(u8, key, "identity_name")) {
            if (identity_name) |old| allocator.free(old);
            identity_name = try allocator.dupe(u8, val);
        } else if (std.mem.eql(u8, key, "host")) {
            if (host) |old| allocator.free(old);
            host = try allocator.dupe(u8, val);
        } else if (std.mem.eql(u8, key, "port")) {
            port = std.fmt.parseInt(u16, val, 10) catch {
                std.debug.print("[sipd] Fehler: Ungültiger Port in Zeile {d}: {s}\n", .{ line_nr, val });
                return error.InvalidPort;
            };
        } else if (std.mem.eql(u8, key, "use_v6")) {
            use_v6 = parseBool(val) catch {
                std.debug.print("[sipd] Fehler: Ungültiger Bool in Zeile {d}: {s}\n", .{ line_nr, val });
                return error.InvalidBool;
            };
        } else if (std.mem.eql(u8, key, "output_path")) {
            if (output_path) |old| allocator.free(old);
            output_path = try allocator.dupe(u8, val);
        } else if (std.mem.eql(u8, key, "verbose")) {
            verbose = parseBool(val) catch {
                std.debug.print("[sipd] Fehler: Ungültiger Bool in Zeile {d}: {s}\n", .{ line_nr, val });
                return error.InvalidBool;
            };
        } else if (std.mem.eql(u8, key, "pidfile")) {
            allocator.free(pidfile);
            pidfile = try allocator.dupe(u8, val);
        } else if (std.mem.eql(u8, key, "runtime_dir")) {
            allocator.free(runtime_dir);
            runtime_dir = try allocator.dupe(u8, val);
        } else {
            std.debug.print("[sipd] Warnung: Unbekannter Schlüssel in Zeile {d}: {s}\n", .{ line_nr, key });
        }
    }

    const resolved_identity = identity_name orelse {
        std.debug.print("[sipd] Fehler: 'identity_name' fehlt in {s}\n", .{path});
        return error.MissingIdentity;
    };

    return DaemonConfig{
        .identity_name = resolved_identity,
        .host = host,
        .port = port,
        .use_v6 = use_v6,
        .output_path = output_path,
        .verbose = verbose,
        .pidfile = pidfile,
        .runtime_dir = runtime_dir,
    };
}

fn parseBool(s: []const u8) !bool {
    if (std.mem.eql(u8, s, "true") or std.mem.eql(u8, s, "1") or std.mem.eql(u8, s, "yes")) return true;
    if (std.mem.eql(u8, s, "false") or std.mem.eql(u8, s, "0") or std.mem.eql(u8, s, "no")) return false;
    return error.InvalidBool;
}

var should_shutdown: std.atomic.Value(bool) = std.atomic.Value(bool).init(false);
var current_connection: ?sip.synet.Socket = null;
var connection_mutex: std.Io.Mutex = .init;

fn signalHandler(sig: std.os.linux.SIG) callconv(.c) void {
    switch (sig) {
        .TERM, .INT => {
            std.debug.print("\n[sipd] Signal empfangen, fahre herunter...\n", .{});
            should_shutdown.store(true, .release);
        },
        .HUP => {
            std.debug.print("[sipd] SIGHUP empfangen\n", .{});
        },
        else => {},
    }
}

fn setupSignalHandlers() !void {
    const linux = std.os.linux;
    var sa = linux.Sigaction{
        .handler = .{ .handler = signalHandler },
        .mask = linux.sigemptyset(),
        .flags = 0,
    };
    _ = linux.sigaction(.TERM, &sa, null);
    _ = linux.sigaction(.INT, &sa, null);
    _ = linux.sigaction(.HUP, &sa, null);

    var sa_pipe = linux.Sigaction{
        .handler = .{ .handler = linux.SIG.IGN },
        .mask = linux.sigemptyset(),
        .flags = 0,
    };
    _ = linux.sigaction(.PIPE, &sa_pipe, null);
}

fn writePidFile(io: std.Io, pidfile: []const u8) !void {
    const pid = std.os.linux.getpid();
    var buf: [32]u8 = undefined;
    const pid_str = try std.fmt.bufPrint(&buf, "{d}", .{pid});

    try fs.writeNewFile(io, pidfile, 0o644, pid_str);

    std.debug.print("[sipd] PID {d} → {s}\n", .{ pid, pidfile });
}

fn removePidFile(io: std.Io, pidfile: []const u8) void {
    const cwd = std.Io.Dir.cwd();
    cwd.deleteFile(io, pidfile) catch |err| {
        std.debug.print("[sipd] Warnung: PID-Datei konnte nicht gelöscht werden: {any}\n", .{err});
    };
}

fn ensureRuntimeDir(io: std.Io, runtime_dir: []const u8) !void {
    fs.createDirPath(io, runtime_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
    std.debug.print("[sipd] Runtime-Verzeichnis: {s}\n", .{runtime_dir});
}

fn promptPassword(allocator: std.mem.Allocator, prompt_text: []const u8) ![]u8 {
    std.debug.print("{s}: ", .{prompt_text});

    const fd = std.posix.STDIN_FILENO;

    const original_termios = try std.posix.tcgetattr(fd);

    var no_echo_termios = original_termios;
    no_echo_termios.lflag.ECHO = false;
    no_echo_termios.lflag.ECHONL = false;

    try std.posix.tcsetattr(fd, .NOW, no_echo_termios);

    defer {
        std.posix.tcsetattr(fd, .NOW, original_termios) catch {};
        std.debug.print("\n", .{});
    }

    var buf: [1024]u8 = undefined;
    const n = try std.posix.read(fd, &buf);

    var len = n;
    if (len > 0 and buf[len - 1] == '\n') len -= 1;
    if (len > 0 and buf[len - 1] == '\r') len -= 1;

    const password = try allocator.alloc(u8, len);
    @memcpy(password, buf[0..len]);
    return password;
}

fn loadOrCreateIdentity(
    init: std.process.Init,
    allocator: std.mem.Allocator,
    identity_name: []const u8,
) !sip.identity.KeyPair {
    const io = init.io;

    if (keymng.identityExists(io, identity_name)) {
        std.debug.print("[sipd] '{s}' gefunden\n", .{identity_name});

        var env_map = try init.minimal.environ.createMap(allocator);
        defer env_map.deinit();

        const password = if (env_map.get("SIPD_PASSWORD")) |env_val| blk: {
            break :blk try allocator.dupe(u8, env_val);
        } else blk: {
            break :blk try promptPassword(allocator, "[sipd] Passwort");
        };
        defer allocator.free(password);

        return keymng.loadIdentity(io, identity_name, password);
    } else {
        std.debug.print("[sipd] '{s}' nicht gefunden\n", .{identity_name});

        if (!keymng.validName(identity_name)) {
            std.debug.print("[sipd] Ungültiger Identitätsname\n", .{});
            return error.InvalidIdentityName;
        }

        const password = try promptPassword(allocator, "[sipd] Neues Passwort");
        defer allocator.free(password);

        const password_confirm = try promptPassword(allocator, "[sipd] Passwort bestätigen");
        defer allocator.free(password_confirm);

        if (!std.mem.eql(u8, password, password_confirm)) {
            std.debug.print("[sipd] Passwörter stimmen nicht überein\n", .{});
            return error.PasswordMismatch;
        }

        return keymng.createIdentity(io, identity_name, password) catch |err| {
            std.debug.print("[sipd] Fehler beim Erstellen der Identität: {any}\n", .{err});
            return err;
        };
    }
}

// ---------------------------------------------------------------------------
// Framed I/O
// ---------------------------------------------------------------------------

fn sendFramed(sock: sip.synet.Socket, data: []const u8, verbose: bool) !void {
    verbosePrint(verbose, "[sipd] sendFramed: {d} Byte\n", .{data.len});

    var len_buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &len_buf, @intCast(data.len), .big);
    try sip.synet.sendAll(sock, &len_buf);
    try sip.synet.sendAll(sock, data);
}

fn recvFramed(allocator: std.mem.Allocator, sock: sip.synet.Socket, verbose: bool) ![]u8 {
    var len_buf: [4]u8 = undefined;
    try sip.synet.recvExact(sock, &len_buf);
    const len = std.mem.readInt(u32, &len_buf, .big);

    verbosePrint(verbose, "[sipd] recvFramed: {d} Byte angekündigt\n", .{len});

    if (len > MAX_FRAME_SIZE) {
        std.debug.print("[sipd] Frame zu groß: {d}\n", .{len});
        return error.FrameTooLarge;
    }

    const buf = try allocator.alloc(u8, len);
    errdefer allocator.free(buf);
    try sip.synet.recvExact(sock, buf);
    return buf;
}

// ---------------------------------------------------------------------------
// Schlüsselaustausch
// ---------------------------------------------------------------------------

fn performKeyExchange(
    io: std.Io,
    allocator: std.mem.Allocator,
    sock: sip.synet.Socket,
    local_keys: sip.identity.KeyPair,
    local_address: [16]u8,
    is_initiator: bool,
    peer_address: ?[16]u8,
    verbose: bool,
) !sip.handshake.SessionKeys {
    verbosePrint(verbose, "[sipd-kex] Generiere ephemeres Schlüsselpaar...\n", .{});

    var local_ephemeral = try sip.handshake.EphemeralKeyPair.generate(io);
    defer local_ephemeral.deinit();

    const local_msg = try sip.handshake.HandshakeMessage.create(local_keys, local_ephemeral);
    var peer_msg: sip.handshake.HandshakeMessage = undefined;

    const MSG_LEN = sip.handshake.IDENTITY_PUBLIC_KEY_SIZE +
        sip.handshake.PUBLIC_KEY_SIZE +
        sip.handshake.SIGNATURE_SIZE;

    const serializeMsg = struct {
        fn run(msg: sip.handshake.HandshakeMessage, out: *[MSG_LEN]u8) void {
            @memcpy(out[0..sip.handshake.IDENTITY_PUBLIC_KEY_SIZE], &msg.identity_public_key);
            @memcpy(out[sip.handshake.IDENTITY_PUBLIC_KEY_SIZE..][0..sip.handshake.PUBLIC_KEY_SIZE], &msg.ephemeral_public_key);
            @memcpy(out[sip.handshake.IDENTITY_PUBLIC_KEY_SIZE + sip.handshake.PUBLIC_KEY_SIZE ..], &msg.signature);
        }
    }.run;

    const deserializeMsg = struct {
        fn run(buf: []const u8, msg: *sip.handshake.HandshakeMessage) !void {
            if (buf.len != MSG_LEN) return error.InvalidPeerMessage;
            @memcpy(&msg.identity_public_key, buf[0..sip.handshake.IDENTITY_PUBLIC_KEY_SIZE]);
            @memcpy(&msg.ephemeral_public_key, buf[sip.handshake.IDENTITY_PUBLIC_KEY_SIZE..][0..sip.handshake.PUBLIC_KEY_SIZE]);
            @memcpy(&msg.signature, buf[sip.handshake.IDENTITY_PUBLIC_KEY_SIZE + sip.handshake.PUBLIC_KEY_SIZE ..]);
        }
    }.run;

    if (is_initiator) {
        verbosePrint(verbose, "[sipd-kex] [initiator] Sende Handshake...\n", .{});
        var out_buf: [MSG_LEN]u8 = undefined;
        serializeMsg(local_msg, &out_buf);
        try sendFramed(sock, &out_buf, verbose);

        verbosePrint(verbose, "[sipd-kex] [initiator] Warte auf Peer...\n", .{});
        const peer_buf = try recvFramed(allocator, sock, verbose);
        defer allocator.free(peer_buf);
        try deserializeMsg(peer_buf, &peer_msg);
    } else {
        verbosePrint(verbose, "[sipd-kex] [responder] Warte auf Peer...\n", .{});
        const peer_buf = try recvFramed(allocator, sock, verbose);
        defer allocator.free(peer_buf);
        try deserializeMsg(peer_buf, &peer_msg);

        verbosePrint(verbose, "[sipd-kex] [responder] Sende Handshake...\n", .{});
        var out_buf: [MSG_LEN]u8 = undefined;
        serializeMsg(local_msg, &out_buf);
        try sendFramed(sock, &out_buf, verbose);
    }

    verbosePrint(verbose, "[sipd-kex] Verifiziere Peer-Signatur...\n", .{});
    try peer_msg.verify();

    const session = try sip.handshake.completeHandshake(
        local_keys,
        local_address,
        local_ephemeral,
        peer_msg,
        peer_address,
    );

    var addr_buf: [64]u8 = undefined;
    const addr_str = try formatSipAddress(&addr_buf, "peer", session.peer_address);
    verbosePrint(verbose, "[sipd-kex] Peer: {s}  ConnID: {d}\n", .{ addr_str, session.conn_id });

    return session;
}

// ---------------------------------------------------------------------------
// Verbindungshandling
// ---------------------------------------------------------------------------

fn handleConnection(
    io: std.Io,
    allocator: std.mem.Allocator,
    config: DaemonConfig,
    keys: sip.identity.KeyPair,
    conn: sip.synet.Socket,
) !void {
    defer sip.synet.close(conn);

    {
        connection_mutex.lockUncancelable(io);
        defer connection_mutex.unlock(io);
        current_connection = conn;
    }
    defer {
        connection_mutex.lockUncancelable(io);
        defer connection_mutex.unlock(io);
        current_connection = null;
    }

    const addr = sip.identity.baseAddress(keys.public);

    var disc_buf: [34]u8 = undefined;
    try sip.synet.recvExact(conn, &disc_buf);

    if (disc_buf[0] != sip.header.MAGIC) return error.InvalidMagic;
    if (disc_buf[1] != @intFromEnum(sip.protocol.Command.discovery)) return error.InvalidDiscovery;

    var disc_src: [16]u8 = undefined;
    @memcpy(&disc_src, disc_buf[2..18]);
    std.debug.print("[sipd] Discovery von: {x}\n", .{disc_src});

    var reply_buf: [34]u8 = undefined;
    const reply = try sip.header.buildDiscoveryPacket(&reply_buf, addr, disc_src);
    try sip.synet.sendAll(conn, reply);
    verbosePrint(config.verbose, "[sipd] Discovery-Reply gesendet\n", .{});

    var session = try performKeyExchange(io, allocator, conn, keys, addr, false, null, config.verbose);
    defer session.deinit();
    const rx_key = session.rx;
    verbosePrint(config.verbose, "[sipd] Schlüsselaustausch abgeschlossen\n", .{});

    var reassembler = sip.translation.Reassembler.init(io, allocator, "/tmp/sip");
    defer reassembler.deinit();

    const stdout = std.Io.File.stdout();

    const first_pkt = try sip.translation.readInboundPacket(conn, allocator, rx_key);
    defer sip.translation.freeInboundPacket(allocator, first_pkt);

    switch (first_pkt.parsed.command) {
        .Data => {
            // Fall 1: Direkt-Daten
            verbosePrint(config.verbose, "[sipd] Direkt-Daten empfangen\n", .{});
            try stdout.writeStreamingAll(io, "\n");
            try stdout.writeStreamingAll(io, first_pkt.parsed.payload);
            try stdout.writeStreamingAll(io, "\n\n");
        },

        .DataChunk => {
            // Fall 2: Großer Datentransfer
            const chunk_paths: [][]u8 = blk: {
                switch (try reassembler.feed(first_pkt.parsed)) {
                    .pending => {},
                    .complete => |paths| break :blk paths,
                }

                while (!should_shutdown.load(.acquire)) {
                    const pkt = sip.translation.readInboundPacket(conn, allocator, rx_key) catch |err| {
                        if (err == error.ConnectionClosed or err == error.SocketError) {
                            std.debug.print("[sipd] Verbindung geschlossen\n", .{});
                            break :blk &[_][]u8{};
                        }
                        std.debug.print("[sipd] Lesefehler: {any}\n", .{err});
                        return err;
                    };
                    defer sip.translation.freeInboundPacket(allocator, pkt);

                    switch (try reassembler.feed(pkt.parsed)) {
                        .pending => continue,
                        .complete => |paths| break :blk paths,
                    }
                }
                break :blk &[_][]u8{};
            };

            defer {
                for (chunk_paths) |p| allocator.free(p);
                allocator.free(chunk_paths);
            }

            verbosePrint(config.verbose, "[sipd] Chunk-Transfer komplett, {d} Chunks\n", .{chunk_paths.len});

            for (chunk_paths) |chunk_path| {
                try streamFileAndDelete(io, allocator, stdout, chunk_path, config.verbose);
            }
        },

        else => |cmd| {
            std.debug.print("[sipd] Unbehandeltes oder anderes Command empfangen: {any}\n", .{cmd});
        },
    }
}

fn streamFileAndDelete(io: std.Io, allocator: std.mem.Allocator, dest: anytype, path: []const u8, verbose: bool) !void {
    var tmp_dir = try std.Io.Dir.openDirAbsolute(io, "/tmp", .{});
    defer tmp_dir.close(io);

    const tmp_prefix = "/tmp/";
    const relative_to_tmp = if (std.mem.startsWith(u8, path, tmp_prefix))
        path[tmp_prefix.len..]
    else
        path;

    verbosePrint(verbose, "[sipd-debug] Lese Datei {s}\n", .{relative_to_tmp});

    const data = try tmp_dir.readFileAlloc(io, relative_to_tmp, allocator, .unlimited);
    defer allocator.free(data);

    try dest.writeStreamingAll(io, data);

    try tmp_dir.deleteFile(io, relative_to_tmp);
}

// ---------------------------------------------------------------------------
// Daemon-Hauptschleife
// ---------------------------------------------------------------------------

fn runDaemon(
    io: std.Io,
    allocator: std.mem.Allocator,
    config: DaemonConfig,
    keys: sip.identity.KeyPair,
) !void {
    try setupSignalHandlers();
    try ensureRuntimeDir(io, config.runtime_dir);
    try writePidFile(io, config.pidfile);
    defer removePidFile(io, config.pidfile);

    if (config.verbose) {
        var addr_buf: [64]u8 = undefined;
        const addr = sip.identity.baseAddress(keys.public);
        const addr_str = try formatSipAddress(&addr_buf, config.identity_name, addr);
        std.debug.print("[sipd] SIP-Adresse : {s}\n", .{addr_str});
        std.debug.print("[sipd] Modus       : {s}\n", .{if (config.use_v6) "IPv6" else "IPv4"});
        std.debug.print("[sipd] Host        : {s}\n", .{config.host orelse "ANY (0.0.0.0 / ::)"});
        std.debug.print("[sipd] Port        : {d}\n", .{config.port});
    }

    const listener = if (config.use_v6)
        try sip.synet.createTcpSocketFamily(std.posix.AF.INET6)
    else
        try sip.synet.createTcpSocket();
    defer sip.synet.close(listener);

    if (config.use_v6) {
        var ip_bytes = [_]u8{0} ** 16;
        if (config.host) |h| {
            if (std.mem.eql(u8, h, "::1")) {
                ip_bytes[15] = 1;
            } else if (std.mem.eql(u8, h, "::")) {} else {
                std.debug.print("[sipd] Fehler: IPv6-Parsing für '{s}' nicht implementiert (nutze '::1' oder '::')\n", .{h});
                return error.UnsupportedIPv6Format;
            }
        }
        const bind_addr = sip.synet.buildSockaddrIn6(ip_bytes, config.port);
        try sip.synet.bind6(listener, &bind_addr);
    } else {
        var ip_bytes = [_]u8{ 0, 0, 0, 0 };
        if (config.host) |h| {
            var it = std.mem.splitScalar(u8, h, '.');
            var i: usize = 0;
            while (it.next()) |part| : (i += 1) {
                if (i >= 4) return error.InvalidAddress;
                ip_bytes[i] = std.fmt.parseInt(u8, part, 10) catch {
                    std.debug.print("[sipd] Fehler: Ungültige IPv4-Komponente '{s}' in '{s}'\n", .{ part, h });
                    return error.InvalidAddress;
                };
            }
            if (i != 4) {
                std.debug.print("[sipd] Fehler: IPv4-Adresse '{s}' hat keine 4 Segmente\n", .{h});
                return error.InvalidAddress;
            }
        }
        const bind_addr = sip.synet.buildSockaddrIn(ip_bytes, config.port);
        try sip.synet.bind(listener, &bind_addr);
    }

    try sip.synet.listen(listener, 1);
    verbosePrint(config.verbose, "[sipd] lauscht auf Port {d}\n", .{config.port});

    while (!should_shutdown.load(.acquire)) {
        std.debug.print("[sipd] warte auf Verbindung...\n", .{});

        const conn = sip.synet.accept(listener) catch |err| {
            if (should_shutdown.load(.acquire)) break;
            return err;
        };

        std.debug.print("[sipd] Verbindung angenommen\n", .{});
        handleConnection(io, allocator, config, keys, conn) catch |err| {
            std.debug.print("[sipd] Fehler: {any}\n", .{err});
        };
    }

    std.debug.print("[sipd] heruntergefahren\n", .{});
}

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

// ---------------------------------------------------------------------------
// Einstiegspunkt
// ---------------------------------------------------------------------------
pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.gpa;

    const argv = try init.minimal.args.toSlice(gpa);
    defer gpa.free(argv);

    var arg_idx: usize = 1;
    var args = ArgIter{ .argv = argv, .idx = &arg_idx };

    var config_path: []const u8 = CONFIG_PATH;
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "-c") or std.mem.eql(u8, arg, "--config")) {
            config_path = args.next() orelse {
                std.debug.print("[sipd] Fehler: -c erwartet einen Pfad\n", .{});
                std.process.exit(1);
            };
        }
    }

    const config = loadConfig(io, gpa, config_path) catch |err| {
        std.debug.print("[sipd] Konfigurationsfehler ({any}), Abbruch.\n", .{err});
        std.process.exit(1);
    };

    const keys = loadOrCreateIdentity(init, gpa, config.identity_name) catch |err| {
        std.debug.print("[sipd] Identitätsfehler ({any}), Abbruch.\n", .{err});
        std.process.exit(1);
    };

    try runDaemon(io, gpa, config, keys);
}
