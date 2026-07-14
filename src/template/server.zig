const std = @import("std");
const sip = @import("sip");
const utils = @import("siputils");

// ---------------------------------------------------------------------------
//   Beispiel-Konfigurationsdatei:
//   # Kommentar
//   identity_name = identity
//   host          = 0.0.0.0
//   port          = 9443
//   use_v6        = false
//   output_path   = /var/spool/sip/payload
//   verbose       = true
// ---------------------------------------------------------------------------

const Context = struct {
    allocator: std.mem.Allocator,
    config: utils.sipd.DaemonConfig,
    keys: sip.identity.KeyPair,
};

fn streamFileAndDelete(io: std.Io, allocator: std.mem.Allocator, dest: anytype, path: []const u8, verbose: bool) !void {
    var tmp_dir = try std.Io.Dir.openDirAbsolute(io, "/tmp", .{});
    defer tmp_dir.close(io);

    const tmp_prefix = "/tmp/";
    const relative_to_tmp = if (std.mem.startsWith(u8, path, tmp_prefix))
        path[tmp_prefix.len..]
    else
        path;

    utils.sipd.verbosePrint(verbose, "[sipd-debug] Lese Datei {s}\n", .{relative_to_tmp});

    const data = try tmp_dir.readFileAlloc(io, relative_to_tmp, allocator, .unlimited);
    defer allocator.free(data);

    try dest.writeStreamingAll(io, data);

    try tmp_dir.deleteFile(io, relative_to_tmp);
}

fn handleConnection(io: std.Io, ctx: *const Context, conn: sip.synet.Socket) void {
    handleConnectionInner(io, ctx, conn) catch |err| {
        std.debug.print("[sipd] Verbindungsfehler: {any}\n", .{err});
    };
}

fn handleConnectionInner(io: std.Io, ctx: *const Context, conn: sip.synet.Socket) !void {
    defer sip.synet.close(conn);

    const allocator = ctx.allocator;
    const config = ctx.config;
    const keys = ctx.keys;

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
    utils.sipd.verbosePrint(config.verbose, "[sipd] Discovery-Reply gesendet\n", .{});

    var session = try sip.handshake.performKeyExchange(
        io,
        allocator,
        conn,
        keys,
        addr,
        false, // responder
        null,
    );
    defer session.deinit();
    const rx_key = session.rx;
    utils.sipd.verbosePrint(config.verbose, "[sipd] Schlüsselaustausch abgeschlossen (ConnID: {d})\n", .{session.conn_id});

    var reassembler = sip.translation.Reassembler.init(io, allocator, "/tmp/sip");
    defer reassembler.deinit();

    const stdout = std.Io.File.stdout();

    const first_pkt = try sip.translation.readInboundPacket(conn, allocator, rx_key);
    defer sip.translation.freeInboundPacket(allocator, first_pkt);

    switch (first_pkt.parsed.command) {
        .Data => {
            // Fall 1: Direkt-Daten
            utils.sipd.verbosePrint(config.verbose, "[sipd] Direkt-Daten empfangen\n", .{});
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

                break :blk &[_][]u8{};
            };

            defer {
                for (chunk_paths) |p| allocator.free(p);
                allocator.free(chunk_paths);
            }

            utils.sipd.verbosePrint(config.verbose, "[sipd] Chunk-Transfer komplett, {d} Chunks\n", .{chunk_paths.len});

            for (chunk_paths) |chunk_path| {
                try streamFileAndDelete(io, allocator, stdout, chunk_path, config.verbose);
            }
        },

        else => |c| {
            std.debug.print("[sipd] Unbehandeltes oder anderes Command empfangen: {any}\n", .{c});
        },
    }
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

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.gpa;

    const argv = try init.minimal.args.toSlice(gpa);
    defer gpa.free(argv);

    var arg_idx: usize = 1;
    var args = ArgIter{ .argv = argv, .idx = &arg_idx };

    var config_path: []const u8 = utils.sipd.CONFIG_PATH;
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "-c") or std.mem.eql(u8, arg, "--config")) {
            config_path = args.next() orelse {
                std.debug.print("[sipd] Fehler: -c erwartet einen Pfad\n", .{});
                std.process.exit(1);
            };
        }
    }

    const config = utils.sipd.loadConfig(io, gpa, config_path) catch |err| {
        std.debug.print("[sipd] Konfigurationsfehler ({any}), Abbruch.\n", .{err});
        std.process.exit(1);
    };
    defer gpa.free(config.identity_name);
    defer if (config.host) |h| gpa.free(h);
    defer if (config.output_path) |o| gpa.free(o);

    const keys = utils.sipd.loadOrCreateIdentity(init, config.identity_name) catch |err| {
        std.debug.print("[sipd] Identitätsfehler ({any}), Abbruch.\n", .{err});
        std.process.exit(1);
    };

    if (config.verbose) {
        var addr_buf: [64]u8 = undefined;
        const addr = sip.identity.baseAddress(keys.public);
        const addr_str = try sip.identity.formatSipAddress(&addr_buf, config.identity_name, addr);
        std.debug.print("[sipd] SIP-Adresse : {s}\n", .{addr_str});
        std.debug.print("[sipd] Modus       : {s}\n", .{if (config.use_v6) "IPv6" else "IPv4"});
        std.debug.print("[sipd] Host        : {s}\n", .{config.host orelse "ANY (0.0.0.0 / ::)"});
        std.debug.print("[sipd] Port        : {d}\n", .{config.port});
    }

    const listener = utils.sipd.createListener(config) catch |err| {
        std.debug.print("[sipd] Fehler beim Erstellen des Listeners: {any}\n", .{err});
        std.process.exit(1);
    };
    defer sip.synet.close(listener);

    utils.sipd.verbosePrint(config.verbose, "[sipd] lauscht auf Port {d}\n", .{config.port});

    const ctx = Context{ .allocator = gpa, .config = config, .keys = keys };

    try utils.sipd.acceptLoop(io, listener, &ctx, handleConnection);

    std.debug.print("[sipd] heruntergefahren\n", .{});
}
