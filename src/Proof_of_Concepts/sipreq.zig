// TODO: SICHERHEIT!!!! trunst prinzip muss noch erstellt werden also keihne ahnung.
// außerdem halt das genrelle wirkche registirien mal iwrlich richtig machen nciht so wie es jezt gerade ist
const std = @import("std");
const linux = std.os.linux;
const Io = std.Io;
const sip = @import("sip");

const utils = @import("siputils");
const registry = utils.registry;
const keymng = utils.keymng;
const sipd_config = utils.sipd;
const cmd = utils.cmdhandler;

const DEFAULT_SIPD_CONFIG = "/etc/sip/sipd.conf";

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.gpa;
    const arena_alloc = init.arena.allocator();

    var stdout_buf: [4096]u8 = undefined;
    var stdout_w = Io.File.stdout().writer(io, &stdout_buf);
    const stdout = &stdout_w.interface;

    const args = try init.minimal.args.toSlice(arena_alloc);

    if (args.len < 2) {
        try stdout.writeAll("Usage: sipreg <ipv6-or-unreg-name> [list]\n");
        try stdout.writeAll("  sipreg <ipv6>      Register an unreg entry\n");
        try stdout.writeAll("  sipreg list        List all unreg entries\n");
        try stdout.flush();
        return;
    }

    const query = args[1];

    if (std.mem.eql(u8, query, "list")) {
        try stdout.writeAll("Unregistrierte Peers:\n\n");

        try registry.forEachRecord(io, *Io.Writer, stdout, struct {
            fn cb(out: *Io.Writer, entry: registry.RegistryEntry) !void {
                if (!entry.isDiscovered()) return;

                var addr_buf: [40]u8 = undefined;
                const addr_str = registry.formatIpv6(&addr_buf, entry.addr[0..16].*);

                var mesh_buf: [registry.MESH_ADDR_SIZE * 2 + 3]u8 = undefined;
                const mesh_str = registry.formatMeshAddrGrouped(&mesh_buf, entry.mesh_addr);

                try out.print("  {s}\n", .{entry.name()});
                try out.print("    ipv6: {s}\n", .{addr_str});
                try out.print("    mesh: {s}\n\n", .{mesh_str});
            }
        }.cb);

        try stdout.flush();
        return;
    }

    const config = sipd_config.loadConfig(io, gpa, DEFAULT_SIPD_CONFIG) catch |err| {
        try stdout.print("Error loading sipd config: {}\n", .{err});
        try stdout.flush();
        return;
    };
    defer {
        gpa.free(config.identity_name);
        if (config.host) |h| gpa.free(h);
        if (config.output_path) |o| gpa.free(o);
    }

    var pw_buf: [256]u8 = undefined;
    const password = cmd.resolvePassword(io, stdout, init.environ_map, .{ .env_name = "SIPREG_PASSWORD" }, &pw_buf, false) catch |err| {
        try stdout.print("Error resolving password: {}\n", .{err});
        try stdout.flush();
        return;
    };

    const kp = keymng.loadIdentity(io, config.identity_name, password) catch |err| {
        try stdout.print("Error loading identity '{s}': {}\n", .{ config.identity_name, err });
        try stdout.flush();
        return;
    };

    const our_base_addr = sip.identity.baseAddress(kp.public);
    try stdout.print("[sipreg] Loading identity '{s}', base: {x}\n", .{ config.identity_name, our_base_addr });

    const resolved = registry.resolve(io, query) catch |err| {
        try stdout.print("Error resolving '{s}': {}\n", .{ query, err });
        try stdout.flush();
        return;
    };

    if (resolved.entry.kind != .ipv6) {
        try stdout.writeAll("Error: resolved entry is not IPv6 type\n");
        try stdout.flush();
        return;
    }

    if (resolved.entry.resolved_mesh == null) {
        try stdout.writeAll("Error: no mesh address associated with this entry\n");
        try stdout.flush();
        return;
    }

    const peer_ipv6 = resolved.entry.ipv6;
    const peer_mesh = resolved.entry.resolved_mesh.?;

    var ipv6_buf: [50]u8 = undefined;
    var mesh_buf: [registry.MESH_ADDR_SIZE * 2]u8 = undefined;
    const ipv6_str = registry.formatIpv6(&ipv6_buf, peer_ipv6);
    const mesh_str = registry.formatMeshAddr(&mesh_buf, peer_mesh);

    try stdout.print("[sipreg] Resolved '{s}':\n", .{query});
    try stdout.print("  IPv6: {s}\n", .{ipv6_str});
    try stdout.print("  Mesh: {s}\n", .{mesh_str});
    try stdout.print("  Discovered: {}\n", .{resolved.source == .registry and registry.isDiscoveredName(resolved.matchedName())});

    try stdout.print("[sipreg] Sende Discovery-Paket an {s}:{d}...\n", .{ ipv6_str, config.port });
    try stdout.flush();

    const sock = try sip.synet.createTcpSocketFamily(std.posix.AF.INET6);
    defer sip.synet.close(sock);

    const peer_sockaddr = sip.synet.buildSockaddrIn6(peer_ipv6, config.port);
    sip.synet.connect6(sock, &peer_sockaddr) catch |err| {
        try stdout.print("Error: Verbindung zu {s}:{d} fehlgeschlagen: {}\n", .{ ipv6_str, config.port, err });
        try stdout.flush();
        return;
    };

    var disc_buf: [sip.header.OUTER_HEADER_SIZE]u8 = undefined;
    const disc_pkt = try sip.header.buildDiscoveryPacket(&disc_buf, our_base_addr, [_]u8{0} ** 16);

    sip.synet.sendAll(sock, disc_pkt) catch |err| {
        try stdout.print("Error: Discovery-Paket konnte nicht gesendet werden: {}\n", .{err});
        try stdout.flush();
        return;
    };

    var reply_buf: [34]u8 = undefined;
    sip.synet.recvExact(sock, &reply_buf) catch |err| {
        try stdout.print("Error: Keine Antwort auf Discovery-Paket: {}\n", .{err});
        try stdout.flush();
        return;
    };

    if (reply_buf[0] != sip.header.MAGIC) {
        try stdout.writeAll("Error: Ungültiges Magic-Byte in Discovery-Antwort\n");
        try stdout.flush();
        return;
    }

    var fresh_peer_addr: [16]u8 = undefined;
    @memcpy(&fresh_peer_addr, reply_buf[2..18]);

    // TODO: hier soll später noch mehr Logik rein (z.B. Re-Trust-Flow)
    if (!std.mem.eql(u8, &fresh_peer_addr, &peer_mesh)) {
        try stdout.writeAll("Error: Peer-Identität hat sich geändert! Erwartete SIP-Adresse stimmt nicht mit der Discovery-Antwort überein.\n");
        try stdout.print("  Erwartet: {x}\n", .{peer_mesh});
        try stdout.print("  Erhalten: {x}\n", .{fresh_peer_addr});
        try stdout.flush();
        return error.PeerIdentityMismatch;
    }

    try stdout.print("[sipreg] Discovery bestätigt: {x}\n", .{fresh_peer_addr});
    try stdout.flush();

    try stdout.writeAll("\nEnter label to register (or Ctrl+C to cancel):\n");

    try stdout.writeAll("> ");
    try stdout.flush();

    var label_buf: [64]u8 = undefined;
    const n_rc = linux.read(0, &label_buf, label_buf.len);
    const n_signed: isize = @bitCast(n_rc);
    if (n_signed <= 0) {
        try stdout.writeAll("Error reading input\n");
        try stdout.flush();
        return;
    }
    const n: usize = @intCast(n_signed);
    const label = std.mem.trim(u8, label_buf[0..n], " \t\r\n");

    if (label.len == 0 or label.len > registry.MAX_NAME_LEN) {
        try stdout.writeAll("Error: label must be 1-64 characters\n");
        try stdout.flush();
        return;
    }

    var entry = registry.Entry.fromIpv6(peer_ipv6);
    entry.resolved_mesh = peer_mesh;

    try registry.register(io, label, entry);
    try stdout.print("[sipreg] Registered '{s}' (IPv6: {s})\n", .{ label, ipv6_str });
    try stdout.flush();
}
