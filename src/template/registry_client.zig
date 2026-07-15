const std = @import("std");
const sip = @import("sip");
const siputils = @import("siputils");

const Io = std.Io;
const synet = sip.synet;
const handshake = sip.handshake;
const translation = sip.translation;
const protocol = sip.protocol;
const registry = siputils.registry;
const keymng = siputils.keymng;
const cmd = siputils.cmdhandler;
const helpers = siputils.helpers;
const fs = siputils.filesystem;

pub const DEFAULT_PORT: u16 = 9443;
const DEFAULT_IDENTITY: []const u8 = "default";

pub const RegistryClientError = error{
    HandshakeFailed,
    InvalidServerResponse,
    RegistrationFailed,
    UnregistrationFailed,
    ConnectionError,
    ResolveError,
    NameAmbiguous,
    ServerError,
};

pub const RegistryClient = struct {
    allocator: std.mem.Allocator,
    verbose: bool,
    client_keys: sip.identity.KeyPair,

    pub fn init(allocator: std.mem.Allocator, io: Io, init_ctx: std.process.Init, identity_name: []const u8) !RegistryClient {
        var pw_buf: [256]u8 = undefined;

        var stdout_io_buf: [1024]u8 = undefined;
        var stdout_struct = std.Io.File.stdout().writer(io, &stdout_io_buf);
        const stdout_writer = &stdout_struct.interface;

        const password = try cmd.resolvePassword(
            io,
            stdout_writer,
            init_ctx.environ_map,
            .{ .env_name = "SIP_PASSWORD" },
            &pw_buf,
            false,
        );

        const client_keys = try keymng.loadIdentity(io, identity_name, password);

        return RegistryClient{
            .allocator = allocator,
            .verbose = true,
            .client_keys = client_keys,
        };
    }

    fn connectAndHandshake(
        self: *RegistryClient,
        io: Io,
        server_host: []const u8,
        server_port: u16,
    ) !struct { sock: synet.Socket, session: handshake.SessionKeys } {
        const sock = try synet.createTcpSocketFamily(std.posix.AF.INET6);
        errdefer synet.close(sock);

        const server_ip = try registry.parseIpv6(server_host);
        const server_addr = synet.buildSockaddrIn6(server_ip, server_port);

        synet.connect6(sock, &server_addr) catch |err| {
            std.debug.print("[ERROR] Connection failed: {}\n", .{err});
            return error.ConnectionError;
        };

        const my_address = sip.identity.baseAddress(self.client_keys.public);

        const session = handshake.performKeyExchange(
            io,
            self.allocator,
            sock,
            self.client_keys,
            my_address,
            true,
            null,
        ) catch |err| {
            std.debug.print("[registry] Handshake failed: {}\n", .{err});
            return error.HandshakeFailed;
        };

        return .{ .sock = sock, .session = session };
    }

    fn sendQuery(
        self: *RegistryClient,
        io: Io,
        sock: synet.Socket,
        session: *handshake.SessionKeys,
        sub_cmd: registry.RegistrySubCommand,
        body: []const u8,
    ) !void {
        const payload = try self.allocator.alloc(u8, 1 + body.len);
        defer self.allocator.free(payload);
        payload[0] = @intFromEnum(sub_cmd);
        @memcpy(payload[1..], body);

        const pkt = try translation.buildOutboundPacket(
            io,
            self.allocator,
            session.peer_address,
            session.peer_address,
            session.conn_id,
            0,
            .Query,
            payload,
            session.tx,
        );
        defer self.allocator.free(pkt);

        try synet.sendAll(sock, pkt);
    }

    const RegistryResponse = struct {
        code: registry.RegistryResponseCode,
        data: []const u8,
        _pkt: translation.InboundPacket,

        fn deinit(self: RegistryResponse, allocator: std.mem.Allocator) void {
            translation.freeInboundPacket(allocator, self._pkt);
        }
    };

    fn readResponse(self: *RegistryClient, sock: synet.Socket, session: *handshake.SessionKeys) !RegistryResponse {
        const resp_pkt = try translation.readInboundPacket(sock, self.allocator, session.rx);
        errdefer translation.freeInboundPacket(self.allocator, resp_pkt);

        const parsed = resp_pkt.parsed;
        if (parsed.command != .Data) {
            translation.freeInboundPacket(self.allocator, resp_pkt);
            return error.InvalidServerResponse;
        }
        if (parsed.payload.len < 1) {
            translation.freeInboundPacket(self.allocator, resp_pkt);
            return error.InvalidServerResponse;
        }

        const code: registry.RegistryResponseCode = @enumFromInt(parsed.payload[0]);
        return RegistryResponse{
            .code = code,
            .data = parsed.payload[1..],
            ._pkt = resp_pkt,
        };
    }

    pub fn resolveRemote(
        self: *RegistryClient,
        io: Io,
        server_host: []const u8,
        server_port: u16,
        target_name: []const u8,
    ) !?registry.Entry {
        const conn = try self.connectAndHandshake(io, server_host, server_port);
        var session = conn.session;
        defer synet.close(conn.sock);
        defer session.deinit();

        try self.sendQuery(io, conn.sock, &session, .resolve, target_name);

        const resp = try self.readResponse(conn.sock, &session);
        defer resp.deinit(self.allocator);

        switch (resp.code) {
            .ok => {
                const entry = registry.decodeEntry(resp.data) catch {
                    return error.InvalidServerResponse;
                };
                return entry;
            },
            .not_found => {
                std.debug.print("[registry] Server reports: Name '{s}' not found.\n", .{target_name});

                return null;
            },
            .ambiguous => return error.NameAmbiguous,
            .err => return error.ServerError,
            else => return error.InvalidServerResponse,
        }
    }

    pub fn registerAtServer(
        self: *RegistryClient,
        io: Io,
        server_host: []const u8,
        server_port: u16,
        my_name: []const u8,
        my_ipv6: [16]u8,
    ) !void {
        const conn = try self.connectAndHandshake(io, server_host, server_port);
        var session = conn.session;
        defer synet.close(conn.sock);
        defer session.deinit();

        const entry = registry.Entry.fromIpv6(my_ipv6);
        var body_buf: [300]u8 = undefined;
        const body = try registry.encodeRegisterRequest(&body_buf, my_name, entry);

        try self.sendQuery(io, conn.sock, &session, .register, body);

        const resp = try self.readResponse(conn.sock, &session);
        defer resp.deinit(self.allocator);

        switch (resp.code) {
            .ok => {
                std.debug.print("[registry] Registration for '{s}' completed successfully.\n", .{my_name});
            },
            else => return error.RegistrationFailed,
        }
    }

    pub fn unregisterAtServer(
        self: *RegistryClient,
        io: Io,
        server_host: []const u8,
        server_port: u16,
        my_name: []const u8,
    ) !void {
        const conn = try self.connectAndHandshake(io, server_host, server_port);
        var session = conn.session;
        defer synet.close(conn.sock);
        defer session.deinit();

        try self.sendQuery(io, conn.sock, &session, .unregister, my_name);

        const resp = try self.readResponse(conn.sock, &session);
        defer resp.deinit(self.allocator);

        switch (resp.code) {
            .ok => {
                std.debug.print("[registry] '{s}' successfully removed.\n", .{my_name});
            },
            .not_found => return error.UnregistrationFailed,
            else => return error.UnregistrationFailed,
        }
    }
};

const CliArgs = struct {
    server_host: []const u8 = "::1",
    subcommand: []const u8,
    identity_name: []const u8 = DEFAULT_IDENTITY,
    port: u16,
    manual_name: ?[]const u8 = null,
    manual_ipv6: ?[]const u8 = null,
    resolve_target: ?[]const u8 = null,
};

fn parseArgs(args: []const []const u8) !CliArgs {
    if (args.len < 2) return error.MissingRequiredArgs;

    var result = CliArgs{
        .port = DEFAULT_PORT,
        .subcommand = undefined,
    };

    var start_idx: usize = 1;

    const first_arg = args[1];
    const is_subcmd = std.mem.eql(u8, first_arg, "resolve") or
        std.mem.eql(u8, first_arg, "register") or
        std.mem.eql(u8, first_arg, "unregister");

    if (is_subcmd) {
        result.subcommand = first_arg;
        start_idx = 2;
    } else {
        if (args.len < 3) return error.MissingRequiredArgs;
        result.server_host = first_arg;
        result.subcommand = args[2];
        start_idx = 3;
    }

    var i: usize = start_idx;
    var raw_positionals_count: usize = 0;

    while (i < args.len) : (i += 1) {
        const arg = args[i];

        if (std.mem.eql(u8, arg, "-p") or std.mem.eql(u8, arg, "--port")) {
            i += 1;
            if (i >= args.len) return error.MissingFlagValue;
            result.port = std.fmt.parseInt(u16, args[i], 10) catch return error.InvalidPort;
        } else if (std.mem.eql(u8, arg, "-i") or std.mem.eql(u8, arg, "--identity")) {
            i += 1;
            if (i >= args.len) return error.MissingFlagValue;
            result.identity_name = args[i];
        } else if (std.mem.eql(u8, arg, "-n") or std.mem.eql(u8, arg, "--name")) {
            i += 1;
            if (i >= args.len) return error.MissingFlagValue;
            result.manual_name = args[i];
        } else if (std.mem.eql(u8, arg, "-ip") or std.mem.eql(u8, arg, "--ipv6")) {
            i += 1;
            if (i >= args.len) return error.MissingFlagValue;
            result.manual_ipv6 = args[i];
        } else if (std.mem.startsWith(u8, arg, "-")) {
            std.debug.print("Error: Unknown option '{s}'\n", .{arg});
            return error.UnknownFlag;
        } else {
            if (raw_positionals_count == 0) {
                result.resolve_target = arg;
                raw_positionals_count += 1;
            } else {
                std.debug.print("Error: Too many positional arguments ('{s}')\n", .{arg});
                return error.TooManyArgs;
            }
        }
    }

    return result;
}

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;

    std.debug.print("[DEBUG] 1. Reading arguments...\n", .{});
    const raw_args = try init.minimal.args.toSlice(gpa);
    defer gpa.free(raw_args);

    std.debug.print("[DEBUG] 2. Parsing arguments...\n", .{});
    const args = parseArgs(raw_args) catch |err| {
        std.debug.print("[DEBUG] parseArgs failed with: {any}\n", .{err});
        printUsage();
        std.process.exit(1);
    };

    var resolved_identity_name = args.identity_name;
    var symlink_resolved_buf: [256]u8 = undefined;

    if (std.mem.eql(u8, args.identity_name, "default")) {
        var path_buf: [300]u8 = undefined;
        if (keymng.identityDir(&path_buf, "default")) |dpath| {
            const cwd = std.Io.Dir.cwd();
            if (cwd.readLink(io, dpath, &symlink_resolved_buf)) |bytes_read| {
                const target_path = symlink_resolved_buf[0..bytes_read];
                const base_name = std.fs.path.basename(target_path);
                resolved_identity_name = base_name;
                std.debug.print("[cli] Identity 'default' resolved to symlink target: '{s}'\n", .{resolved_identity_name});
            } else |_| {}
        } else |_| {}
    }

    var client = RegistryClient.init(gpa, io, init, args.identity_name) catch |err| {
        std.debug.print("[ERROR] Client initialization failed with: {any}\n", .{err});
        std.process.exit(1);
    };

    if (std.mem.eql(u8, args.subcommand, "resolve")) {
        const target_name = args.resolve_target orelse {
            std.debug.print("[ERROR] resolve_target is null!\n", .{});
            std.debug.print("[ERROR] 'resolve' requires a target name.\n", .{});
            std.process.exit(1);
        };

        const entry = client.resolveRemote(io, args.server_host, args.port, target_name) catch |err| {
            std.debug.print("[✗] Resolution failed (catch block): {any}\n", .{err});
            std.process.exit(1);
        };

        if (entry) |e| {
            var ip_buf: [40]u8 = undefined;
            switch (e.kind) {
                .mesh => {
                    std.debug.print("[✓] Found: Mesh address: {x}\n", .{e.mesh});
                },
                .ipv4 => {
                    std.debug.print("[✓] Found: IPv4 address: {d}.{d}.{d}.{d}\n", .{ e.ipv4[0], e.ipv4[1], e.ipv4[2], e.ipv4[3] });
                },
                .ipv6 => {
                    const formatted = registry.formatIpv6(&ip_buf, e.ipv6);
                    std.debug.print("[✓] Found: IPv6 address: {s}\n", .{formatted});
                },
            }
        } else {
            std.debug.print("[✗] Resolution failed. Entry does not exist on the server.\n", .{});
            std.process.exit(1);
        }
    } else if (std.mem.eql(u8, args.subcommand, "register")) {
        const my_name = args.manual_name orelse resolved_identity_name;

        var my_ipv6: [16]u8 = undefined;
        if (args.manual_ipv6) |ip_str| {
            my_ipv6 = registry.parseIpv6(ip_str) catch |err| {
                std.debug.print("Failed to parse manual IPv6 address '{s}': {any}\n", .{ ip_str, err });
                std.process.exit(1);
            };
        } else {
            const iface = helpers.getDefaultIface(gpa, io) catch |err| {
                std.debug.print("Error: Failed to determine default interface: {any}\n", .{err});
                std.process.exit(1);
            };
            defer gpa.free(iface);

            const prefix = helpers.getPrefix(gpa, io, iface) catch |err| {
                std.debug.print("Error: Failed to read IPv6 prefix from interface '{s}': {any}\n", .{ iface, err });
                std.process.exit(1);
            };
            defer gpa.free(prefix);

            const generated_ip_str = helpers.generateAddress(gpa, prefix, init) catch |err| {
                std.debug.print("Address generation failed: {any}\n", .{err});
                std.process.exit(1);
            };
            defer gpa.free(generated_ip_str);

            my_ipv6 = registry.parseIpv6(generated_ip_str) catch |err| {
                std.debug.print("Failed to parse generated address '{s}': {any}\n", .{ generated_ip_str, err });
                std.process.exit(1);
            };
            std.debug.print("[cli] IP automatically generated: {s}\n", .{generated_ip_str});
        }

        std.debug.print("[cli] Registering name '{s}' with the server...\n", .{my_name});
        client.registerAtServer(io, args.server_host, args.port, my_name, my_ipv6) catch |err| {
            std.debug.print("[✗] Registration failed: {any}\n", .{err});
            std.process.exit(1);
        };
    } else if (std.mem.eql(u8, args.subcommand, "unregister")) {
        const my_name = args.manual_name orelse resolved_identity_name;

        std.debug.print("[cli] Removing '{s}' from the server...\n", .{my_name});
        client.unregisterAtServer(io, args.server_host, args.port, my_name) catch |err| {
            std.debug.print("[✗] Removal failed: {any}\n", .{err});
            std.process.exit(1);
        };
    } else {
        std.debug.print("Error: Unknown command '{s}'\n", .{args.subcommand});
        printUsage();
        std.process.exit(1);
    }
}

fn printUsage() void {
    std.debug.print(
        \\Usage:
        \\  registry_client <server_host> resolve <target_name> [Options]
        \\  registry_client <server_host> register [Options]
        \\  registry_client <server_host> unregister [Options]
        \\
        \\Options:
        \\  -p, --port N          Server port (Default: {d})
        \\  -i, --identity NAME   Local identity to use (Default: "{s}")
        \\  -n, --name NAME       Manual registration name (Default: Identity name)
        \\  -ip, --ipv6 ADDR      Manual registration IPv6 (Default: Auto-generated)
        \\
    , .{ DEFAULT_PORT, DEFAULT_IDENTITY });
}
