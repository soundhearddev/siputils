// TODO:
// default user integration!!!!
// etc...
//
//
const std = @import("std");
const sip = @import("sip");
const Io = std.Io;

const utils = @import("siputils");
const keymng = utils.keymng;
const registry = utils.registry;
const fs = utils.filesystem;
const cmd = utils.cmdhandler;

var config = struct { verbose: bool }{ .verbose = false };

fn verbosePrint(verbose: bool, comptime fmt: []const u8, args: anytype) void {
    if (verbose) {
        std.debug.print(fmt, args);
    }
}

const ListCtx = struct {
    stdout: *Io.Writer,
    verbose: bool,
    idx: usize = 1,
};

fn printIdentityEntry(ctx: *ListCtx, entry: keymng.IdentityEntry, name: []const u8) !void {
    if (!entry.valid) {
        try ctx.stdout.print("{d}: {s}: <invalid public key>\n", .{ ctx.idx, entry.name() });
        ctx.idx += 1;
        return;
    }

    const base = sip.identity.baseAddress(entry.public);
    var addr_buf: [80]u8 = undefined;
    const addr = try sip.identity.formatSipAddress(&addr_buf, name, base);

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
            try stdout.writeAll("No identities found. (Folder 'keys/' does not exist)\n");
            try stdout.writeAll("Create one with: sipctl new <name>\n");
            try stdout.flush();
            return;
        },
        else => return err,
    };

    if (ctx.idx == 1) {
        try stdout.writeAll("No identities found.\n");
        try stdout.writeAll("Create one with: sipctl new <name>\n");
    }
    try stdout.flush();
}

fn printHelp(stdout: *Io.Writer) !void {
    try stdout.writeAll(
        \\sipctl - SIP identity and address management
        \\
        \\Identity management:
        \\  sipctl                      List addresses in compact form (like 'ip a')
        \\  sipctl -v, --verbose        List addresses with details
        \\  sipctl list                 Alias for the above
        \\
        \\  sipctl new <name>           Create a new identity
        \\  sipctl show <name>          Show details of an identity
        \\  sipctl id <name>            Generate a new random session/peer ID
        \\  sipctl export <name>        Output SIP address + public key
        \\  sipctl passwd <name>       Change identity password
        \\  sipctl rm <name>           Delete identity
        \\
        \\Trust management:
        \\  sipctl trust <pubkey_hex> <label>
        \\                              Add a peer public key to the trust whitelist
        \\  sipctl untrust <pubkey_hex>
        \\                              Remove a peer public key from the whitelist
        \\  sipctl trust-list           List all currently trusted peers
        \\
        \\Messaging:
        \\  sipctl send <identity> <host> [--port PORT] <message>
        \\                              Send a message to a server
        \\                              If <message> starts with '@', file content is sent
        \\
        \\  sipctl -h, --help           Show this help message
        \\
        \\Password options (new/passwd/send):
        \\  --password <pw>             Provide password directly
        \\  SIP_PASSWORD env variable   Use environment variable for password
        \\  (otherwise interactive hidden prompt)
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
    var args = cmd.ArgIter{ .argv = argv, .idx = &arg_idx };

    var command: ?[]const u8 = null;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            try printHelp(stdout);
            return;
        } else if (std.mem.eql(u8, arg, "-v") or std.mem.eql(u8, arg, "--verbose")) {
            config.verbose = true;
        } else {
            command = arg;

            if (std.mem.eql(u8, arg, "list")) {
                continue;
            }
            break;
        }
    }

    if (command == null or std.mem.eql(u8, command.?, "list")) {
        try listIdentities(io, stdout, config.verbose);
        return;
    }

    const final_cmd = command.?;

    if (std.mem.eql(u8, final_cmd, "new")) {
        utils.helpers.isRoot();
        cmd.ctl.cmdNew(io, stdout, init.environ_map, &args) catch |err| switch (err) {
            cmd.CliError.MissingArgument => try stdout.writeAll("Usage: sipctl new <name>\n"),
            else => return err,
        };
        try stdout.flush();
    } else if (std.mem.eql(u8, final_cmd, "show")) {
        cmd.ctl.cmdShow(io, stdout, &args) catch |err| switch (err) {
            cmd.CliError.MissingArgument => try stdout.writeAll("Usage: sipctl show <name>\n"),
            else => return err,
        };
        try stdout.flush();
    } else if (std.mem.eql(u8, final_cmd, "id")) {
        cmd.ctl.cmdId(io, stdout, &args) catch |err| switch (err) {
            cmd.CliError.MissingArgument => try stdout.writeAll("Usage: sipctl id <name>\n"),
            else => return err,
        };
        try stdout.flush();
    } else if (std.mem.eql(u8, final_cmd, "export")) {
        cmd.ctl.cmdExport(io, stdout, &args) catch |err| switch (err) {
            cmd.CliError.MissingArgument => try stdout.writeAll("Usage: sipctl export <name>\n"),
            else => return err,
        };
        try stdout.flush();
    } else if (std.mem.eql(u8, final_cmd, "rm") or std.mem.eql(u8, final_cmd, "remove") or std.mem.eql(u8, final_cmd, "delete")) {
        utils.helpers.isRoot();
        cmd.ctl.cmdRemove(io, stdout, &args) catch |err| switch (err) {
            cmd.CliError.MissingArgument => try stdout.writeAll("Usage: sipctl rm <name>\n"),
            else => return err,
        };
        try stdout.flush();
    } else if (std.mem.eql(u8, final_cmd, "passwd")) {
        utils.helpers.isRoot();
        cmd.ctl.cmdPasswd(io, stdout, init.environ_map, &args) catch |err| switch (err) {
            cmd.CliError.MissingArgument => try stdout.writeAll("Usage: sipctl passwd <name>\n"),
            else => return err,
        };
        try stdout.flush();
    } else if (std.mem.eql(u8, final_cmd, "send")) {
        cmd.ctl.cmdSend(io, gpa, stdout, init.environ_map, &args) catch |err| {
            std.debug.print("Send error: {}\n", .{err});
        };
    } else if (std.mem.eql(u8, final_cmd, "trust")) {
        utils.helpers.isRoot();
        cmd.ctl.cmdTrust(io, stdout, &args) catch |err| {
            std.debug.print("Trust error: {}\n", .{err});
        };
    } else if (std.mem.eql(u8, final_cmd, "untrust")) {
        utils.helpers.isRoot();
        cmd.ctl.cmdUntrust(io, stdout, &args) catch |err| {
            std.debug.print("Untrust error: {}\n", .{err});
        };
    } else if (std.mem.eql(u8, final_cmd, "trust-list")) {
        cmd.ctl.cmdTrustList(io, stdout) catch |err| {
            std.debug.print("Trust-list error: {}\n", .{err});
        };
    } else {
        try stdout.print("Unknown command: '{s}'\n", .{final_cmd});
        try stdout.writeAll("See 'sipctl --help' for help.\n");
        try stdout.flush();
    }
}
