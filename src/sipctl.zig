// TODO:
// default user integration!!!!
// etc...
//
//

const std = @import("std");
const sip = @import("sip");
const keymng = @import("keymng.zig");
const Io = std.Io;
const registry = @import("registry.zig");
const fs = @import("filesystem.zig");
const cmd = @import("cmdhandler.zig");

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
        try ctx.stdout.print("{d}: {s}: <kein gültiger public key>\n", .{ ctx.idx, entry.name() });
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
        cmd.ctl.cmdNew(io, stdout, init.environ_map, &args) catch |err| switch (err) {
            cmd.CliError.MissingArgument => try stdout.writeAll("Verwendung: sipctl new <name>\n"),
            else => return err,
        };
        try stdout.flush();
    } else if (std.mem.eql(u8, final_cmd, "show")) {
        cmd.ctl.cmdShow(io, stdout, &args) catch |err| switch (err) {
            cmd.CliError.MissingArgument => try stdout.writeAll("Verwendung: sipctl show <name>\n"),
            else => return err,
        };
        try stdout.flush();
    } else if (std.mem.eql(u8, final_cmd, "id")) {
        cmd.ctl.cmdId(io, stdout, &args) catch |err| switch (err) {
            cmd.CliError.MissingArgument => try stdout.writeAll("Verwendung: sipctl id <name>\n"),
            else => return err,
        };
        try stdout.flush();
    } else if (std.mem.eql(u8, final_cmd, "export")) {
        cmd.ctl.cmdExport(io, stdout, &args) catch |err| switch (err) {
            cmd.CliError.MissingArgument => try stdout.writeAll("Verwendung: sipctl export <name>\n"),
            else => return err,
        };
        try stdout.flush();
    } else if (std.mem.eql(u8, final_cmd, "rm") or std.mem.eql(u8, final_cmd, "remove") or std.mem.eql(u8, final_cmd, "delete")) {
        cmd.ctl.cmdRemove(io, stdout, &args) catch |err| switch (err) {
            cmd.CliError.MissingArgument => try stdout.writeAll("Verwendung: sipctl rm <name>\n"),
            else => return err,
        };
        try stdout.flush();
    } else if (std.mem.eql(u8, final_cmd, "passwd")) {
        cmd.ctl.cmdPasswd(io, stdout, init.environ_map, &args) catch |err| switch (err) {
            cmd.CliError.MissingArgument => try stdout.writeAll("Verwendung: sipctl passwd <name>\n"),
            else => return err,
        };
        try stdout.flush();
    } else if (std.mem.eql(u8, final_cmd, "send")) {
        cmd.ctl.cmdSend(io, gpa, stdout, init.environ_map, &args) catch |err| {
            std.debug.print("Fehler beim Senden: {}\n", .{err});
        };
    } else {
        try stdout.print("Unbekannter Befehl: '{s}'\n", .{final_cmd});
        try stdout.writeAll("Siehe 'sipctl --help' für Hilfe.\n");
        try stdout.flush();
    }
}
