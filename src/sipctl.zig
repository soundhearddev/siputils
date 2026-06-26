const std = @import("std");
const sip = @import("sip");
const keystore = @import("keystore.zig");
const Io = std.Io;

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

fn printIdentityEntry(ctx: *ListCtx, entry: keystore.IdentityEntry) !void {
    if (!entry.valid) {
        try ctx.stdout.print("{d}: {s}: <kein gültiger public key>\n", .{ ctx.idx, entry.name() });
        ctx.idx += 1;
        return;
    }

    const base = sip.identity.baseAddress(entry.public);
    var addr_buf: [80]u8 = undefined;
    const addr = try sip.identity.formatSipAddress(&addr_buf, base);

    if (ctx.verbose) {
        try ctx.stdout.print("{d}: {s}\n", .{ ctx.idx, entry.name() });
        try ctx.stdout.print("    sip-address: {s}\n", .{addr});
        try ctx.stdout.print("    public-key : {x}\n", .{entry.public});
        try ctx.stdout.print("    base-addr  : {x}\n", .{base});
        var dir_buf: [300]u8 = undefined;
        const dpath = try keystore.identityDir(&dir_buf, entry.name());
        try ctx.stdout.print("    keydir     : {s}\n", .{dpath});
        try ctx.stdout.writeAll("\n");
    } else {
        try ctx.stdout.print("{d}: {s}: {s}\n", .{ ctx.idx, entry.name(), addr });
    }
    ctx.idx += 1;
}

fn listIdentities(io: std.Io, stdout: *Io.Writer, verbose: bool) !void {
    var ctx = ListCtx{ .stdout = stdout, .verbose = verbose };

    keystore.forEachIdentity(io, *ListCtx, &ctx, struct {
        fn cb(c: *ListCtx, entry: keystore.IdentityEntry) !void {
            try printIdentityEntry(c, entry);
        }
    }.cb) catch |err| switch (err) {
        keystore.ListError.KeyRootMissing => {
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
    if (!keystore.validName(name)) {
        try stdout.writeAll("Fehler: Ungültiger Name (nur a-z, A-Z, 0-9, -, _, .)\n");
        try stdout.flush();
        return;
    }

    var pw_buf: [256]u8 = undefined;
    const password = try resolvePassword(io, stdout, env_map, .{}, &pw_buf, true);

    const kp = keystore.createIdentity(io, name, password) catch |err| switch (err) {
        keystore.KeystoreError.IdentityAlreadyExists => {
            try stdout.print("Fehler: Identität '{s}' existiert bereits.\n", .{name});
            try stdout.flush();
            return;
        },
        else => return err,
    };

    const base = sip.identity.baseAddress(kp.public);
    var addr_buf: [80]u8 = undefined;
    const addr = try sip.identity.formatSipAddress(&addr_buf, base);

    try stdout.print("[+] Identität '{s}' erstellt\n", .{name});
    try stdout.print("    sip-address: {s}\n", .{addr});
    try stdout.print("    public-key : {x}\n", .{kp.public});
    try stdout.flush();
}

fn cmdShow(io: std.Io, stdout: *Io.Writer, args: *ArgIter) !void {
    const name = args.next() orelse return CliError.MissingArgument;

    const pub_bytes = keystore.loadPublicOnly(io, name) catch |err| switch (err) {
        keystore.KeystoreError.IdentityNotFound => {
            try stdout.print("Fehler: Identität '{s}' nicht gefunden.\n", .{name});
            try stdout.flush();
            return;
        },
        else => return err,
    };
    const base = sip.identity.baseAddress(pub_bytes);
    var addr_buf: [80]u8 = undefined;
    const addr = try sip.identity.formatSipAddress(&addr_buf, base);

    var dir_buf: [300]u8 = undefined;
    const dpath = try keystore.identityDir(&dir_buf, name);

    try stdout.print("name        : {s}\n", .{name});
    try stdout.print("sip-address : {s}\n", .{addr});
    try stdout.print("public-key  : {x}\n", .{pub_bytes});
    try stdout.print("base-addr   : {x}\n", .{base});
    try stdout.print("keydir      : {s}\n", .{dpath});
    try stdout.flush();
}

fn cmdId(io: std.Io, stdout: *Io.Writer, args: *ArgIter) !void {
    const name = args.next() orelse return CliError.MissingArgument;
    const pub_bytes = keystore.loadPublicOnly(io, name) catch |err| switch (err) {
        keystore.KeystoreError.IdentityNotFound => {
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
    const pub_bytes = keystore.loadPublicOnly(io, name) catch |err| switch (err) {
        keystore.KeystoreError.IdentityNotFound => {
            try stdout.print("Fehler: Identität '{s}' nicht gefunden.\n", .{name});
            try stdout.flush();
            return;
        },
        else => return err,
    };
    const base = sip.identity.baseAddress(pub_bytes);
    var addr_buf: [80]u8 = undefined;
    const addr = try sip.identity.formatSipAddress(&addr_buf, base);
    try stdout.print("{s} {x}\n", .{ addr, pub_bytes });
    try stdout.flush();
}

fn cmdRemove(io: std.Io, stdout: *Io.Writer, args: *ArgIter) !void {
    const name = args.next() orelse return CliError.MissingArgument;

    keystore.deleteIdentity(io, name) catch |err| switch (err) {
        keystore.KeystoreError.IdentityNotFound => {
            try stdout.print("Fehler: Identität '{s}' nicht gefunden.\n", .{name});
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

    _ = keystore.changePassword(io, name, old_pw, new_pw) catch |err| switch (err) {
        keystore.KeystoreError.IdentityNotFound => {
            try stdout.print("Fehler: Identität '{s}' nicht gefunden.\n", .{name});
            try stdout.flush();
            return;
        },
        sip.identity.SipError.DecryptionFailed => {
            try stdout.writeAll("Fehler: Falsches Passwort.\n");
            try stdout.flush();
            return;
        },
        else => return err,
    };

    try stdout.print("[+] Passwort für '{s}' geändert\n", .{name});
    try stdout.flush();
}

fn printHelp(stdout: *Io.Writer) !void {
    try stdout.writeAll(
        \\sipctl - SIP Identitäts- und Adressverwaltung
        \\
        \\Verwendung:
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
        \\  sipctl -h, --help           Diese Hilfe anzeigen
        \\
        \\Passwort-Optionen (new/passwd):
        \\  --password <pw>             Passwort direkt übergeben
        \\  SIP_PASSWORD Env-Variable    Passwort über Umgebungsvariable
        \\  (sonst interaktiver, versteckter Prompt)
        \\
    );
    try stdout.flush();
}

pub fn main(init: std.process.Init) !void {
    const io = init.io;

    var stdout_buf: [4096]u8 = undefined;
    var stdout_w = Io.File.stdout().writer(io, &stdout_buf);
    const stdout = &stdout_w.interface;

    const arena_alloc = init.arena.allocator();
    const argv = try init.minimal.args.toSlice(arena_alloc);

    var arg_idx: usize = 1;
    var args = ArgIter{ .argv = argv, .idx = &arg_idx };

    const first = args.next();

    if (first == null) {
        try listIdentities(io, stdout, false);
        return;
    }

    const cmd = first.?;

    if (std.mem.eql(u8, cmd, "-h") or std.mem.eql(u8, cmd, "--help")) {
        try printHelp(stdout);
    } else if (std.mem.eql(u8, cmd, "-v") or std.mem.eql(u8, cmd, "--verbose")) {
        try listIdentities(io, stdout, true);
    } else if (std.mem.eql(u8, cmd, "list")) {
        try listIdentities(io, stdout, false);
    } else if (std.mem.eql(u8, cmd, "new")) {
        cmdNew(io, stdout, init.environ_map, &args) catch |err| switch (err) {
            CliError.MissingArgument => try stdout.writeAll("Verwendung: sipctl new <name>\n"),
            else => return err,
        };
        try stdout.flush();
    } else if (std.mem.eql(u8, cmd, "show")) {
        cmdShow(io, stdout, &args) catch |err| switch (err) {
            CliError.MissingArgument => try stdout.writeAll("Verwendung: sipctl show <name>\n"),
            else => return err,
        };
        try stdout.flush();
    } else if (std.mem.eql(u8, cmd, "id")) {
        cmdId(io, stdout, &args) catch |err| switch (err) {
            CliError.MissingArgument => try stdout.writeAll("Verwendung: sipctl id <name>\n"),
            else => return err,
        };
        try stdout.flush();
    } else if (std.mem.eql(u8, cmd, "export")) {
        cmdExport(io, stdout, &args) catch |err| switch (err) {
            CliError.MissingArgument => try stdout.writeAll("Verwendung: sipctl export <name>\n"),
            else => return err,
        };
        try stdout.flush();
    } else if (std.mem.eql(u8, cmd, "rm") or std.mem.eql(u8, cmd, "remove") or std.mem.eql(u8, cmd, "delete")) {
        cmdRemove(io, stdout, &args) catch |err| switch (err) {
            CliError.MissingArgument => try stdout.writeAll("Verwendung: sipctl rm <name>\n"),
            else => return err,
        };
        try stdout.flush();
    } else if (std.mem.eql(u8, cmd, "passwd")) {
        cmdPasswd(io, stdout, init.environ_map, &args) catch |err| switch (err) {
            CliError.MissingArgument => try stdout.writeAll("Verwendung: sipctl passwd <name>\n"),
            else => return err,
        };
        try stdout.flush();
    } else {
        try stdout.print("Unbekannter Befehl: '{s}'\n", .{cmd});
        try stdout.writeAll("Siehe 'sipctl --help' für Hilfe.\n");
        try stdout.flush();
    }
}
