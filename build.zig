const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const sip_dep = b.dependency("sip", .{
        .target = target,
        .optimize = optimize,
    });

    const sip_mod = sip_dep.module("sip");

    const siputils_mod = b.addModule("siputils", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "sip", .module = sip_mod },
        },
    });

    // ─────────────────────────────────────────────
    // sipd
    // ─────────────────────────────────────────────

    const sipd_mod = b.addModule("sipd", .{
        .root_source_file = b.path("src/sipd.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "sip", .module = sip_mod },
            .{ .name = "siputils", .module = siputils_mod },
        },
    });

    // ─────────────────────────────────────────────
    // sipctl
    // ─────────────────────────────────────────────

    const sipctl_mod = b.createModule(.{
        .root_source_file = b.path("src/sipctl.zig"),
        .target = target,
        .optimize = optimize,
    });

    sipctl_mod.addImport("sip", sip_mod);
    sipctl_mod.addImport("siputils", siputils_mod);

    const sipctl = b.addExecutable(.{
        .name = "sipctl",
        .root_module = sipctl_mod,
    });

    b.installArtifact(sipctl);

    const run_sipctl = b.addRunArtifact(sipctl);
    run_sipctl.step.dependOn(b.getInstallStep());

    if (b.args) |args| run_sipctl.addArgs(args);

    b.step("run-sipctl", "Run sipctl")
        .dependOn(&run_sipctl.step);

    // ─────────────────────────────────────────────
    // sipreq
    // ─────────────────────────────────────────────

    const sipreq_mod = b.createModule(.{
        .root_source_file = b.path("src/template/sipreq.zig"),
        .target = target,
        .optimize = optimize,
    });

    sipreq_mod.addImport("sip", sip_mod);
    sipreq_mod.addImport("siputils", siputils_mod);

    const sipreq = b.addExecutable(.{
        .name = "sipreq",
        .root_module = sipreq_mod,
    });

    b.installArtifact(sipreq);

    const run_sipreq = b.addRunArtifact(sipreq);
    run_sipreq.step.dependOn(b.getInstallStep());

    if (b.args) |args| run_sipctl.addArgs(args);

    b.step("run-sipreq", "Run sipreq")
        .dependOn(&run_sipreq.step);

    // ─────────────────────────────────────────────
    // server
    // ─────────────────────────────────────────────
    const server_mod = b.createModule(.{
        .root_source_file = b.path("src/template/server.zig"),
        .target = target,
        .optimize = optimize,
    });

    server_mod.addImport("sip", sip_mod);
    server_mod.addImport("siputils", siputils_mod);
    server_mod.addImport("sipd", sipd_mod);

    const server = b.addExecutable(.{
        .name = "server",
        .root_module = server_mod,
    });

    b.installArtifact(server);

    const run_server = b.addRunArtifact(server);
    run_server.step.dependOn(b.getInstallStep());

    if (b.args) |args| run_server.addArgs(args);

    b.step("run-server", "Run server")
        .dependOn(&run_server.step);

    // ─────────────────────────────────────────────
    // cmdhandler
    // ─────────────────────────────────────────────
    const cmd_mod = b.createModule(.{
        .root_source_file = b.path("src/cmdhandler.zig"),
        .target = target,
        .optimize = optimize,
    });

    cmd_mod.addImport("sip", sip_mod);
    cmd_mod.addImport("siputils", siputils_mod);

    // ─────────────────────────────────────────────
    // sniffer
    // ─────────────────────────────────────────────

    const discover_mod = b.createModule(.{
        .root_source_file = b.path("src/template/sniffer.zig"),
        .target = target,
        .optimize = optimize,
    });

    discover_mod.addImport("sip", sip_mod);
    discover_mod.addImport("siputils", siputils_mod);

    const sniffer = b.addExecutable(.{
        .name = "sniffer",
        .root_module = discover_mod,
    });

    b.installArtifact(sniffer);

    const run_sniffer = b.addRunArtifact(sniffer);
    run_sniffer.step.dependOn(b.getInstallStep());

    if (b.args) |args| run_sniffer.addArgs(args);

    b.step("run-sniffer", "Run sniffer")
        .dependOn(&run_sniffer.step);
}
