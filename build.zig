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
    // registry_viewer
    // ─────────────────────────────────────────────

    const registry_viewer_mod = b.createModule(.{
        .root_source_file = b.path("src/template/registry_viewer.zig"),
        .target = target,
        .optimize = optimize,
    });

    registry_viewer_mod.addImport("sip", sip_mod);
    registry_viewer_mod.addImport("siputils", siputils_mod);

    const registry_viewer = b.addExecutable(.{
        .name = "registry_viewer",
        .root_module = registry_viewer_mod,
    });

    b.installArtifact(registry_viewer);

    const run_registry_viewer = b.addRunArtifact(registry_viewer);
    run_registry_viewer.step.dependOn(b.getInstallStep());

    if (b.args) |args| run_registry_viewer.addArgs(args);

    b.step("run-registry-viewer", "Run registry_viewer")
        .dependOn(&run_registry_viewer.step);

    // ─────────────────────────────────────────────
    // registry_server
    // ─────────────────────────────────────────────

    const registry_server_mod = b.createModule(.{
        .root_source_file = b.path("src/template/registry_server.zig"),
        .target = target,
        .optimize = optimize,
    });

    registry_server_mod.addImport("sip", sip_mod);
    registry_server_mod.addImport("siputils", siputils_mod);

    const registry_server = b.addExecutable(.{
        .name = "registry_server",
        .root_module = registry_server_mod,
    });

    b.installArtifact(registry_server);

    const run_registry_server = b.addRunArtifact(registry_server);
    run_registry_server.step.dependOn(b.getInstallStep());

    if (b.args) |args| run_registry_server.addArgs(args);

    b.step("run-registry-server", "Run registry_server")
        .dependOn(&run_registry_server.step);

    // ─────────────────────────────────────────────
    // registry_client
    // ─────────────────────────────────────────────

    // const registry_client_mod = b.createModule(.{
    //     .root_source_file = b.path("src/template/registry_client.zig"),
    //     .target = target,
    //     .optimize = optimize,
    // });

    // registry_client_mod.addImport("sip", sip_mod);
    // registry_client_mod.addImport("siputils", siputils_mod);

    // const registry_client = b.addExecutable(.{
    //     .name = "registry_client",
    //     .root_module = registry_client_mod,
    // });

    // b.installArtifact(registry_client);

    // const run_registry_client = b.addRunArtifact(registry_client);
    // run_registry_client.step.dependOn(b.getInstallStep());

    // if (b.args) |args| run_registry_client.addArgs(args);

    // b.step("run-registry-client", "Run registry_client")
    //     .dependOn(&run_registry_client.step);

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
    // setdefault
    // ─────────────────────────────────────────────
    const setdefault_mod = b.createModule(.{
        .root_source_file = b.path("src/template/setdefault.zig"),
        .target = target,
        .optimize = optimize,
    });

    setdefault_mod.addImport("sip", sip_mod);
    setdefault_mod.addImport("siputils", siputils_mod);

    const setdefault = b.addExecutable(.{
        .name = "set-default",
        .root_module = setdefault_mod,
    });

    b.installArtifact(setdefault);

    const run_setdefault = b.addRunArtifact(setdefault);
    run_setdefault.step.dependOn(b.getInstallStep());

    if (b.args) |args| run_setdefault.addArgs(args);

    b.step("run-setdefault", "Set default")
        .dependOn(&run_setdefault.step);

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
