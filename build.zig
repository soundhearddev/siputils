const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const sip_dep = b.dependency("sip", .{
        .target = target,
        .optimize = optimize,
    });

    const sip_mod = sip_dep.module("sip");

    // ─────────────────────────────────────────────
    // sipctl
    // ─────────────────────────────────────────────

    const sipctl_mod = b.createModule(.{
        .root_source_file = b.path("src/sipctl.zig"),
        .target = target,
        .optimize = optimize,
    });

    sipctl_mod.addImport("sip", sip_mod);

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
    // server_test
    // ─────────────────────────────────────────────

    const server_mod = b.createModule(.{
        .root_source_file = b.path("src/svr_clt_test.zig"),
        .target = target,
        .optimize = optimize,
    });

    server_mod.addImport("sip", sip_mod);

    const server = b.addExecutable(.{
        .name = "server_test",
        .root_module = server_mod,
    });

    b.installArtifact(server);

    const run_server = b.addRunArtifact(server);
    run_server.step.dependOn(b.getInstallStep());

    if (b.args) |args| run_server.addArgs(args);

    b.step("run-server", "Run server_test")
        .dependOn(&run_server.step);

    // ─────────────────────────────────────────────
    // header_test
    // ─────────────────────────────────────────────

    const header_test_mod = b.createModule(.{
        .root_source_file = b.path("src/header_test.zig"),
        .target = target,
        .optimize = optimize,
    });

    header_test_mod.addImport("sip", sip_mod);

    const header_test = b.addExecutable(.{
        .name = "header_test",
        .root_module = header_test_mod,
    });

    b.installArtifact(header_test);

    const run_header_test = b.addRunArtifact(header_test);
    run_header_test.step.dependOn(b.getInstallStep());

    if (b.args) |args| run_header_test.addArgs(args);

    b.step("run-header-test", "Run header_test")
        .dependOn(&run_header_test.step);

    // ─────────────────────────────────────────────
    // discovery_test
    // ─────────────────────────────────────────────

    const discovery_test_mod = b.createModule(.{
        .root_source_file = b.path("src/discovery_test.zig"),
        .target = target,
        .optimize = optimize,
    });

    discovery_test_mod.addImport("sip", sip_mod);

    const discovery_test = b.addExecutable(.{
        .name = "discovery_test",
        .root_module = discovery_test_mod,
    });

    b.installArtifact(discovery_test);

    const run_discovery_test = b.addRunArtifact(discovery_test);
    run_discovery_test.step.dependOn(b.getInstallStep());

    if (b.args) |args| run_discovery_test.addArgs(args);

    b.step("run-discovery-test", "Run discovery_test")
        .dependOn(&run_discovery_test.step);

    // ─────────────────────────────────────────────
    // address
    // ─────────────────────────────────────────────
    const address_mod = b.createModule(.{
        .root_source_file = b.path("src/address.zig"),
        .target = target,
        .optimize = optimize,
    });

    address_mod.addImport("sip", sip_mod);

    const address = b.addExecutable(.{
        .name = "address",
        .root_module = address_mod,
    });

    b.installArtifact(address);

    const run_address = b.addRunArtifact(address);
    run_address.step.dependOn(b.getInstallStep());

    if (b.args) |args| run_address.addArgs(args);

    b.step("run-address", "Run address")
        .dependOn(&run_address.step);

    // ─────────────────────────────────────────────
    // sniffer
    // ─────────────────────────────────────────────

    const discover_mod = b.createModule(.{
        .root_source_file = b.path("src/sniffer.zig"),
        .target = target,
        .optimize = optimize,
    });

    discover_mod.addImport("sip", sip_mod);

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
