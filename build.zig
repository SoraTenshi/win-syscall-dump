const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.resolveTargetQuery(.{
        .os_tag = .windows,
    });
    const optimize = b.standardOptimizeOption(.{});

    const args = b.dependency("args", .{ .target = target, .optimize = optimize });

    const load_syscall_table = b.addModule("load-syscall-table", .{
        .root_source_file = b.path("syscalls.zig"),
        .target = target,
        .optimize = optimize,
    });

    const inner_exe = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "args", .module = args.module("args") },
            .{ .name = "syscalls", .module = load_syscall_table },
        },
    });

    const exe = b.addExecutable(.{
        .name = "syscall-dumper",
        .root_module = inner_exe,
    });
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);

    run_cmd.step.dependOn(b.getInstallStep());

    if (b.args) |argss| {
        run_cmd.addArgs(argss);
    }

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);
}
