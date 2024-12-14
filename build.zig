const std = @import("std");

pub fn build(b: *std.Build) void {
    const proj_options = .{
        .target = b.standardTargetOptions(.{}),
        .optimize = b.standardOptimizeOption(.{}),
    };

    const steps = .{
        .check = b.step("check", "Check for compilation errors"),
        .run_wast = b.step("run-wast", "Run the specification test interpreter"),
    };

    const run_wast_exe = b.addExecutable(.{
        .name = "wasmstint-wast",
        .root_source_file = b.path("src/tools/run_wast.zig"),
        .target = proj_options.target,
        .optimize = proj_options.optimize,
    });

    const run_wast_cmd = b.addRunArtifact(run_wast_exe);
    if (b.args) |args| {
        run_wast_cmd.addArgs(args);
    }

    steps.run_wast.dependOn(&run_wast_cmd.step);

    steps.check.dependOn(&run_wast_exe.step);
}
