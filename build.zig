const std = @import("std");

pub fn build(b: *std.Build) void {
    const proj_options = .{
        .target = b.standardTargetOptions(.{}),
        .optimize = b.standardOptimizeOption(.{}),
    };

    const steps = .{
        .check = b.step("check", "Check for compilation errors"),
        .run_wast = b.step("run-wast", "Run the specification test interpreter"),
        // .@"test" = b.step("test", "Run all unit and specification tests"),
        .test_unit = b.step("test-unit", "Run unit tests"),
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

    const unit_tests = b.addTest(.{
        .root_source_file = b.path("src/root.zig"),
        .target = proj_options.target,
        .optimize = proj_options.optimize,
    });

    const unit_tests_run = b.addRunArtifact(unit_tests);
    steps.test_unit.dependOn(&unit_tests_run.step);
}
