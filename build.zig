const std = @import("std");

pub fn build(b: *std.Build) void {
    const proj_options = .{
        .target = b.standardTargetOptions(.{}),
        .optimize = b.standardOptimizeOption(.{}),
    };

    const steps = .{
        .check = b.step("check", "Check for compilation errors"),
        .run_wast = b.step("run-wast", "Run the specification test interpreter"),
        .run_wasip1 = b.step("run-wasip1", "Run the WASI (preview 1) application interpreter"),
        // .@"test" = b.step("test", "Run all unit and specification tests"),
        .test_unit = b.step("test-unit", "Run unit tests"),
    };

    const root_mod = b.createModule(.{ .root_source_file = b.path("src/root.zig") });
    const global_allocator_mod = b.createModule(.{ .root_source_file = b.path("src/GlobalAllocator.zig") });

    const run_wast_exe = b.addExecutable(.{
        .name = "wasmstint-wast",
        .root_source_file = b.path("src/tools/run_wast.zig"),
        .target = proj_options.target,
        .optimize = proj_options.optimize,
    });

    run_wast_exe.root_module.addImport("wasmstint", root_mod);
    // run_wast_exe.root_module.addImport("GlobalAllocator", global_allocator_mod);

    const run_wasip1_exe = b.addExecutable(.{
        .name = "wasmstint-wasip1",
        .root_source_file = b.path("src/tools/wasip1.zig"),
        .target = proj_options.target,
        .optimize = proj_options.optimize,
    });

    run_wasip1_exe.root_module.addImport("wasmstint", root_mod);
    run_wasip1_exe.root_module.addImport("GlobalAllocator", global_allocator_mod);

    const run_wast_cmd = b.addRunArtifact(run_wast_exe);
    const run_wasip1_cmd = b.addRunArtifact(run_wasip1_exe);
    if (b.args) |args| {
        run_wast_cmd.addArgs(args);
        run_wasip1_cmd.addArgs(args);
    }

    steps.run_wast.dependOn(&run_wast_cmd.step);
    steps.run_wasip1.dependOn(&run_wasip1_cmd.step);

    steps.check.dependOn(&run_wast_exe.step);
    steps.check.dependOn(&run_wasip1_exe.step);

    const unit_tests = b.addTest(.{
        .root_source_file = b.path("src/root.zig"),
        .target = proj_options.target,
        .optimize = proj_options.optimize,
    });

    const unit_tests_run = b.addRunArtifact(unit_tests);
    steps.test_unit.dependOn(&unit_tests_run.step);
}
