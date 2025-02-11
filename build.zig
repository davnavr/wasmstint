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
        .test_spec = b.step("test-spec", "Run all specification tests (that are currently expected to pass)"),
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

    {
        const run_spec_tests_cmd = b.addRunArtifact(run_wast_exe);
        const tests = [_][]const u8{
            "tests/spec/address.wast",
            "tests/spec/align.wast",
            "tests/spec/binary-leb128.wast",
            "tests/spec/binary.wast",
            "tests/spec/block.wast",
            "tests/spec/br_if.wast",
            "tests/spec/br_table.wast",
            "tests/spec/br.wast",
            "tests/spec/bulk.wast",
            "tests/spec/call_indirect.wast",
            "tests/spec/call.wast",
            // "tests/spec/comment.wast", // TODO: pending support for module fields as abbreviation for module
            // "tests/spec/const.wast", // TODO: need to fix float literal parsing
            // "tests/spec/conversions.wast",  // TODO: need to detect when @intFromFloat would cause a panic
            "tests/spec/custom.wast",
            // "tests/spec/data.wast", // TODO: some keyword is incorrectly parsed as an instruction
            // "tests/spec/elem.wast", // TODO: parser needs support for non-inline imports and assert_trap on modules
            "tests/spec/endianness.wast",
            // "tests/spec/exports.wast", // TODO: parser needs support for non-inline exports
            "tests/spec/f32_bitwise.wast",
            "tests/spec/f32_cmp.wast",
            "tests/spec/f32.wast",
            "tests/spec/f64_bitwise.wast",
            "tests/spec/f64_cmp.wast",
            "tests/spec/f64.wast",
            "tests/spec/fac.wast",
            "tests/spec/float_exprs.wast",
            "tests/spec/float_literals.wast",
            "tests/spec/float_memory.wast",
            // "tests/spec/float_misc.wast", // TODO: rounding error in f32.nearest implementation caused by not picking the even when tied
            "tests/spec/forward.wast",
            // "tests/spec/func_ptrs.wast", // TODO: blocked on non-inline import parsing
            // "tests/spec/func.wast", // TODO: encoder should skip empty local groups instead of crashing.
            // "tests/spec/global.wast", // TODO: blocked on non-inline import parsing
            "tests/spec/i32.wast",
            "tests/spec/i64.wast",
            "tests/spec/if.wast",
            // "tests/spec/imports.wast", // TODO: blocked on non-inline import parsing and `assert_unlinkable` support
            // "tests/spec/inline-module.wast", // TODO: parser doesn't support inline modules
            "tests/spec/int_exprs.wast",
            "tests/spec/int_literals.wast",
            "tests/spec/labels.wast",
            "tests/spec/left-to-right.wast",
            // "tests/spec/linking.wast", // TODO: export and imports not yet supported by parser
            "tests/spec/load.wast",
            "tests/spec/local_get.wast",
            "tests/spec/local_set.wast",
            "tests/spec/local_tee.wast",
            "tests/spec/loop.wast",
            "tests/spec/memory_copy.wast", // passes with --fuel 1_048_263 (~15 instructions per byte, with 65536 bytes)
            "tests/spec/memory_fill.wast",
            // "tests/spec/memory_grow.wast", // TODO: parsing non-inline imports
            "tests/spec/memory_init.wast",
            "tests/spec/memory_redundancy.wast",
            // "tests/spec/memory_size.wast", // TODO: OOM, due to hard-coded limit in allocator
            "tests/spec/memory_trap.wast",
            "tests/spec/memory.wast",
            // "tests/spec/names.wast", // TODO: export and imports not yet supported by parser
            "tests/spec/nop.wast",
            "tests/spec/obsolete-keywords.wast", // Currently skipped
            // "tests/spec/ref_func.wast", // TODO: export and start field parsing
            // "tests/spec/ref_is_null.wast", // TODO: ref.null result parser
            // "tests/spec/ref_null.wast", // TODO: ref.null result parser
            "tests/spec/return.wast",
            // "tests/spec/select.wast", // TODO: ref.null result parser

            // simd_*.wast tests are skipped as 128-bit SIMD is not yet supported

            // "tests/spec/skip-stack-guard-page.wast", // TODO: parser needs support for non-inline exports
            "tests/spec/stack.wast",
            // "tests/spec/start.wast", // TODO: start field parser
            "tests/spec/store.wast",
            "tests/spec/switch.wast",
            // "tests/spec/table_copy.wast", // TODO: parsing non-inline imports
            // "tests/spec/table_fill.wast", // TODO: ref.null result parser
            // "tests/spec/table_get.wast", // TODO: ref.null result parser
            // "tests/spec/table_set.wast", // TODO: ref.null result parser
            // "tests/spec/table_size.wast", // TODO: Interpreter does not support ref.null and other table instructions
            "tests/spec/table-sub.wast", // Currently skipped
            // "tests/spec/table.wast", // TODO: memory safety issue (OOB) in error message printer
            // "tests/spec/token.wast", // TODO: parsing non-inline imports
            "tests/spec/traps.wast",
            "tests/spec/type.wast",
            "tests/spec/unreachable.wast",
            "tests/spec/unreached-invalid.wast", // Currently skipped
            // "tests/spec/unreached-valid.wast", // TODO: Interpreter support for ref.is_null and maybe more
            "tests/spec/unwind.wast",
            "tests/spec/utf8-custom-section-id.wast", // Currently skipped
            "tests/spec/utf8-import-field.wast", // Currently skipped
            "tests/spec/utf8-import-module.wast", // Currently skipped
            "tests/spec/utf8-invalid-encoding.wast", // Currently skipped
        };

        for (tests) |path| {
            run_spec_tests_cmd.addArg("--run");
            run_spec_tests_cmd.addFileArg(b.path(path));
        }

        if (b.args) |args| run_spec_tests_cmd.addArgs(args);

        steps.test_spec.dependOn(&run_spec_tests_cmd.step);
    }
}
