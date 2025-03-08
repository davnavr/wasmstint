const std = @import("std");
const Build = std.Build;
const Step = Build.Step;

const executable_paths = .{
    .run_wast = .{ "wasmstint-wast", "src/wast_main.zig" },
};

const executable_paths_fields =
    @typeInfo(@TypeOf(executable_paths)).@"struct".fields;

const Executables = @Type(.{
    .@"struct" = std.builtin.Type.Struct{
        .backing_integer = null,
        .layout = .auto,
        .is_tuple = false,
        .decls = &.{},
        .fields = fields: {
            var fields: [executable_paths_fields.len]std.builtin.Type.StructField = undefined;
            for (&fields, executable_paths_fields) |*dst, *src| {
                dst.* = std.builtin.Type.StructField{
                    .name = src.name,
                    .type = *Step.Compile,
                    .alignment = 0,
                    .default_value_ptr = null,
                    .is_comptime = false,
                };
            }

            break :fields &fields;
        },
    },
});

pub fn build(b: *Build) error{OutOfMemory}!void {
    const proj_options = .{
        .target = b.standardTargetOptions(.{}),
        .optimize = b.standardOptimizeOption(.{}),
    };

    const path_options = .{
        .cargo = b.option(
            []const u8,
            "cargo",
            "Path to cargo executable",
        ) orelse "cargo",

        // .afl_fuzz = b.option(
        //     []const u8,
        //     "afl-fuzz",
        //     "Path to afl-fuzz executable",
        // ) orelse "afl-fuzz",

        .afl_clang_lto = b.option(
            []const u8,
            "afl-clang-lto",
            "Path to afl-clang-lto executable",
        ) orelse "afl-clang-lto",

        .afl_driver = b.option(
            []const u8,
            "afl-driver",
            "Path to the AFLDriver library (e.g. libAFLDriver.a)",
        ) orelse std.fs.realpathAlloc(
            b.allocator,
            "/usr/local/lib/afl/libAFLDriver.a",
        ) catch |e| switch (e) {
            error.OutOfMemory => |oom| return oom,
            else => null,
        },
    };

    const steps = .{
        .check = b.step("check", "Check for compilation errors"),

        .run_wast = b.step("run-wast", "Run the specification test interpreter"),
        // .run_wasip1 = b.step("run-wasip1", "Run the WASI (preview 1) application interpreter",),

        .@"test" = b.step("test", "Run all unit and specification tests"),
        .test_unit = b.step("test-unit", "Run unit tests"),
        .test_spec = b.step("test-spec", "Run some specification tests"),

        .fuzz_rust_afl = b.step("fuzz-rust-afl", "Build wasm-smith fuzz tests using afl-clang-lto"),
    };

    const wasmstint_module = b.addModule(
        "wasmstint",
        .{ .root_source_file = b.path("src/root.zig") },
    );

    const executables: Executables = exes: {
        var exes_result: Executables = undefined;

        inline for (executable_paths_fields) |*exe_field| {
            const exe_spec: [2][]const u8 = @field(executable_paths, exe_field.name);
            const exe = b.addExecutable(.{
                .name = exe_spec[0],
                .root_module = b.createModule(.{
                    .root_source_file = b.path(exe_spec[1]),
                    .target = proj_options.target,
                    .optimize = proj_options.optimize,
                }),
            });

            exe.root_module.addImport("wasmstint", wasmstint_module);

            const run = b.addRunArtifact(exe);
            if (b.args) |args| {
                run.addArgs(args);
            }

            Step.dependOn(@field(steps, exe_field.name), &run.step);
            @field(exes_result, exe_field.name) = exe;
        }

        break :exes exes_result;
    };

    const unit_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/root.zig"),
            .target = proj_options.target,
            .optimize = proj_options.optimize,
        }),
    });

    const unit_tests_run = b.addRunArtifact(unit_tests);
    steps.test_unit.dependOn(&unit_tests_run.step);

    {
        const run_spec_tests_cmd = b.addRunArtifact(executables.run_wast);
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
            "tests/spec/conversions.wast",
            "tests/spec/custom.wast",
            "tests/spec/data.wast",
            "tests/spec/elem.wast",
            "tests/spec/endianness.wast",
            "tests/spec/exports.wast",
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
            "tests/spec/float_misc.wast",
            "tests/spec/forward.wast",
            "tests/spec/func_ptrs.wast",
            "tests/spec/func.wast",
            "tests/spec/global.wast",
            "tests/spec/i32.wast",
            "tests/spec/i64.wast",
            "tests/spec/if.wast",
            "tests/spec/imports.wast",
            // "tests/spec/inline-module.wast", // TODO: parser doesn't support inline modules
            "tests/spec/int_exprs.wast",
            "tests/spec/int_literals.wast",
            "tests/spec/labels.wast",
            "tests/spec/left-to-right.wast",
            "tests/spec/linking.wast",
            "tests/spec/load.wast",
            "tests/spec/local_get.wast",
            "tests/spec/local_set.wast",
            "tests/spec/local_tee.wast",
            "tests/spec/loop.wast",
            "tests/spec/memory_copy.wast",
            "tests/spec/memory_fill.wast",
            "tests/spec/memory_grow.wast",
            "tests/spec/memory_init.wast",
            "tests/spec/memory_redundancy.wast",
            "tests/spec/memory_size.wast",
            "tests/spec/memory_trap.wast",
            "tests/spec/memory.wast",
            "tests/spec/names.wast",
            "tests/spec/nop.wast",
            "tests/spec/obsolete-keywords.wast", // Currently skipped
            "tests/spec/ref_func.wast",
            "tests/spec/ref_is_null.wast",
            "tests/spec/ref_null.wast",
            "tests/spec/return.wast",
            "tests/spec/select.wast",

            // simd_*.wast tests are skipped as 128-bit SIMD is not yet supported

            "tests/spec/skip-stack-guard-page.wast",
            "tests/spec/stack.wast",
            "tests/spec/start.wast",
            "tests/spec/store.wast",
            "tests/spec/switch.wast",
            "tests/spec/table_copy.wast",
            "tests/spec/table_fill.wast",
            "tests/spec/table_get.wast",
            "tests/spec/table_set.wast",
            "tests/spec/table_size.wast",
            "tests/spec/table-sub.wast", // Currently skipped
            "tests/spec/table.wast",
            "tests/spec/token.wast",
            "tests/spec/traps.wast",
            "tests/spec/type.wast",
            "tests/spec/unreachable.wast",
            "tests/spec/unreached-invalid.wast", // Currently skipped
            "tests/spec/unreached-valid.wast",
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

        if (b.args) |args| {
            run_spec_tests_cmd.addArgs(args);
        }

        steps.test_spec.dependOn(&run_spec_tests_cmd.step);
    }

    steps.@"test".dependOn(steps.test_unit);
    steps.@"test".dependOn(steps.test_spec);

    const rust_target: ?[]const u8 = b.option(
        []const u8,
        "rust-target",
        "The Rust target triple",
    );

    const missing_rust_target = rust_target == null and
        !proj_options.target.query.isNativeTriple();

    const rust_fuzz_lib_name = try std.mem.concat(
        b.allocator,
        u8,
        &.{
            proj_options.target.result.libPrefix(),
            "wasmstint_fuzz",
            proj_options.target.result.staticLibSuffix(),
        },
    );

    const cargo_build = b.addSystemCommand(&.{ path_options.cargo, "build" });
    cargo_build.disable_zig_progress = true;
    cargo_build.addArgs(&.{ "--message-format", "short" });

    cargo_build.addArg("--manifest-path");
    cargo_build.addFileArg(b.path("fuzz/wasm-smith/Cargo.toml"));

    const cargo_target_dir = b.path("fuzz/wasm-smith/target/debug");

    if (rust_target) |rust_triple| {
        cargo_build.addArgs(&.{ "--target", rust_triple });
    }

    const cargo_artifact_dir = if (rust_target) |rust_triple|
        cargo_target_dir.path(b, rust_triple)
    else
        cargo_target_dir;

    const rust_fuzz_lib = cargo_artifact_dir.path(b, rust_fuzz_lib_name);

    const rust_fuzz_harness = b.createModule(.{
        .root_source_file = b.path("fuzz/wasm-smith/src/harness.zig"),
        .target = proj_options.target,
        .optimize = proj_options.optimize,
    });

    const rust_fuzz_target_module = b.createModule(.{
        .root_source_file = b.path("fuzz/wasm-smith/targets/execute.zig"),
        .target = proj_options.target,
        .optimize = proj_options.optimize,
    });
    rust_fuzz_target_module.addImport("harness", rust_fuzz_harness);
    rust_fuzz_target_module.addImport("wasmstint", wasmstint_module);

    const rust_fuzz_target = b.addLibrary(.{
        .name = "execute",
        .root_module = rust_fuzz_target_module,
        .linkage = .static,
    });
    rust_fuzz_target.sanitize_coverage_trace_pc_guard = true;

    // https://www.ryanliptak.com/blog/fuzzing-zig-code/#treating-zig-code-as-a-static-library
    rust_fuzz_target.want_lto = true;
    rust_fuzz_target.bundle_compiler_rt = true;
    rust_fuzz_target.pie = true;

    const build_rust_fuzz = b.addSystemCommand(&.{path_options.afl_clang_lto});
    if (missing_rust_target) {
        build_rust_fuzz.step.dependOn(&b.addFail("-Drust-target=... is required").step);
    } else {
        build_rust_fuzz.step.dependOn(&rust_fuzz_target.step);
        build_rust_fuzz.step.dependOn(&cargo_build.step);
    }

    build_rust_fuzz.addArg("-o");
    const rust_fuzz_target_exe = build_rust_fuzz.addOutputFileArg(rust_fuzz_target.name);

    build_rust_fuzz.addFileArg(rust_fuzz_lib);
    build_rust_fuzz.addFileArg(rust_fuzz_target.getEmittedBin());

    if (path_options.afl_driver) |afl_driver_lib| {
        build_rust_fuzz.addArg(afl_driver_lib);
    } else {
        build_rust_fuzz.step.dependOn(&b.addFail("-Dafl-driver=... is required").step);
    }

    const fuzz_exe_dir = Build.InstallDir{ .custom = "fuzz" };
    const install_rust_fuzz = b.addInstallFileWithDir(
        rust_fuzz_target_exe,
        fuzz_exe_dir,
        rust_fuzz_target.name,
    );

    steps.fuzz_rust_afl.dependOn(&install_rust_fuzz.step);

    // const afl_fuzz = b.addSystemCommand(&.{path_options.afl_fuzz});
    // if (path_options.afl_driver == null) {
    //     afl_fuzz.step.dependOn(&b.addFail("-Dafl-driver=... is required").step);
    // }
    // // TODONT: -i and -o params
    // if (b.args) |args| {
    //     afl_fuzz.addArgs(args);
    // } else {
    //     afl_fuzz.addArgs(&.{ "-m", "4", "-V", "30", "-g", "16" });
    // }
    // afl_fuzz.addArg("--");
    // afl_fuzz.addFileArg(rust_fuzz_target_exe);
}
