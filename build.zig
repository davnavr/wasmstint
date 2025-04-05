const std = @import("std");
const OomError = std.mem.Allocator.Error;
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

const fuzz_target_paths = [_][:0]const u8{
    "fuzz/wasm-smith/targets/execute.zig",
    "fuzz/wasm-smith/targets/wasmi_differential.zig",
    // "fuzz/wasm-smith/targets/raw_validate.zig",
};

const FuzzTarget = @Type(.{
    .@"enum" = std.builtin.Type.Enum{
        .tag_type = std.math.IntFittingRange(0, fuzz_target_paths.len),
        .decls = &.{},
        .is_exhaustive = true,
        .fields = fields: {
            var fields: [fuzz_target_paths.len]std.builtin.Type.EnumField = undefined;
            for (0.., &fields, fuzz_target_paths) |i, *dst, src| {
                dst.* = std.builtin.Type.EnumField{
                    .name = std.fs.path.stem(src) ++ "\x00",
                    .value = i,
                };
            }

            break :fields &fields;
        },
    },
});

const ProjectOptions = struct {
    target: Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    rust_target: ?[]const u8,
    fuzz_targets: std.enums.EnumSet(FuzzTarget),

    fn init(b: *Build) ProjectOptions {
        return .{
            .target = b.standardTargetOptions(.{}),
            .optimize = b.standardOptimizeOption(.{}),
            .rust_target = b.option(
                []const u8,
                "rust-target",
                "Sets the Rust target triple",
            ),
            .fuzz_targets = if (b.option(
                []const FuzzTarget,
                "fuzz-targets",
                "Which fuzz targets will be built",
            )) |targets| .initMany(targets) else .initFull(),
        };
    }
};

const PathOptions = struct {
    cargo: []const u8,
    @"afl-clang-lto": []const u8,

    fn init(b: *Build) PathOptions {
        var options: PathOptions = undefined;

        inline for (@typeInfo(PathOptions).@"struct".fields) |field| {
            @field(options, field.name) = b.option(
                []const u8,
                field.name,
                "Path to " ++ field.name ++ " executable",
            ) orelse field.name;
        }

        return options;
    }
};

const WasmstintModule = struct {
    module: *Build.Module,

    fn build(b: *Build, proj_opts: *const ProjectOptions) WasmstintModule {
        return .{
            .module = b.addModule(
                "wasmstint",
                .{
                    .root_source_file = b.path("src/root.zig"),
                    .target = proj_opts.target,
                    .optimize = proj_opts.optimize,
                },
            ),
        };
    }

    fn addAsImportTo(wasmstint: *const WasmstintModule, to: *Build.Module) void {
        to.addImport("wasmstint", wasmstint.module);
    }
};

const RustFuzzLib = struct {
    step: *Build.Step,
    path: Build.LazyPath,

    fn build(
        b: *Build,
        proj_opts: *const ProjectOptions,
        path_opts: *const PathOptions,
    ) OomError!RustFuzzLib {
        const cargo = b.addSystemCommand(&.{ path_opts.cargo, "build", "--profile", "dev" });
        cargo.disable_zig_progress = true;

        const lib_name = try std.mem.concat(
            b.allocator,
            u8,
            &.{
                proj_opts.target.result.libPrefix(),
                "wasmstint_rust_fuzz",
                proj_opts.target.result.staticLibSuffix(),
            },
        );

        if (proj_opts.rust_target) |rust_target| {
            cargo.addArgs(&.{ "--target", rust_target });
        } else if (!proj_opts.target.query.isNativeTriple()) {
            cargo.step.dependOn(&b.addFail("-Drust-target=... is required when cross compiling").step);
        }

        if (b.verbose) {
            cargo.addArg("--verbose");
        } else {
            cargo.addArgs(&.{ "--message-format", "short" });
        }

        cargo.addArg("--manifest-path");
        cargo.addFileArg(b.path("fuzz/wasm-smith/Cargo.toml"));

        const target_dir = b.path("fuzz/wasm-smith/target");
        cargo.addArg("--target-dir"); // TODO: Allow overriding target directory in options
        cargo.addDirectoryArg(target_dir);

        const profile_dir = target_dir.path(b, "debug");
        const artifact_dir = if (proj_opts.rust_target) |rust_target|
            profile_dir.path(b, rust_target)
        else
            profile_dir;

        return .{
            .step = &cargo.step,
            .path = artifact_dir.path(b, lib_name),
        };
    }

    fn addRunFileArgTo(lib: *const RustFuzzLib, run: *Build.Step.Run) void {
        run.step.dependOn(lib.step);
        run.addFileArg(lib.path);
    }

    fn addObjectFileToCompile(lib: *const RustFuzzLib, compile: *Build.Step.Compile) void {
        compile.step.dependOn(lib.step);
        compile.addObjectFile(lib.path);
    }
};

const RustFuzzTargetHarness = struct {
    module: *Build.Module,

    fn build(
        b: *Build,
        proj_opts: *const ProjectOptions,
        wasmstint: WasmstintModule,
    ) RustFuzzTargetHarness {
        const module = b.createModule(.{
            .root_source_file = b.path("fuzz/wasm-smith/src/harness.zig"),
            .target = proj_opts.target,
            .optimize = switch (proj_opts.optimize) {
                .Debug, .ReleaseSafe => |same| same,
                else => .ReleaseSafe,
            },
            .error_tracing = true,
        });
        wasmstint.addAsImportTo(module);
        return .{ .module = module };
    }

    fn buildTarget(
        harness: RustFuzzTargetHarness,
        b: *Build,
        proj_opts: *const ProjectOptions,
        wasmstint: WasmstintModule,
        name: []const u8,
        root_source_file: Build.LazyPath,
    ) RustFuzzTarget {
        const target_module = b.createModule(.{
            .root_source_file = root_source_file,
            .target = proj_opts.target,
            .optimize = harness.module.optimize orelse proj_opts.optimize,
            .omit_frame_pointer = false,
            .error_tracing = true,
        });

        target_module.addImport("harness", harness.module);
        wasmstint.addAsImportTo(target_module);

        const target_lib = b.addLibrary(.{
            .name = name,
            .root_module = target_module,
            .linkage = .static,
            .use_llvm = true,
        });

        if (proj_opts.optimize == .Debug) {
            target_lib.step.dependOn(&b.addFail("--release[=mode] is required for fuzz targets").step);
        }

        // https://www.ryanliptak.com/blog/fuzzing-zig-code/#treating-zig-code-as-a-static-library
        target_lib.want_lto = true;
        target_lib.bundle_compiler_rt = true;
        target_lib.pie = true;
        // target_lib.sanitize_coverage_trace_pc_guard = true; // Not needed in AFL LTO mode?

        return .{ .lib = target_lib };
    }
};

const RustFuzzTarget = struct {
    lib: *Build.Step.Compile,

    fn installAflExecutable(
        target: *const RustFuzzTarget,
        b: *Build,
        proj_opts: *const ProjectOptions,
        path_opts: *const PathOptions,
        rust_fuzz_lib: *const RustFuzzLib,
        install_dir: Build.InstallDir,
    ) *Build.Step.InstallFile {
        const afl_lto = b.addSystemCommand(&.{ path_opts.@"afl-clang-lto", "-g", "-Wall", "-fsanitize=fuzzer" });
        afl_lto.disable_zig_progress = true;
        if (!proj_opts.target.query.isNativeTriple()) {
            afl_lto.step.dependOn(&b.addFail("cannot build AFL fuzz executable for non-native target").step);
        } else {
            // afl_lto.step.dependOn(&target.lib.step);
            rust_fuzz_lib.addRunFileArgTo(afl_lto);
        }

        afl_lto.addArtifactArg(target.lib);

        if (b.verbose) {
            afl_lto.addArg("-v");
        }

        afl_lto.addArg("-o");
        const target_exe = afl_lto.addOutputFileArg(target.lib.name);

        return b.addInstallFileWithDir(
            target_exe,
            install_dir,
            target.lib.name,
        );
    }

    fn installDebugExecutable(
        target: *const RustFuzzTarget,
        b: *Build,
        proj_opts: *const ProjectOptions,
        wasmstint: WasmstintModule,
        rust_fuzz_harness: RustFuzzTargetHarness,
        rust_fuzz_lib: *const RustFuzzLib,
        install_dir: Build.InstallDir,
    ) OomError!*Build.Step.InstallArtifact {
        const exe = b.addExecutable(.{
            .name = try std.mem.concat(
                b.allocator,
                u8,
                &.{ target.lib.name, "-debug" },
            ),
            .root_module = b.createModule(.{
                .root_source_file = b.path("fuzz/wasm-smith/src/runner_main.zig"),
                .target = proj_opts.target,
                .optimize = proj_opts.optimize,
                // This seems to interfere with Zig's panic handler when Zig code is not in one exe/lib
                // The workaround is to put all Zig code in the one exe
                .link_libcpp = true, // Required by Rust's panic infrastructure (libunwind)
            }),
        });

        exe.bundle_compiler_rt = true;
        exe.root_module.addImport("target", target.lib.root_module);
        exe.root_module.addImport("harness", rust_fuzz_harness.module);
        wasmstint.addAsImportTo(exe.root_module);

        if (!proj_opts.target.query.isNativeTriple() and proj_opts.rust_target == null) {
            exe.step.dependOn(&b.addFail("-Drust-target=... is required when cross compiling").step);
        }

        rust_fuzz_lib.addObjectFileToCompile(exe);

        return b.addInstallArtifact(
            exe,
            .{ .dest_dir = .{ .override = install_dir } },
        );
    }
};

pub fn build(b: *Build) OomError!void {
    const project_options = ProjectOptions.init(b);
    const path_options = PathOptions.init(b);

    const steps = .{
        // .check = b.step("check", "Check for compilation errors"),

        .run_wast = b.step("run-wast", "Run the specification test interpreter"),
        // .run_wasip1 = b.step("run-wasip1", "Run the WASI (preview 1) application interpreter",),

        .@"test" = b.step("test", "Run all unit and specification tests"),
        .test_unit = b.step("test-unit", "Run unit tests"),
        .test_spec = b.step("test-spec", "Run some specification tests"),

        .fuzz_rust_afl = b.step("fuzz-rust-afl", "Build wasm-smith fuzz tests using afl-clang-lto"),
        .fuzz_rust_debug = b.step("fuzz-rust-debug", "Build runners for wasm-smith fuzz tests"),
    };

    const wasmstint_module = WasmstintModule.build(b, &project_options);

    const executables: Executables = exes: {
        var exes_result: Executables = undefined;

        inline for (executable_paths_fields) |*exe_field| {
            const exe_spec: [2][]const u8 = @field(executable_paths, exe_field.name);
            const exe = b.addExecutable(.{
                .name = exe_spec[0],
                .root_module = b.createModule(.{
                    .root_source_file = b.path(exe_spec[1]),
                    .target = project_options.target,
                    .optimize = project_options.optimize,
                }),
            });

            wasmstint_module.addAsImportTo(exe.root_module);

            const run = b.addRunArtifact(exe);
            if (b.args) |args| {
                run.addArgs(args);
            }

            Step.dependOn(@field(steps, exe_field.name), &run.step);
            @field(exes_result, exe_field.name) = exe;
        }

        break :exes exes_result;
    };

    const unit_tests = b.addTest(.{ .root_module = wasmstint_module.module });

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

    const rust_fuzz_lib = try RustFuzzLib.build(b, &project_options, &path_options);
    const rust_fuzz_harness = RustFuzzTargetHarness.build(b, &project_options, wasmstint_module);

    const fuzz_exe_dir = Build.InstallDir{ .custom = "fuzz" };
    var fuzz_targets_iter = project_options.fuzz_targets.iterator();
    while (fuzz_targets_iter.next()) |fuzz_target| {
        const fuzz_execute_target = rust_fuzz_harness.buildTarget(
            b,
            &project_options,
            wasmstint_module,
            @tagName(fuzz_target),
            b.path(fuzz_target_paths[@intFromEnum(fuzz_target)]),
        );

        steps.fuzz_rust_afl.dependOn(
            &fuzz_execute_target.installAflExecutable(
                b,
                &project_options,
                &path_options,
                &rust_fuzz_lib,
                fuzz_exe_dir,
            ).step,
        );

        steps.fuzz_rust_debug.dependOn(
            &(try fuzz_execute_target.installDebugExecutable(
                b,
                &project_options,
                wasmstint_module,
                rust_fuzz_harness,
                &rust_fuzz_lib,
                fuzz_exe_dir,
            )).step,
        );
    }

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
