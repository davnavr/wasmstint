const std = @import("std");
const builtin = @import("builtin");
const Build = std.Build;
const Step = Build.Step;

const ProjectOptions = struct {
    target: Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    optimize_interpreter: std.builtin.OptimizeMode,
    use_llvm: packed struct(u2) {
        interpreter: bool,
        other: bool,
    },
    /// Should never be `false`, that would imply `libc` is *prohibited*.
    link_libc: ?bool,
    /// Implies `link_libc`.
    enable_coz: bool,

    fn init(b: *Build) ProjectOptions {
        const optimize = b.standardOptimizeOption(.{});

        const enable_coz = b.option(
            bool,
            "coz",
            "Enable coz profiling counters. Implies -Dlink-libc",
        ) orelse false;

        const link_libc = b.option(
            bool,
            "link-libc",
            "Require linking to the C standard library",
        ) orelse false;

        const Llvm = enum { never, interpreter, always };

        const llvm = b.option(
            Llvm,
            "use-llvm",
            "Specifies when the LLVM backend is used",
        ) orelse if (optimize == .Debug) Llvm.never else .interpreter;

        return .{
            .target = b.standardTargetOptions(.{}),
            .optimize = optimize,
            .optimize_interpreter = b.option(
                std.builtin.OptimizeMode,
                "optimize-interpreter",
                "Override optimization level for interpreter",
            ) orelse optimize,
            .link_libc = if (enable_coz or link_libc) true else null,
            .use_llvm = .{
                .interpreter = llvm != .never,
                .other = llvm == .always,
            },
            .enable_coz = enable_coz,
        };
    }
};

const TopLevelSteps = struct {
    check: *Step,
    @"test": *Step,
    @"test-unit": *Step,
};

const top_level_steps: []const struct { std.meta.FieldEnum(TopLevelSteps), [:0]const u8 } = &.{
    .{ .check, "Check for compilation errors" },
    .{ .@"test", "Run all tests" },
    .{ .@"test-unit", "Run only unit tests" },
};

pub fn build(b: *Build) void {
    const project_options = ProjectOptions.init(b);

    const steps = steps: {
        var init: TopLevelSteps = undefined;
        inline for (top_level_steps) |step| {
            const name = @tagName(step[0]);
            @field(init, name) = b.step(name, step[1]);
        }
        break :steps init;
    };
    steps.@"test".dependOn(steps.@"test-unit");

    var modules = Modules{
        .coz = .build(b, &project_options),
        .sys = .build(b, &project_options),
        .allocators = undefined,
        .file_content = undefined,
        .wasmstint = undefined,
        .cli_args = Modules.CliArgs.build(b, &steps, &project_options),
        .wasip1 = undefined,
        .subprocess = .build(b, &project_options),
    };
    modules.allocators = .build(b, &steps, &project_options, .{ .sys = modules.sys });
    modules.file_content = .build(b, &project_options, .{
        .allocators = modules.allocators,
        .sys = modules.sys,
    });
    modules.wasmstint = .build(
        b,
        &steps,
        &project_options,
        .{ .coz = modules.coz, .allocators = modules.allocators },
    );
    modules.wasip1 = Modules.Wasip1.build(
        b,
        &steps,
        &project_options,
        .{
            .wasmstint = modules.wasmstint,
            .coz = modules.coz,
            .allocators = modules.allocators,
            .sys = modules.sys,
        },
    );

    const spectest_exe = SpectestInterp.build(
        b,
        &steps,
        &project_options,
        .{
            .wasmstint = modules.wasmstint,
            .file_content = modules.file_content,
            .cli_args = modules.cli_args,
            .coz = modules.coz,
            .allocators = modules.allocators,
        },
    );

    const wasip1_exe = Wasip1Interp.build(
        b,
        &steps,
        &project_options,
        .{
            .wasmstint = modules.wasmstint,
            .file_content = modules.file_content,
            .cli_args = modules.cli_args,
            .wasip1 = modules.wasip1,
            .coz = modules.coz,
            .allocators = modules.allocators,
            .sys = modules.sys,
        },
    );

    buildSpecificationTests(b, spectest_exe, &steps);

    // const wasip1_test_runner = Wasip1TestRunner.build(
    //     b,
    //     &steps,
    //     .{ .project = &project_options },
    //     .{
    //         .cli_args = modules.cli_args,
    //         .file_content = modules.file_content,
    //         .interpreter = wasip1_exe,
    //     },
    // );

    buildFuzzers(b, &steps, .{ .project = &project_options }, .{
        .wasmstint = modules.wasmstint,
        .file_content = modules.file_content,
        .cli_args = modules.cli_args,
    });

    buildWasiSamplePrograms(b, &steps, .{ .project = &project_options }, .{
        .interpreter = wasip1_exe,
        .subprocess = modules.subprocess,
    });

    // buildWasiTestsuite(
    //     b,
    //     &steps,
    //     .{ .project = &project_options, .tool_paths = &tool_paths },
    //     .{ .driver = wasip1_test_runner, .interpreter = wasip1_exe },
    // );
}

const ByteSize = packed struct(usize) {
    bytes: usize,

    fn kib(amt: usize) ByteSize {
        return .{ .bytes = amt * 1024 };
    }

    fn mib(amt: usize) ByteSize {
        return .kib(amt * 1024);
    }
};

fn addCheck(
    b: *Build,
    steps: *const TopLevelSteps,
    comptime kind: enum { @"test", exe },
    module: *Build.Module,
    name: []const u8,
    options: struct { max_rss: ByteSize, use_llvm: bool },
) void {
    const Args = switch (kind) {
        .@"test" => Build.TestOptions,
        .exe => Build.ExecutableOptions,
    };

    const args = Args{
        .name = b.fmt("check-{s}", .{name}),
        .root_module = module,
        .max_rss = options.max_rss.bytes,
        .use_llvm = options.use_llvm,
    };

    steps.check.dependOn(switch (kind) {
        .@"test" => &b.addTest(args).step,
        .exe => &b.addExecutable(args).step,
    });
}

const Modules = struct {
    allocators: Allocators,
    sys: Sys,
    file_content: FileContent,
    wasmstint: Wasmstint,
    cli_args: CliArgs,
    wasip1: Wasip1,
    subprocess: Subprocess,
    coz: Coz,

    fn addAsImportTo(comptime T: type, from: T, to: *Build.Module) void {
        to.addImport(T.name, from.module);
    }

    const Allocators = struct {
        module: *Build.Module,

        const name = "allocators";

        fn build(
            b: *Build,
            steps: *const TopLevelSteps,
            options: *const ProjectOptions,
            imports: struct { sys: Sys },
        ) Allocators {
            const module = b.createModule(.{
                .root_source_file = b.path("src/allocators.zig"),
                .target = options.target,
                .optimize = options.optimize,
            });
            addAsImportTo(Sys, imports.sys, module);

            const tests = b.addTest(.{
                .name = name,
                .root_module = module,
                .max_rss = ByteSize.mib(234).bytes,
                .use_llvm = options.use_llvm.other,
            });

            const tests_run = &b.addRunArtifact(tests).step;
            tests_run.max_rss = ByteSize.mib(16).bytes;
            steps.@"test-unit".dependOn(tests_run);

            addCheck(b, steps, .@"test", module, name, .{
                .max_rss = .mib(110),
                .use_llvm = options.use_llvm.other,
            });
            return .{ .module = module };
        }
    };

    const Sys = struct {
        module: *Build.Module,

        const name = "sys";

        fn build(b: *Build, options: *const ProjectOptions) Sys {
            return Sys{
                .module = b.createModule(.{
                    .root_source_file = b.path("src/sys.zig"),
                    .target = options.target,
                    .optimize = options.optimize,
                }),
            };
        }
    };

    const FileContent = struct {
        module: *Build.Module,

        const name = "file_content";

        fn build(
            b: *Build,
            options: *const ProjectOptions,
            imports: struct { allocators: Allocators, sys: Sys },
        ) FileContent {
            const module = b.createModule(.{
                .root_source_file = b.path("src/file_content.zig"),
                .target = options.target,
                .optimize = options.optimize,
            });
            addAsImportTo(Allocators, imports.allocators, module);
            addAsImportTo(Sys, imports.sys, module);

            return .{ .module = module };
        }
    };

    const Wasmstint = struct {
        module: *Build.Module,

        const name = "wasmstint";

        fn build(
            b: *Build,
            steps: *const TopLevelSteps,
            options: *const ProjectOptions,
            imports: struct { coz: Coz, allocators: Allocators },
        ) Wasmstint {
            const module = b.addModule(name, .{
                .root_source_file = b.path("src/root.zig"),
                .target = options.target,
                .optimize = options.optimize_interpreter,
                .link_libc = options.link_libc,
            });
            addAsImportTo(Coz, imports.coz, module);
            addAsImportTo(Allocators, imports.allocators, module);

            const tests = b.addTest(.{
                .name = name,
                .root_module = module,
                // TODO(zig): https://github.com/ziglang/zig/issues/23423
                .use_llvm = true,
                .max_rss = ByteSize.mib(257).bytes,
            });

            const tests_run = &b.addRunArtifact(tests).step;
            tests_run.max_rss = ByteSize.mib(19).bytes;
            steps.@"test-unit".dependOn(tests_run);
            addCheck(b, steps, .@"test", module, name, .{
                .max_rss = .mib(126),
                .use_llvm = options.use_llvm.interpreter,
            });
            return .{ .module = module };
        }
    };

    const CliArgs = struct {
        module: *Build.Module,

        const name = "cli_args";

        fn build(
            b: *Build,
            steps: *const TopLevelSteps,
            options: *const ProjectOptions,
        ) CliArgs {
            const module = b.createModule(.{
                .root_source_file = b.path("src/cli_args.zig"),
                .target = options.target,
                .optimize = options.optimize,
            });

            const tests = b.addTest(.{
                .name = name,
                .root_module = module,
                .use_llvm = options.use_llvm.other,
                .max_rss = ByteSize.mib(236).bytes,
            });

            const tests_run = &b.addRunArtifact(tests).step;
            tests_run.max_rss = ByteSize.mib(16).bytes;
            steps.@"test-unit".dependOn(tests_run);

            addCheck(b, steps, .@"test", module, name, .{
                .max_rss = ByteSize.mib(109),
                .use_llvm = options.use_llvm.other,
            });
            return .{ .module = module };
        }
    };

    const Wasip1 = struct {
        module: *Build.Module,

        const name = "WasiPreview1";

        fn build(
            b: *Build,
            steps: *const TopLevelSteps,
            options: *const ProjectOptions,
            imports: struct { wasmstint: Wasmstint, coz: Coz, allocators: Allocators, sys: Sys },
        ) Wasip1 {
            const module = b.addModule(name, .{
                .root_source_file = b.path("src/WasiPreview1.zig"),
                .target = options.target,
                .optimize = options.optimize,
                .link_libc = options.link_libc,
            });
            addAsImportTo(Wasmstint, imports.wasmstint, module);
            addAsImportTo(Coz, imports.coz, module);
            addAsImportTo(Allocators, imports.allocators, module);
            addAsImportTo(Sys, imports.sys, module);

            const tests = b.addTest(.{
                .name = name,
                .root_module = module,
                .max_rss = ByteSize.mib(219).bytes,
                .use_llvm = options.use_llvm.interpreter,
            });

            const tests_run = &b.addRunArtifact(tests).step;
            tests_run.max_rss = ByteSize.mib(16).bytes;
            steps.@"test-unit".dependOn(tests_run);

            addCheck(b, steps, .@"test", module, name, .{
                .max_rss = .mib(106),
                .use_llvm = options.use_llvm.other,
            });
            return .{ .module = module };
        }
    };

    const Subprocess = struct {
        module: *Build.Module,

        const name = "subprocess";

        fn build(b: *Build, options: *const ProjectOptions) Subprocess {
            const module = b.createModule(.{
                .root_source_file = b.path("src/subprocess.zig"),
                .target = options.target,
                .optimize = options.optimize,
            });

            return .{ .module = module };
        }
    };

    const Coz = struct {
        module: *Build.Module,

        const name = "coz";

        fn build(b: *Build, options: *const ProjectOptions) Coz {
            const module = b.createModule(.{
                .root_source_file = b.path("src/coz.zig"),
                .target = options.target,
                .optimize = options.optimize,
                .link_libc = options.link_libc,
            });

            const coz_options = b.addOptions();
            coz_options.addOption(bool, "enabled", options.enable_coz);
            module.addOptions("options", coz_options);

            return .{ .module = module };
        }
    };
};

const SpectestInterp = struct {
    exe: *Step.Compile,

    fn build(
        b: *Build,
        steps: *const TopLevelSteps,
        proj_opts: *const ProjectOptions,
        imports: struct {
            file_content: Modules.FileContent,
            wasmstint: Modules.Wasmstint,
            cli_args: Modules.CliArgs,
            coz: Modules.Coz,
            allocators: Modules.Allocators,
        },
    ) SpectestInterp {
        const module = b.createModule(.{
            .root_source_file = b.path("src/spectest/main.zig"),
            .target = proj_opts.target,
            .optimize = proj_opts.optimize,
        });
        Modules.addAsImportTo(Modules.FileContent, imports.file_content, module);
        Modules.addAsImportTo(Modules.Wasmstint, imports.wasmstint, module);
        Modules.addAsImportTo(Modules.CliArgs, imports.cli_args, module);
        Modules.addAsImportTo(Modules.Coz, imports.coz, module);
        Modules.addAsImportTo(Modules.Allocators, imports.allocators, module);

        const exe = b.addExecutable(.{
            .name = "wasmstint-spectest",
            .root_module = module,
            .use_llvm = proj_opts.use_llvm.interpreter,
            .max_rss = ByteSize.mib(447).bytes,
        });

        b.getInstallStep().dependOn(&b.addInstallArtifact(exe, .{}).step);

        {
            const run = b.addRunArtifact(exe);
            if (b.args) |args| {
                run.addArgs(args);
            }

            b.step("run-wast", "Run the specification test interpreter").dependOn(&run.step);
        }

        addCheck(b, steps, .exe, module, exe.name, .{
            .max_rss = ByteSize.mib(160),
            .use_llvm = proj_opts.use_llvm.interpreter,
        });

        return .{ .exe = exe };
    }
};

const WabtTools = struct {
    wast2json: *Step.Compile,
};

fn buildWabtTools(b: *Build, wabt_dep: *Build.Dependency) WabtTools {
    const host_os = b.graph.host.result.os;
    const unix_like = @intFromBool(host_os.tag != .windows);
    const config_header = b.addConfigHeader(
        .{
            .style = .{ .cmake = wabt_dep.path("src/config.h.in") },
            .include_path = "wabt/config.h",
        },
        .{
            .WABT_VERSION_STRING = "1.0.39",
            .WABT_DEBUG = null,
            .HAVE_ALLOCA_H = unix_like,
            .HAVE_UNISTD_H = unix_like,
            .HAVE_SNPRINTF = 1,
            .HAVE_SSIZE_T = unix_like,
            .HAVE_STRCASECMP = unix_like,
            .HAVE_WIN32_VT100 = @intFromBool(host_os.isAtLeast(.windows, .win10) == true),
            .WABT_BIG_ENDIAN = builtin.target.cpu.arch.endian() == .big,
            .COMPILER_IS_CLANG = 1,
            .WITH_EXCEPTIONS = 0,
            .SIZEOF_SIZE_T = @sizeOf(usize),
        },
    );
    const flags = &.{
        "-Wall",
        "-Wextra",
        "-Wno-unused-parameter",
        "-Wpointer-arith",
        "-Wuninitialized",
        "-Wimplicit-fallthrough",
        "-fno-exceptions",
    };

    const wabt_lib = b.addLibrary(.{
        .name = "wabt",
        .root_module = b.createModule(.{
            .target = b.graph.host,
            .optimize = .ReleaseSmall,
        }),
        .use_llvm = true,
        .max_rss = ByteSize.mib(500).bytes, // arbitrary value
    });
    wabt_lib.addConfigHeader(config_header);
    wabt_lib.addIncludePath(wabt_dep.path("include"));
    wabt_lib.addCSourceFiles(.{
        .root = wabt_dep.path("."),
        .files = &@import("tools/wabt.zon").src,
        .flags = flags,
    });
    wabt_lib.linkLibCpp();

    const wast2json_exe = b.addExecutable(.{
        .name = "wast2json",
        .root_module = b.createModule(.{
            .target = b.graph.host,
            .optimize = .ReleaseSmall,
        }),
        .use_llvm = true,
        .max_rss = ByteSize.mib(500).bytes, // arbitrary value
    });
    wast2json_exe.addConfigHeader(config_header);
    wast2json_exe.addIncludePath(wabt_dep.path("include"));
    wast2json_exe.addCSourceFile(.{
        .file = wabt_dep.path("src/tools/wast2json.cc"),
        .flags = flags,
    });
    wast2json_exe.linkLibrary(wabt_lib);
    wast2json_exe.linkLibCpp();

    {
        const run = b.addRunArtifact(wast2json_exe);
        if (b.args) |args| {
            run.addArgs(args);
        }
        b.step("run-wast2json", "Run WABT wast2json executable").dependOn(&run.step);
    }

    return WabtTools{ .wast2json = wast2json_exe };
}

fn buildWastTest(
    b: *Build,
    interpreter: SpectestInterp,
    wast_path: Build.LazyPath,
    wabt: WabtTools,
    name: []const u8,
) *Step {
    std.debug.assert(std.mem.endsWith(u8, name, ".wast"));
    var wast2json = b.addRunArtifact(wabt.wast2json);
    wast2json.step.max_rss = ByteSize.mib(19).bytes;
    wast2json.addFileArg(wast_path);
    wast2json.addArgs(&.{"--output"});
    const output_json = wast2json.addOutputFileArg(b.fmt("{s}.json", .{name[0 .. name.len - 5]}));

    const run_test = b.addRunArtifact(interpreter.exe);
    run_test.max_stdio_size = 15 * 1024 * 1024;
    run_test.step.max_rss = ByteSize.mib(45).bytes;
    run_test.setName(name);
    run_test.addArg("--run");
    run_test.addFileArg(output_json);
    run_test.expectExitCode(0);
    return &run_test.step;
}

fn buildSpecificationTests(
    b: *Build,
    interpreter: SpectestInterp,
    top_steps: *const TopLevelSteps,
) void {
    const wabt_dep = b.lazyDependency("wabt", .{}) orelse return;
    const spectest_dep = b.lazyDependency("spectest", .{}) orelse return;
    const wabt = buildWabtTools(b, wabt_dep);

    const test_names: []const []const u8 = &@import("tests/testsuite.zon").names;

    const test_spec_step = b.step("test-spec", "Run specification tests");

    for (test_names) |name| {
        const wast_name = b.fmt("{s}.wast", .{name});
        test_spec_step.dependOn(
            buildWastTest(b, interpreter, spectest_dep.path(wast_name), wabt, wast_name),
        );
    }

    top_steps.@"test".dependOn(test_spec_step);

    const test_fuzzed_step = b.step("test-fuzzed", "Run test cases discovered by fuzzing");
    test_fuzzed_step.dependOn(
        buildWastTest(b, interpreter, b.path("tests/fuzzed/validation.wast"), wabt, "validation.wast"),
    );
    top_steps.@"test".dependOn(test_fuzzed_step);
}

const Wasip1Interp = struct {
    exe: *Step.Compile,

    fn build(
        b: *Build,
        steps: *const TopLevelSteps,
        proj_opts: *const ProjectOptions,
        imports: struct {
            file_content: Modules.FileContent,
            wasmstint: Modules.Wasmstint,
            cli_args: Modules.CliArgs,
            wasip1: Modules.Wasip1,
            coz: Modules.Coz,
            allocators: Modules.Allocators,
            sys: Modules.Sys,
        },
    ) Wasip1Interp {
        const module = b.createModule(.{
            .root_source_file = b.path("src/WasiPreview1/main.zig"),
            .target = proj_opts.target,
            .optimize = proj_opts.optimize,
        });
        Modules.addAsImportTo(Modules.FileContent, imports.file_content, module);
        Modules.addAsImportTo(Modules.Wasmstint, imports.wasmstint, module);
        Modules.addAsImportTo(Modules.CliArgs, imports.cli_args, module);
        Modules.addAsImportTo(Modules.Wasip1, imports.wasip1, module);
        Modules.addAsImportTo(Modules.Coz, imports.coz, module);
        Modules.addAsImportTo(Modules.Allocators, imports.allocators, module);
        Modules.addAsImportTo(Modules.Sys, imports.sys, module);

        const exe = b.addExecutable(.{
            .name = "wasmstint-wasip1",
            .root_module = module,
            .use_llvm = proj_opts.use_llvm.interpreter,
            .max_rss = ByteSize.mib(755).bytes,
        });

        addCheck(b, steps, .exe, module, exe.name, .{
            .max_rss = .mib(175),
            .use_llvm = proj_opts.use_llvm.interpreter,
        });

        {
            const run = b.addRunArtifact(exe);
            if (b.args) |args| {
                run.addArgs(args);
            }
            b.step("run-wasip1", "Run the WASI (preview 1) application interpreter")
                .dependOn(&run.step);
        }

        b.getInstallStep().dependOn(&b.addInstallArtifact(exe, .{}).step);

        return .{ .exe = exe };
    }
};

const Wasip1TestRunner = struct {
    exe: *Build.Step.Compile,

    fn build(
        b: *Build,
        steps: *const TopLevelSteps,
        options: struct { project: *const ProjectOptions },
        modules: struct {
            cli_args: Modules.CliArgs,
            file_content: Modules.FileContent,
            interpreter: Wasip1Interp,
        },
    ) Wasip1TestRunner {
        const module = b.createModule(.{
            .root_source_file = b.path("src/WasiPreview1/test_driver.zig"),
            .target = options.project.target,
            .optimize = options.project.optimize,
        });
        Modules.addAsImportTo(Modules.CliArgs, modules.cli_args, module);
        Modules.addAsImportTo(Modules.FileContent, modules.file_content, module);

        const exe = b.addExecutable(.{
            .name = "wasmstint-wasip1-test",
            .root_module = module,
            .use_llvm = false,
            .max_rss = ByteSize.mib(174).bytes,
        });

        steps.check.dependOn(&exe.step);
        b.getInstallStep().dependOn(&b.addInstallArtifact(exe, .{}).step);

        {
            const step = b.step("run-wasip1-test", "Run WASI testsuite test interpreter");
            const run = b.addRunArtifact(exe);
            run.addArg("--interpreter");
            run.addArtifactArg(modules.interpreter.exe);
            if (b.args) |args| {
                run.addArgs(args);
            }

            step.dependOn(&run.step);
        }

        return .{ .exe = exe };
    }
};

fn buildFuzzers(
    b: *Build,
    steps: *const TopLevelSteps,
    options: struct { project: *const ProjectOptions },
    modules: struct {
        wasmstint: Modules.Wasmstint,
        file_content: Modules.FileContent,
        cli_args: Modules.CliArgs,
    },
) void {
    // const fuzz_zig_step = b.step("fuzz-zig", "Run integrated fuzz tests");
    // fuzz_zig_step.dependOn(
    //     &b.addFail(
    //         "TODO(zig): fix crash in test runner: https://github.com/ziglang/zig/issues/25919",
    //     ).step,
    // );

    {
        const ffi_test = b.addTest(.{
            .root_module = b.createModule(.{
                .root_source_file = b.path("fuzz/ffi/src/ffi.zig"),
                .target = options.project.target,
                .optimize = options.project.optimize,
            }),
            .max_rss = ByteSize.mib(127).bytes,
            .use_llvm = options.project.use_llvm.other,
        });
        const ffi_tests_run = &b.addRunArtifact(ffi_test).step;
        ffi_tests_run.max_rss = ByteSize.mib(10).bytes; // arbitrary amount
        steps.@"test-unit".dependOn(ffi_tests_run);
    }

    const fuzz_step = b.step("fuzz", "Run a fuzz test");

    var rust_include_paths_buf: [2]Build.LazyPath = undefined;
    var rust_include_paths = std.ArrayList(Build.LazyPath).initBuffer(&rust_include_paths_buf);

    // Currently, this does not invoke `cargo build release`
    const rust_target_dir = b.path("fuzz/ffi/target");
    const native_target = b.graph.host.result;
    const chosen_target = options.project.target.result;
    if (native_target.cpu.arch == chosen_target.cpu.arch and
        native_target.os.tag == chosen_target.os.tag and
        native_target.abi == chosen_target.abi)
    {
        rust_include_paths.appendAssumeCapacity(rust_target_dir.path(b, "release"));
    }

    // TODO: translate `chosen_target` to Rust target triple
    //rust_include_paths.appendAssumeCapacity();

    if (rust_include_paths.items.len == 0) {
        fuzz_step.dependOn(
            &b.addFail("could not determine include path for FFI wrapper").step,
        );
    }

    const FuzzTarget = enum {
        validation,
        execution,
    };

    const FuzzRunner = enum {
        afl,
        standalone,
    };

    const fuzz_target = b.option(FuzzTarget, "fuzz-target", "Which fuzz target to run") orelse {
        fuzz_step.dependOn(&b.addFail("Specify fuzz target with -Dfuzz-target").step);
        return;
    };

    const fuzz_runner = b.option(
        FuzzRunner,
        "fuzz-runner",
        "Specifies how a fuzz target is run",
    ) orelse FuzzRunner.standalone;

    const ffi_module = b.createModule(.{
        .root_source_file = b.path("fuzz/ffi/src/ffi.zig"),
        .link_libc = true,
        .target = options.project.target,
        .optimize = options.project.optimize,
    });
    for (rust_include_paths.items) |include_path| {
        ffi_module.addLibraryPath(include_path);
    }

    ffi_module.linkSystemLibrary(
        "wasmstint_fuzz_ffi",
        .{ .preferred_link_mode = .dynamic, .search_strategy = .paths_first },
    );

    const target_module = b.createModule(.{
        .root_source_file = b.path(b.fmt("fuzz/targets/{t}.zig", .{fuzz_target})),
        .target = options.project.target,
        .optimize = options.project.optimize,
    });
    Modules.addAsImportTo(Modules.Wasmstint, modules.wasmstint, target_module);
    target_module.addImport("ffi", ffi_module);

    const libfuzzer_harness_lib = b.addLibrary(.{
        .name = b.fmt("fuzz-{t}-libfuzzer", .{fuzz_target}),
        .root_module = b.createModule(.{
            .root_source_file = b.path("fuzz/harness/libfuzzer.zig"),
            .target = options.project.target,
            .optimize = options.project.optimize,
        }),
        .max_rss = ByteSize.mib(291).bytes,
        .use_llvm = true,
        // .use_lld = options.project.use_llvm.interpreter,
    });
    libfuzzer_harness_lib.sanitize_coverage_trace_pc_guard = true; // required for AFL++
    libfuzzer_harness_lib.lto = .full;
    libfuzzer_harness_lib.bundle_compiler_rt = true;
    libfuzzer_harness_lib.root_module.addImport("target", target_module);
    libfuzzer_harness_lib.root_module.addImport("ffi", ffi_module);

    // TODO(zig): find way to limit parallelism of afl-clang-lto https://github.com/ziglang/zig/issues/14934
    const afl_clang_lto = b.addSystemCommand(
        &.{ "afl-clang-lto", "-g", "-Wall", "-fsanitize=fuzzer", "-lwasmstint_fuzz_ffi", "-v" },
    );
    afl_clang_lto.disable_zig_progress = true;
    afl_clang_lto.step.max_rss = ByteSize.mib(268).bytes; // arbitrary amount

    afl_clang_lto.addArg("-o");
    const afl_exe = afl_clang_lto.addOutputFileArg("fuzz-validation");

    afl_clang_lto.addArtifactArg(libfuzzer_harness_lib);

    for (rust_include_paths.items) |include_path| {
        afl_clang_lto.addArg("-L");
        afl_clang_lto.addDirectoryArg(include_path);
    }

    const standalone_exe = b.addExecutable(.{
        .name = b.fmt("fuzz-{t}-standalone", .{fuzz_target}),
        .root_module = b.createModule(.{
            .root_source_file = b.path("fuzz/harness/main.zig"),
            .target = options.project.target,
            .optimize = options.project.optimize,
        }),
        .max_rss = ByteSize.mib(268).bytes, // arbitrary amount
        .use_llvm = options.project.use_llvm.interpreter,
    });
    standalone_exe.root_module.addImport("target", target_module);
    standalone_exe.root_module.addImport("ffi", ffi_module);
    Modules.addAsImportTo(Modules.FileContent, modules.file_content, standalone_exe.root_module);
    Modules.addAsImportTo(Modules.CliArgs, modules.cli_args, standalone_exe.root_module);

    const runner_step: *Step.Run = switch (fuzz_runner) {
        .afl => afl: {
            const run_afl = Step.Run.create(b, "fuzz-validation");
            run_afl.addFileArg(afl_exe);
            break :afl run_afl;
        },
        .standalone => b.addRunArtifact(standalone_exe),
    };

    if (b.args) |args| {
        runner_step.addArgs(args);
    }

    fuzz_step.dependOn(&runner_step.step);
}

fn buildWasiSamplePrograms(
    b: *Build,
    steps: *const TopLevelSteps,
    options: struct { project: *const ProjectOptions },
    modules: struct {
        interpreter: Wasip1Interp,
        subprocess: Modules.Subprocess,
    },
) void {
    const wasm_target = b.resolveTargetQuery(.{ .cpu_arch = .wasm32, .os_tag = .wasi });

    const tests_dir = b.path("tests/wasip1/zig");
    const tests_dir_handle = b.build_root.handle.openDir(
        tests_dir.src_path.sub_path,
        .{ .iterate = true },
    ) catch @panic("could not open tests directory");

    const compile_step = b.step("install-wasip1-samples", "Build sample WASI 0.1 programs");
    const test_step = b.step("test-wasip1-samples", "Test sample WASI 0.1 programs");
    steps.@"test".dependOn(test_step);

    var tests_iter = tests_dir_handle.iterateAssumeFirstIteration();
    while (tests_iter.next() catch @panic("bad entry in tests directory")) |tests_entry| {
        if (tests_entry.kind != .file or
            !std.mem.eql(u8, ".zig", std.fs.path.extension(tests_entry.name)))
        {
            continue;
        }

        const exe_max_rss = ByteSize.mib(176);
        const sample_exe = b.addExecutable(.{
            .name = b.dupe(tests_entry.name[0 .. tests_entry.name.len - 4]),
            .root_module = b.createModule(.{
                .root_source_file = tests_dir.path(b, tests_entry.name),
                .target = wasm_target,
                .optimize = options.project.optimize,
            }),
            .max_rss = exe_max_rss.bytes,
        });

        addCheck(b, steps, .exe, sample_exe.root_module, sample_exe.name, .{
            .max_rss = exe_max_rss,
            .use_llvm = options.project.use_llvm.other,
        });

        const install_sample = b.addInstallArtifact(
            sample_exe,
            .{ .dest_dir = .{ .override = .{ .custom = "samples/zig" } } },
        );

        compile_step.dependOn(&install_sample.step);

        const test_options = b.addOptions();
        test_options.addOptionPath("wasm", sample_exe.getEmittedBin());
        test_options.addOptionPath("interpreter", modules.interpreter.exe.getEmittedBin());

        const invoke_test = b.addTest(.{
            .name = sample_exe.name,
            .root_module = b.createModule(.{
                .root_source_file = sample_exe.root_module.root_source_file,
                .target = options.project.target,
                .optimize = options.project.optimize,
            }),
            .max_rss = ByteSize.mib(278).bytes,
            .use_llvm = options.project.use_llvm.other,
        });
        invoke_test.root_module.addOptions("test_paths", test_options);
        Modules.addAsImportTo(Modules.Subprocess, modules.subprocess, invoke_test.root_module);

        // Can't add to "check" step, since it would require building the WASM.
        const run_test = b.addRunArtifact(invoke_test);
        run_test.step.max_rss = ByteSize.mib(16).bytes;
        test_step.dependOn(&run_test.step);
    }
}

fn buildWasiTestsuite(
    b: *Build,
    steps: *const TopLevelSteps,
    options: struct { project: *const ProjectOptions },
    dependencies: struct { driver: Wasip1TestRunner, interpreter: Wasip1Interp },
) void {
    const wasm_target = b.resolveTargetQuery(.{ .cpu_arch = .wasm32, .os_tag = .wasi });
    const install_step = b.step("install-wasi-test-c", "Compile WASI C test programs");
    const tests_step = b.step("test-wasi-c", "Run WASI C test suite");

    const tests_dir = b.path("tests/wasi/tests/c/src/");
    const tests_dir_handle = b.build_root.handle.openDir(
        tests_dir.src_path.sub_path,
        .{ .iterate = true },
    ) catch @panic("could not open tests directory");

    var tests_iter = tests_dir_handle.iterateAssumeFirstIteration();
    while (tests_iter.next() catch @panic("bad entry in tests directory")) |tests_entry| {
        if (tests_entry.kind != .file or
            !std.mem.eql(u8, ".c", std.fs.path.extension(tests_entry.name)))
        {
            continue;
        }

        const test_module = b.createModule(.{
            .target = wasm_target,
            .optimize = options.project.optimize,
            .link_libc = true,
        });
        test_module.addCSourceFile(.{ .file = tests_dir.path(b, tests_entry.name) });

        const test_exe = b.addExecutable(.{
            .name = b.dupe(tests_entry.name[0 .. tests_entry.name.len - 2]),
            .root_module = test_module,
            .max_rss = ByteSize.mib(171).bytes,
        });

        const install_test = b.addInstallArtifact(
            test_exe,
            .{ .dest_dir = .{ .override = .{ .custom = "wasitest/c" } } },
        );

        install_step.dependOn(&install_test.step);

        // Steps to run against the test driver
        const run_test = b.addRunArtifact(dependencies.driver.exe);
        run_test.step.max_rss = ByteSize.mib(3).bytes;
        run_test.setName(b.fmt("{s}.wasm", .{tests_entry.name}));

        run_test.addArg("--module");
        run_test.addArtifactArg(test_exe);

        json: {
            const json_file_name = b.fmt("{s}.json", .{std.fs.path.stem(tests_entry.name)});
            tests_dir_handle.access(json_file_name, .{}) catch |e| switch (e) {
                error.FileNotFound => break :json,
                else => unreachable,
            };

            run_test.addArg("--test");
            run_test.addFileArg(tests_dir.path(b, json_file_name));
        }

        run_test.addArg("--interpreter");
        run_test.addArtifactArg(dependencies.interpreter.exe);

        if (b.args) |args| {
            run_test.addArgs(args);
        }

        tests_step.dependOn(&run_test.step);
    }

    steps.@"test".dependOn(tests_step);
}
