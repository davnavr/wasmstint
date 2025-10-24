const std = @import("std");
const Build = std.Build;
const Step = Build.Step;

const ProjectOptions = struct {
    target: Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    optimize_interpreter: std.builtin.OptimizeMode,
    // TODO(zig): https://github.com/ziglang/zig/issues/24044
    comptime use_llvm: bool = true,
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

        return .{
            .target = b.standardTargetOptions(.{}),
            .optimize = optimize,
            .optimize_interpreter = b.option(
                std.builtin.OptimizeMode,
                "optimize-interpreter",
                "Override optimization level for interpreter",
            ) orelse optimize,
            .link_libc = if (enable_coz or link_libc) true else null,
            .enable_coz = enable_coz,
        };
    }
};

const ToolPaths = struct {
    wast2json: ?[]const u8,
    // @"wasm-opt": ?[]const u8,
    // @"wasm-reduce": []const u8,
    // @"wasm-tools": []const u8,

    fn getOrDefault(
        paths: *const ToolPaths,
        comptime tool: std.meta.FieldEnum(ToolPaths),
    ) []const u8 {
        return @field(paths, @tagName(tool)) orelse @tagName(tool);
    }

    fn init(b: *Build) ToolPaths {
        var options: ToolPaths = undefined;
        inline for (@typeInfo(ToolPaths).@"struct".fields) |field| {
            @field(options, field.name) = b.option(
                []const u8,
                field.name,
                "Path to " ++ field.name ++ " executable",
            ) orelse field.name;
        }

        return options;
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
    const tool_paths = ToolPaths.init(b);

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
        .allocators = .build(b, &steps, &project_options),
        .file_content = undefined,
        .wasmstint = undefined,
        .cli_args = Modules.CliArgs.build(b, &steps, &project_options),
        .wasip1 = undefined,
        .subprocess = .build(b, &project_options),
    };
    modules.file_content = .build(b, &project_options, .{ .allocators = modules.allocators });
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
        .{ .wasmstint = modules.wasmstint, .coz = modules.coz, .allocators = modules.allocators },
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
        },
    );

    buildSpecificationTests(b, spectest_exe, &steps, &tool_paths);

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

    buildFuzzers(
        b,
        &steps,
        .{ .project = &project_options, .tool_paths = &tool_paths },
        .{ .wasmstint = modules.wasmstint, .cli_args = modules.cli_args },
    );

    buildWasiSamplePrograms(
        b,
        &steps,
        .{ .project = &project_options, .tool_paths = &tool_paths },
        .{ .interpreter = wasip1_exe, .subprocess = modules.subprocess },
    );

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
    options: struct { max_rss: ByteSize, use_llvm: ?bool = null },
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
        ) Allocators {
            const module = b.createModule(.{
                .root_source_file = b.path("src/allocators.zig"),
                .target = options.target,
                .optimize = options.optimize,
            });

            const tests = b.addTest(.{
                .name = name,
                .root_module = module,
                .max_rss = ByteSize.mib(234).bytes,
            });

            const tests_run = &b.addRunArtifact(tests).step;
            tests_run.max_rss = ByteSize.mib(16).bytes;
            steps.@"test-unit".dependOn(tests_run);

            addCheck(b, steps, .@"test", module, name, .{ .max_rss = .mib(110) });
            return .{ .module = module };
        }
    };

    const FileContent = struct {
        module: *Build.Module,

        const name = "file_content";

        fn build(
            b: *Build,
            options: *const ProjectOptions,
            imports: struct { allocators: Allocators },
        ) FileContent {
            const module = b.createModule(.{
                .root_source_file = b.path("src/file_content.zig"),
                .target = options.target,
                .optimize = options.optimize,
            });
            addAsImportTo(Allocators, imports.allocators, module);

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
            const module = b.addModule(
                name,
                .{
                    .root_source_file = b.path("src/root.zig"),
                    .target = options.target,
                    .optimize = options.optimize_interpreter,
                    .link_libc = options.link_libc,
                },
            );
            addAsImportTo(Coz, imports.coz, module);
            addAsImportTo(Allocators, imports.allocators, module);

            // TODO(zig): https://github.com/ziglang/zig/issues/23423
            const use_llvm = true;
            const tests = b.addTest(.{
                .name = name,
                .root_module = module,
                .use_llvm = use_llvm,
                .max_rss = ByteSize.mib(257).bytes,
            });

            const tests_run = &b.addRunArtifact(tests).step;
            tests_run.max_rss = ByteSize.mib(19).bytes;
            steps.@"test-unit".dependOn(tests_run);
            addCheck(
                b,
                steps,
                .@"test",
                module,
                name,
                .{ .max_rss = .mib(126), .use_llvm = use_llvm },
            );
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
            const module = b.addModule(
                name,
                .{
                    .root_source_file = b.path("src/cli_args.zig"),
                    .target = options.target,
                    .optimize = options.optimize,
                },
            );

            const tests = b.addTest(.{
                .name = name,
                .root_module = module,
                // TODO(zig): https://github.com/ziglang/zig/issues/23423
                .use_llvm = true,
                .max_rss = ByteSize.mib(236).bytes,
            });

            const tests_run = &b.addRunArtifact(tests).step;
            tests_run.max_rss = ByteSize.mib(16).bytes;
            steps.@"test-unit".dependOn(tests_run);

            addCheck(b, steps, .@"test", module, name, .{ .max_rss = .mib(109) });
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
            imports: struct { wasmstint: Wasmstint, coz: Coz, allocators: Allocators },
        ) Wasip1 {
            const module = b.addModule(
                name,
                .{
                    .root_source_file = b.path("src/WasiPreview1.zig"),
                    .target = options.target,
                    .optimize = options.optimize,
                    .link_libc = options.link_libc,
                },
            );
            addAsImportTo(Wasmstint, imports.wasmstint, module);
            addAsImportTo(Coz, imports.coz, module);
            addAsImportTo(Allocators, imports.allocators, module);

            const tests = b.addTest(.{
                .name = name,
                .root_module = module,
                .max_rss = ByteSize.mib(219).bytes,
            });

            const tests_run = &b.addRunArtifact(tests).step;
            tests_run.max_rss = ByteSize.mib(16).bytes;
            steps.@"test-unit".dependOn(tests_run);

            addCheck(b, steps, .@"test", module, name, .{ .max_rss = .mib(106) });
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
            .use_llvm = proj_opts.use_llvm,
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

        addCheck(
            b,
            steps,
            .exe,
            module,
            exe.name,
            .{
                .max_rss = .mib(160),
                // Prevent compile errors due to https://github.com/ziglang/zig/issues/24044
                .use_llvm = proj_opts.use_llvm,
            },
        );

        return .{ .exe = exe };
    }
};

fn buildSpecificationTests(
    b: *Build,
    interpreter: SpectestInterp,
    top_steps: *const TopLevelSteps,
    tool_paths: *const ToolPaths,
) void {
    const Test = struct {
        name: []const u8,
        json_path: Build.LazyPath,
        run: *Build.Step.Run,
    };

    var spectests = std.ArrayList(Test).initCapacity(b.allocator, 147) catch
        @panic("OOM");

    const tests_dir = b.path("tests/spec");
    const tests_dir_handle = b.build_root.handle.openDir(
        tests_dir.src_path.sub_path,
        .{ .iterate = true },
    ) catch @panic("could not open tests directory");

    var translate_step = b.allocator.create(Step) catch @panic("OOM");
    translate_step.* = Step.init(.{
        .id = .custom,
        .name = @typeName(@This()),
        .owner = b,
    });
    const translate_output = b.addWriteFiles();
    const translate_output_dir = translate_output.getDirectory();
    translate_step.dependOn(&translate_output.step);

    var tests_iter = tests_dir_handle.iterateAssumeFirstIteration();
    while (tests_iter.next() catch @panic("bad entry in tests directory")) |tests_entry| {
        if (tests_entry.kind != .file or
            !std.mem.eql(u8, ".wast", std.fs.path.extension(tests_entry.name)) or
            std.mem.startsWith(u8, tests_entry.name, "simd_"))
        {
            continue;
        }

        var wast2json = b.addSystemCommand(&.{tool_paths.getOrDefault(.wast2json)});
        wast2json.step.max_rss = ByteSize.mib(14).bytes;
        translate_step.dependOn(&wast2json.step);
        wast2json.setCwd(translate_output_dir);
        wast2json.addFileArg(tests_dir.path(b, tests_entry.name));

        const name = b.dupe(tests_entry.name[0 .. tests_entry.name.len - 5]);
        const json_name = b.fmt("{s}.json", .{name});
        wast2json.addArgs(&.{ "--output", json_name });
        // addPrefixedFileArg would mean each .json is in a separate dir
        const json_path = translate_output_dir.path(b, json_name);

        spectests.append(
            b.allocator,
            .{ .name = name, .json_path = json_path, .run = wast2json },
        ) catch @panic("OOM");
    }

    const step = if (spectests.items.len == 0)
        &b.addFail("no .wast files found in test directory").step
    else
        translate_step;

    const install_step = b.step(
        "install-spectest",
        "Translate specification tests with wast2json",
    );
    install_step.dependOn(step);

    if (spectests.items.len > 0) {
        const install_spectests = b.addInstallDirectory(.{
            .source_dir = translate_output_dir,
            .install_dir = .{ .custom = "spectest" },
            .install_subdir = ".",
        });

        install_spectests.step.dependOn(translate_step);
        install_step.dependOn(&install_spectests.step);
    }

    const test_spec_step = b.step("test-spec", "Run specification tests");

    for (spectests.items) |test_spec| {
        const run_test_spec = b.addRunArtifact(interpreter.exe);
        run_test_spec.step.max_rss = ByteSize.mib(20).bytes;
        run_test_spec.setName(b.fmt("spectest/{s}.wast", .{test_spec.name}));
        run_test_spec.addArg("--run");
        run_test_spec.addFileArg(test_spec.json_path);
        run_test_spec.step.dependOn(&test_spec.run.step);
        run_test_spec.expectExitCode(0);
        test_spec_step.dependOn(&run_test_spec.step);
    }

    top_steps.@"test".dependOn(test_spec_step);
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

        const exe = b.addExecutable(.{
            .name = "wasmstint-wasip1",
            .root_module = module,
            .use_llvm = proj_opts.use_llvm,
            .max_rss = ByteSize.mib(755).bytes,
        });

        addCheck(
            b,
            steps,
            .exe,
            module,
            exe.name,
            .{ .max_rss = .mib(175), .use_llvm = proj_opts.use_llvm },
        );

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
    options: struct { project: *const ProjectOptions, tool_paths: *const ToolPaths },
    modules: struct { wasmstint: Modules.Wasmstint, cli_args: Modules.CliArgs },
) void {
    _ = b;
    _ = steps;
    _ = options;
    _ = modules;
}

fn buildWasiSamplePrograms(
    b: *Build,
    steps: *const TopLevelSteps,
    options: struct { project: *const ProjectOptions, tool_paths: *const ToolPaths },
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

        addCheck(
            b,
            steps,
            .exe,
            sample_exe.root_module,
            sample_exe.name,
            .{ .max_rss = exe_max_rss },
        );

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
    options: struct { project: *const ProjectOptions, tool_paths: *const ToolPaths },
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
