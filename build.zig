const std = @import("std");
const Build = std.Build;
const Step = Build.Step;

const ProjectOptions = struct {
    target: Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    // TODO(zig): https://github.com/ziglang/zig/issues/24044
    comptime use_llvm: bool = true,

    fn init(b: *Build) ProjectOptions {
        return .{
            .target = b.standardTargetOptions(.{}),
            .optimize = b.standardOptimizeOption(.{}),
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

const top_level_steps: []const struct { [:0]const u8, [:0]const u8 } = &.{
    .{ "check", "Check for compilation errors" },
    .{ "install-spectest", "Translate specification tests with wast2json" },
    .{ "run-wast", "Run the specification test interpreter" },
    // .{ "run-wasip1", "Run the WASI (preview 1) application interpreter" },
    .{ "test", "Run all unit and specification tests" },
    .{ "test-unit", "Run unit tests" },
    .{ "test-spec", "Run specification tests" },
};

const TopLevelSteps = @Type(.{
    .@"struct" = .{
        .layout = .auto,
        .is_tuple = false,
        .decls = &.{},
        .fields = fields: {
            var fields: [top_level_steps.len]std.builtin.Type.StructField = undefined;
            for (top_level_steps, &fields) |*src, *dst| {
                dst.* = .{
                    .name = src[0],
                    .type = *Step,
                    .default_value_ptr = null,
                    .is_comptime = false,
                    .alignment = @alignOf(*Step),
                };
            }
            break :fields &fields;
        },
    },
});

pub fn build(b: *Build) void {
    const project_options = ProjectOptions.init(b);
    const tool_paths = ToolPaths.init(b);

    const steps: TopLevelSteps = steps: {
        var init: TopLevelSteps = undefined;
        inline for (top_level_steps) |step| {
            @field(init, step[0]) = b.step(step[0], step[1]);
        }
        break :steps init;
    };

    const wasmstint_module = WasmstintModule.build(b, &project_options);
    const cli_args_module = CliArgsModule.build(b, &project_options);
    const wasip1_module = WasiPreview1Module.build(b, &project_options);
    wasmstint_module.addAsImportTo(wasip1_module.module);

    const spectest_exe = SpectestInterp.build(
        b,
        &project_options,
        &wasmstint_module,
        &cli_args_module,
    );
    steps.@"run-wast".dependOn(&spectest_exe.run.step);

    steps.check.dependOn(&wasmstint_module.unit_tests.step);
    // steps.check.dependOn(&cli_args_module.unit_tests.step);
    steps.check.dependOn(&wasip1_module.unit_tests.step);
    steps.check.dependOn(&spectest_exe.exe.step);

    const wasip1_exe = WasiPreview1Exe.build(
        b,
        &steps,
        &project_options,
        .{
            .wasmstint = &wasmstint_module,
            .cli_args = &cli_args_module,
            .wasip1 = &wasip1_module,
        },
    );
    _ = wasip1_exe;

    steps.@"test-unit".dependOn(&b.addRunArtifact(wasmstint_module.unit_tests).step);
    steps.@"test-unit".dependOn(&b.addRunArtifact(cli_args_module.unit_tests).step);
    steps.@"test".dependOn(steps.@"test-unit");

    const translate_spectests = TranslateSpectests.build(b, &steps, &tool_paths);
    for (translate_spectests.tests) |test_spec| {
        const run_test_spec = b.addRunArtifact(spectest_exe.exe);
        run_test_spec.setName(b.fmt("spectest/{s}.wast", .{test_spec.name}));
        run_test_spec.addArg("--run");
        run_test_spec.addFileArg(test_spec.json_path);
        run_test_spec.step.dependOn(translate_spectests.translate_step);
        steps.@"test-spec".dependOn(&run_test_spec.step);
    }

    steps.@"test".dependOn(steps.@"test-spec");

    buildFuzzers(
        b,
        &steps,
        .{ .project = &project_options, .tool_paths = &tool_paths },
        .{ .wasmstint = &wasmstint_module, .cli_args = &cli_args_module },
    );

    buildWasiTestPrograms(
        b,
        &steps,
        .{ .project = &project_options, .tool_paths = &tool_paths },
    );
}

fn NamedModule(
    comptime name: []const u8,
    comptime root_source_file: []const u8,
) type {
    return struct {
        const Self = @This();

        module: *Build.Module,
        unit_tests: *Step.Compile,

        fn build(b: *Build, proj_opts: *const ProjectOptions) Self {
            const module = b.addModule(
                name,
                .{
                    .root_source_file = b.path(root_source_file),
                    .target = proj_opts.target,
                    .optimize = proj_opts.optimize,
                },
            );

            return .{
                .module = module,
                .unit_tests = b.addTest(.{
                    .name = name,
                    .root_module = module,
                    // TODO(zig): https://github.com/ziglang/zig/issues/23423
                    .use_llvm = true,
                }),
            };
        }

        fn addAsImportTo(self: *const Self, to: *Build.Module) void {
            to.addImport(name, self.module);
        }
    };
}

const WasmstintModule = NamedModule("wasmstint", "src/root.zig");
const CliArgsModule = NamedModule("cli_args", "src/cli_args.zig");
const WasiPreview1Module = NamedModule("WasiPreview1", "src/WasiPreview1.zig");

const SpectestInterp = struct {
    exe: *Step.Compile,
    run: *Step.Run,

    fn build(
        b: *Build,
        proj_opts: *const ProjectOptions,
        wasmstint_module: *const WasmstintModule,
        cli_args_module: *const CliArgsModule,
    ) SpectestInterp {
        const module = b.createModule(.{
            .root_source_file = b.path("src/spectest/main.zig"),
            .target = proj_opts.target,
            .optimize = proj_opts.optimize,
        });
        wasmstint_module.addAsImportTo(module);
        cli_args_module.addAsImportTo(module);

        const exe = b.addExecutable(.{
            .name = "wasmstint-spectest",
            .root_module = module,
            .use_llvm = proj_opts.use_llvm,
        });

        const run = b.addRunArtifact(exe);
        if (b.args) |args| {
            run.addArgs(args);
        }

        b.getInstallStep().dependOn(&b.addInstallArtifact(exe, .{}).step);

        return .{ .exe = exe, .run = run };
    }
};

const TranslateSpectests = struct {
    translate_step: *Step,
    tests: []const Test,

    const Test = struct {
        name: []const u8,
        json_path: Build.LazyPath,
    };

    fn build(
        b: *Build,
        top_steps: *const TopLevelSteps,
        tool_paths: *const ToolPaths,
    ) TranslateSpectests {
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
            translate_step.dependOn(&wast2json.step);
            wast2json.setCwd(translate_output_dir);
            wast2json.addFileArg(tests_dir.path(b, tests_entry.name));

            const name = b.dupe(tests_entry.name[0 .. tests_entry.name.len - 5]);
            const json_name = b.fmt("{s}.json", .{name});
            wast2json.addArgs(&.{ "--output", json_name });
            // addPrefixedFileArg would mean each .json is in a separate dir
            const json_path = translate_output_dir.path(b, json_name);

            spectests.append(b.allocator, .{ .name = name, .json_path = json_path }) catch
                @panic("OOM");
        }

        const step = if (spectests.items.len == 0)
            &b.addFail("no .wast files found in test directory").step
        else
            translate_step;

        top_steps.@"install-spectest".dependOn(step);

        if (spectests.items.len > 0) {
            const install_spectests = b.addInstallDirectory(.{
                .source_dir = translate_output_dir,
                .install_dir = .{ .custom = "spectest" },
                .install_subdir = ".",
            });

            install_spectests.step.dependOn(translate_step);
            top_steps.@"install-spectest".dependOn(&install_spectests.step);
        }

        return .{
            .translate_step = step,
            .tests = spectests.items,
        };
    }
};

const WasiPreview1Exe = struct {
    exe: *Step.Compile,

    fn build(
        b: *Build,
        steps: *const TopLevelSteps,
        proj_opts: *const ProjectOptions,
        imported_modules: struct {
            wasmstint: *const WasmstintModule,
            cli_args: *const CliArgsModule,
            wasip1: *const WasiPreview1Module,
        },
    ) WasiPreview1Exe {
        const exe = b.addExecutable(.{
            .name = "wasmstint-wasip1",
            .root_module = b.createModule(.{
                .root_source_file = b.path("src/WasiPreview1/main.zig"),
                .target = proj_opts.target,
                .optimize = proj_opts.optimize,
            }),
            .use_llvm = proj_opts.use_llvm,
        });
        imported_modules.wasmstint.addAsImportTo(exe.root_module);
        imported_modules.cli_args.addAsImportTo(exe.root_module);
        imported_modules.wasip1.addAsImportTo(exe.root_module);

        steps.check.dependOn(&exe.step);

        const run = b.addRunArtifact(exe);
        if (b.args) |args| {
            run.addArgs(args);
        }
        b.step("run-wasip1", "Run WASI 0.1 program interpreter").dependOn(&run.step);

        b.getInstallStep().dependOn(&b.addInstallArtifact(exe, .{}).step);

        return .{ .exe = exe };
    }
};

fn buildFuzzers(
    b: *Build,
    steps: *const TopLevelSteps,
    options: struct { project: *const ProjectOptions, tool_paths: *const ToolPaths },
    modules: struct { wasmstint: *const WasmstintModule, cli_args: *const CliArgsModule },
) void {
    _ = b;
    _ = steps;
    _ = options;
    _ = modules;
}

fn buildWasiTestPrograms(
    b: *Build,
    steps: *const TopLevelSteps,
    options: struct { project: *const ProjectOptions, tool_paths: *const ToolPaths },
) void {
    const wasm_target = b.resolveTargetQuery(.{ .cpu_arch = .wasm32, .os_tag = .wasi });

    const tests_dir = b.path("tests/wasip1/zig");
    const tests_dir_handle = b.build_root.handle.openDir(
        tests_dir.src_path.sub_path,
        .{
            .iterate = true,
        },
    ) catch @panic("could not open tests directory");

    const compile_step = b.step("install-wasip1-samples", "Build sample WASIP 0.1 programs");

    var tests_iter = tests_dir_handle.iterateAssumeFirstIteration();
    while (tests_iter.next() catch @panic("bad entry in tests directory")) |tests_entry| {
        if (tests_entry.kind != .file or
            !std.mem.eql(u8, ".zig", std.fs.path.extension(tests_entry.name)))
        {
            continue;
        }

        const sample_exe = b.addExecutable(.{
            .name = b.dupe(tests_entry.name[0 .. tests_entry.name.len - 4]),
            .root_module = b.createModule(.{
                .root_source_file = tests_dir.path(b, tests_entry.name),
                .target = wasm_target,
                .optimize = options.project.optimize,
            }),
        });

        steps.check.dependOn(&sample_exe.step);

        const install_sample = b.addInstallArtifact(
            sample_exe,
            .{ .dest_dir = .{ .override = .{ .custom = "samples/zig" } } },
        );

        compile_step.dependOn(&install_sample.step);
    }
}
