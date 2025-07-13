const std = @import("std");
const Build = std.Build;
const Step = Build.Step;

const ProjectOptions = struct {
    target: Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,

    fn init(b: *Build) ProjectOptions {
        return .{
            .target = b.standardTargetOptions(.{}),
            .optimize = b.standardOptimizeOption(.{}),
        };
    }
};

const ToolPaths = struct {
    wast2json: []const u8,
    // cargo: []const u8,
    // @"afl-clang-lto": []const u8,

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

pub fn build(b: *Build) void {
    const project_options = ProjectOptions.init(b);
    const tool_paths = ToolPaths.init(b);

    const steps = .{
        .check = b.step("check", "Check for compilation errors"),

        .install_spectest = b.step(
            "install-spectest",
            "Translate specification tests with wast2json",
        ),

        .run_wast = b.step("run-wast", "Run the specification test interpreter"),
        // .run_wasip1 = b.step("run-wasip1", "Run the WASI (preview 1) application interpreter",),

        .@"test" = b.step("test", "Run all unit and specification tests"),
        .test_unit = b.step("test-unit", "Run unit tests"),
        // .test_spec = b.step("test-spec", "Run some specification tests"),
    };

    const wasmstint_module = WasmstintModule.build(b, &project_options);
    const cli_args_module = CliArgsModule.build(b, &project_options);

    steps.check.dependOn(&wasmstint_module.unit_tests.step);
    // steps.check.dependOn(&cli_args_module.unit_tests.step);

    // Executables.build(b);

    steps.test_unit.dependOn(&b.addRunArtifact(wasmstint_module.unit_tests).step);
    steps.test_unit.dependOn(&b.addRunArtifact(cli_args_module.unit_tests).step);
    steps.@"test".dependOn(steps.test_unit);

    const translate_spectests = TranslateSpectests.build(b, steps.install_spectest, &tool_paths);

    _ = translate_spectests;
    // steps.@"test".dependOn(steps.test_spec);
}

fn NamedModule(
    comptime name: []const u8,
    comptime root_source_file: []const u8,
) type {
    return struct {
        module: *Build.Module,
        unit_tests: *Step.Compile,

        fn build(b: *Build, proj_opts: *const ProjectOptions) WasmstintModule {
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
                .unit_tests = b.addTest(.{ .name = name, .root_module = module }),
            };
        }

        fn addAsImportTo(wasmstint: *const WasmstintModule, to: *Build.Module) void {
            to.addImport(name, wasmstint.module);
        }
    };
}

const WasmstintModule = NamedModule("wasmstint", "src/root.zig");
const CliArgsModule = NamedModule("cli_args", "src/cli_args.zig");

const TranslateSpectests = struct {
    translate_step: *Step,
    tests: []const Test,

    const Test = struct {
        name: []const u8,
        json_path: Build.LazyPath,
    };

    fn build(
        b: *Build,
        install_step: *Step,
        tool_paths: *const ToolPaths,
    ) TranslateSpectests {
        var spectests = std.ArrayListUnmanaged(Test).initCapacity(b.allocator, 147) catch
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

            var wast2json = b.addSystemCommand(&.{tool_paths.wast2json});
            translate_step.dependOn(&wast2json.step);
            wast2json.setCwd(translate_output_dir);
            wast2json.addFileArg(tests_dir.path(b, tests_entry.name));

            const name = b.allocator.dupe(u8, tests_entry.name[0 .. tests_entry.name.len - 5]) catch
                @panic("OOM");

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

        return .{
            .translate_step = step,
            .tests = spectests.items,
        };
    }
};
