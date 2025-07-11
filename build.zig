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

const PathOptions = struct {
    // cargo: []const u8,
    // @"afl-clang-lto": []const u8,

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

pub fn build(b: *Build) OomError!void {
    const project_options = ProjectOptions.init(b);
    // const path_options = PathOptions.init(b);

    const steps = .{
        // .check = b.step("check", "Check for compilation errors"),

        .run_wast = b.step("run-wast", "Run the specification test interpreter"),
        // .run_wasip1 = b.step("run-wasip1", "Run the WASI (preview 1) application interpreter",),

        .@"test" = b.step("test", "Run all unit and specification tests"),
        .test_unit = b.step("test-unit", "Run unit tests"),
        .test_spec = b.step("test-spec", "Run some specification tests"),
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
}
