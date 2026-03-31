const UseLlvm = enum {
    /// Only use Zig's other compilation backends. Likely to fail or cause miscompilations.
    never,
    /// Let Zig decide.
    default,
    /// Use the Zig LLVM backend for produced executables, libraries, tests, etc.
    prefer,
    /// Only use the Zig LLVM backend.
    always,

    fn ifPreferred(use: UseLlvm) ?bool {
        return switch (use) {
            .never => false,
            .default => null,
            .prefer, .always => true,
        };
    }

    fn ifAlways(use: UseLlvm) ?bool {
        return switch (use) {
            .never, .prefer => false,
            .default => null,
            .always => true,
        };
    }
};

const InterpreterBackend = enum {
    zig,
    assembly,
    @"llvm-ir",
};

const FuzzRunner = enum {
    /// Requires `afl-fuzz` from AFL++.
    afl,
    standalone,
};

const byte_size = struct {
    fn kib(amt: usize) usize {
        return amt * 1024;
    }

    fn mib(amt: usize) usize {
        return kib(amt * 1024);
    }
};

const WasmFeatures = struct {
    simd128: bool,
    tail_call: bool,
};

fn stringifyZon(b: *Build, object: anytype, capacity: usize) []const u8 {
    var alloc = std.Io.Writer.Allocating.initCapacity(b.allocator, capacity) catch @panic("oom");
    std.zon.stringify.serialize(object, .{ .whitespace = false }, &alloc.writer) catch
        @panic("oom");
    return alloc.written();
}

pub fn build(b: *Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const enable_coz = false; // Untested
    // const enable_coz = b.option(
    //     bool,
    //     "coz",
    //     "Enable coz profiling counters. Implies -Dlink-libc",
    // ) orelse false;

    // const link_libc = b.option(
    //     bool,
    //     "link-libc",
    //     "Require linking to the C standard library (Windows & Linux only)",
    // ) orelse false;

    const use_llvm = b.option(UseLlvm, "use-llvm", "Specifies when the LLVM backend is used") orelse
        UseLlvm.default;

    const pic = b.option(bool, "pic", "Require generating Position Independent Code");

    const check_step = b.step("check", "Check executables for compile errors");
    const unit_tests_step = b.step("test-unit", "Run unit tests");

    const sys_module = b.createModule(.{
        .root_source_file = b.path("src/sys.zig"),
        .target = target,
        .optimize = optimize,
    });

    const allocators_module = b.createModule(.{
        .root_source_file = b.path("src/allocators.zig"),
        .target = target,
        .optimize = optimize,
    });
    {
        allocators_module.addImport("sys", sys_module);

        const tests = &b.addRunArtifact(b.addTest(.{
            .name = "allocators",
            .root_module = allocators_module,
            .max_rss = byte_size.mib(461),
            .use_llvm = use_llvm.ifPreferred(),
        })).step;
        tests.max_rss = byte_size.mib(19);
        unit_tests_step.dependOn(tests);
    }

    const file_content_module = b.createModule(.{
        .root_source_file = b.path("src/file_content.zig"),
        .target = target,
        .optimize = optimize,
    });
    {
        file_content_module.addImport("sys", sys_module);
        file_content_module.addImport("allocators", allocators_module);
    }

    const coz_module = b.createModule(.{
        .root_source_file = b.path("src/coz.zig"),
        .target = target,
        .optimize = optimize,
        // .link_libc = link_libc,
    });
    {
        const coz_options = b.addOptions();
        coz_options.addOption(bool, "enabled", enable_coz);
        coz_module.addOptions("options", coz_options);
    }

    const cli_args_module = b.createModule(.{
        .root_source_file = b.path("src/cli_args.zig"),
        .target = target,
        .optimize = optimize,
    });
    {
        const tests = &b.addRunArtifact(b.addTest(.{
            .name = "cli_args",
            .root_module = cli_args_module,
            .use_llvm = use_llvm.ifPreferred(),
            .max_rss = byte_size.mib(480),
        })).step;
        tests.max_rss = byte_size.mib(19);
        unit_tests_step.dependOn(tests);
    }

    const opcodes_module = b.createModule(.{ .root_source_file = b.path("src/opcodes.zig") });

    const wasm_builder_module = b.addModule("WasmBuilder", .{
        .root_source_file = b.path("src/WasmBuilder.zig"),
        .target = target,
        .optimize = optimize,
    });
    {
        wasm_builder_module.addImport("opcodes", opcodes_module);

        const tests = &b.addRunArtifact(b.addTest(.{
            .name = "WasmBuilder",
            .root_module = wasm_builder_module,
            .use_llvm = use_llvm.ifPreferred(),
            .max_rss = byte_size.mib(475),
        })).step;
        tests.max_rss = byte_size.mib(20); // arbitrary amount
        unit_tests_step.dependOn(tests);
    }

    const wasm_features = WasmFeatures{
        .simd128 = b.option(
            bool,
            "simd128",
            "Disable or enable support for the 128-bit SIMD proposal",
        ) orelse true,
        .tail_call = b.option(
            bool,
            "tail-call",
            "Disable or enable support for the tail call proposal",
        ) orelse true,
    };

    const wasm_options = options: {
        const wasm_options = b.addOptions();
        inline for (comptime std.meta.fieldNames(WasmFeatures)) |field| {
            wasm_options.addOption(bool, field, @field(wasm_features, field));
        }
        break :options wasm_options.createModule();
    };

    const interpreter_backend = b.option(
        InterpreterBackend,
        "interpreter-backend",
        "Set the interpreter implementation to use",
    ) orelse InterpreterBackend.zig;

    const wasmstint_module = wasmstint: {
        const root_module = b.addModule("wasmstint", .{
            .root_source_file = b.path("src/root.zig"),
            .target = target,
            .optimize = optimize,
            // .link_libc = link_libc,
        });
        const handlers_module = b.createModule(.{
            .root_source_file = b.path("src/handlers.zig"),
            .target = target,
            .optimize = optimize,
        });
        const interpreter_module = b.createModule(.{
            .root_source_file = b.path("src/interpreter.zig"),
            .target = target,
            .optimize = optimize,
        });
        interpreter_module.addImport("handlers", handlers_module);

        const module_options = b.addOptions();
        module_options.addOption(InterpreterBackend, "interpreter_backend", interpreter_backend);
        const module_options_import = module_options.createModule();

        for (&[5]struct { []const u8, *Build.Module }{
            .{ "coz", coz_module },
            .{ "allocators", allocators_module },
            .{ "opcodes", opcodes_module },
            .{ "wasm_features", wasm_options },
            .{ "options", module_options_import },
        }) |info| {
            for (&[3]*Build.Module{ root_module, handlers_module, interpreter_module }) |m| {
                m.addImport(info.@"0", info.@"1");
            }
        }

        for (&[2]*Build.Module{ handlers_module, interpreter_module }) |m| {
            m.addImport("wasmstint", root_module);
        }

        for (&[2]*Build.Module{ root_module, handlers_module }) |m| {
            m.addImport("interpreter", interpreter_module);
        }

        const enum_set_module = b.createModule(.{
            .root_source_file = b.path("src/codegen/enum_set.zig"),
        });

        if (interpreter_backend == .assembly and target.result.cpu.arch == .x86_64) {
            const symbol_prefix = "wasmstint.x86_64_sysv.";
            const Options = struct {
                optimize: std.builtin.OptimizeMode,
                symbol_prefix: []const u8,
                pic: bool,
                features: []const std.Target.x86.Feature,
                wasm_features: WasmFeatures,
            };

            const cpu_feature_set = target.result.cpu.features;
            var cpu_features = std.ArrayList(std.Target.x86.Feature)
                .initCapacity(b.allocator, cpu_feature_set.count()) catch @panic("oom");

            for (std.enums.values(std.Target.x86.Feature)) |feat| {
                if (std.Target.x86.featureSetHas(cpu_feature_set, feat)) {
                    cpu_features.appendAssumeCapacity(feat);
                } else if (cpu_features.items.len == cpu_features.capacity) {
                    break;
                }
            }

            const options = Options{
                .optimize = optimize,
                .symbol_prefix = symbol_prefix,
                .pic = pic orelse true, // Assume PIC if unspecified
                // .target_triple = options.target.query.zigTriple(b.allocator) catch @panic("oom"),
                .features = cpu_features.items,
                .wasm_features = wasm_features,
            };

            const codegen_exe = b.addExecutable(.{
                .name = "wasmstint-codegen-x86_64_sysv",
                .root_module = b.createModule(.{
                    .root_source_file = b.path("src/codegen/x86_64/main.zig"),
                    .target = b.graph.host,
                    .optimize = .Debug,
                    .single_threaded = true,
                    .pic = false,
                    // .code_model = .small, // Forces usage of LLVM backend
                }),
                .max_rss = byte_size.mib(184),
            });
            codegen_exe.root_module.addImport("opcodes", opcodes_module);
            codegen_exe.root_module.addImport("enum_set", enum_set_module);

            const run_codegen = b.addRunArtifact(codegen_exe);
            run_codegen.step.max_rss = byte_size.mib(3);
            run_codegen.addArg(stringifyZon(b, options, 512));
            handlers_module.addAssemblyFile(run_codegen.addOutputFileArg("x86_64_sysv.s"));
            // root_module.addAnonymousImport("asm_generated", .{
            //     .root_source_file = run_codegen.addOutputFileArg("x86_64_sys_decls.zig"),
            //     .target = options.target,
            //     .optimize = options.optimize_interpreter,
            // });

            module_options.addOption([]const u8, "symbol_prefix", symbol_prefix);
        } else if (interpreter_backend == .@"llvm-ir") {
            const target_info_bc = b.addLibrary(.{
                .name = "target_info",
                .root_module = b.createModule(.{
                    .root_source_file = b.path("src/codegen/llvm/target_info_source.zig"),
                    .target = target,
                    .optimize = .ReleaseFast,
                    .strip = true,
                }),
                .max_rss = byte_size.mib(88),
            }).getEmittedLlvmIr();

            const target_info = info: {
                const extract_target_info_exe = b.addExecutable(.{
                    .name = "wasmstint-codegen-llvm-extract-target-info",
                    .root_module = b.createModule(.{
                        .root_source_file = b.path("src/codegen/llvm/extract_target_info.zig"),
                        .target = b.graph.host,
                        .optimize = .Debug,
                        .single_threaded = true,
                        .pic = false,
                    }),
                    .max_rss = byte_size.mib(127),
                });

                const extract_target_info = b.addRunArtifact(extract_target_info_exe);
                extract_target_info.addFileArg(target_info_bc);
                extract_target_info.step.max_rss = byte_size.mib(1);
                break :info extract_target_info.captureStdOut(.{ .basename = "target_info.zon" });
            };

            const sample_intrinsics_bc = bc: {
                const sample_intrinsics_exe = b.addExecutable(.{
                    .name = "wasmstint-codegen-llvm-sample-intrinsics",
                    .root_module = b.createModule(.{
                        .root_source_file = b.path("src/codegen/llvm/sample_intrinsics.zig"),
                        .target = b.graph.host,
                        .optimize = .Debug,
                        .single_threaded = true,
                        .pic = false,
                    }),
                    .max_rss = byte_size.mib(170),
                });

                const sample_intrinsics = b.addRunArtifact(sample_intrinsics_exe);
                sample_intrinsics.step.max_rss = byte_size.mib(1);
                sample_intrinsics.addFileArg(target_info);
                break :bc sample_intrinsics.addOutputFileArg("sample_intrinsics.bc");
            };

            const target_triple = target.query.zigTriple(b.allocator) catch @panic("oom");

            // TODO(Zig): LLVM IR can't be used https://github.com/ziglang/zig/issues/25004
            // - Workaround is to use zig cc (clang)
            const sample_intrinsics_asm = cc: {
                const cc = b.addSystemCommand(&.{
                    b.graph.zig_exe,
                    "cc",
                    "-S",
                    "-nostdlib",
                    // Zig enables sanitizer flags when compiling C
                    "-fno-sanitize=undefined",
                    "-fno-sanitize-trap",
                    // Zig passes `-c`, which is unused
                    "-Wno-unused-command-line-argument",
                    "-target",
                });
                cc.step.max_rss = byte_size.mib(39);

                cc.addArg(target_triple);

                if (target.result.cpu.arch.isX86()) {
                    cc.addArg("-masm=intel");
                }

                cc.addFileArg(sample_intrinsics_bc);

                cc.addArg("-o");
                break :cc cc.addOutputFileArg("sample_intrinsics.s");
            };

            const detected_intrinsics = info: {
                const intrinsic_detection_exe = b.addExecutable(.{
                    .name = "wasmstint-codegen-llvm-intrinsic-detection",
                    .root_module = b.createModule(.{
                        .root_source_file = b.path("src/codegen/llvm/intrinsic_detection.zig"),
                        .target = b.graph.host,
                        .optimize = .Debug,
                        .single_threaded = true,
                        .pic = false,
                    }),
                    .max_rss = byte_size.mib(128),
                });

                const intrinsic_detection = b.addRunArtifact(intrinsic_detection_exe);
                intrinsic_detection.step.max_rss = byte_size.mib(1);
                intrinsic_detection.addFileArg(sample_intrinsics_asm);
                break :info intrinsic_detection.captureStdOut(.{
                    .basename = "detected_intrinsics.zon",
                });
            };

            for (&[2]*Build.Module{ root_module, handlers_module }) |m| {
                m.addAnonymousImport("detected_intrinsics", .{
                    .root_source_file = detected_intrinsics,
                });
            }

            const codegen_exe = b.addExecutable(.{
                .name = "wasmstint-codegen-llvm",
                .root_module = b.createModule(.{
                    .root_source_file = b.path("src/codegen/llvm/main.zig"),
                    .target = b.graph.host,
                    .optimize = .Debug,
                    .single_threaded = true,
                    .pic = false,
                    // .code_model = .small, // Forces usage of LLVM backend
                }),
                .max_rss = byte_size.mib(213),
            });
            codegen_exe.root_module.addImport("opcodes", opcodes_module);
            codegen_exe.root_module.addImport("enum_set", enum_set_module);

            const symbol_prefix = "wasmstint.interpreter.";

            const Options = struct {
                optimize: std.builtin.OptimizeMode,
                symbol_prefix: []const u8,
                strip: bool,
                target: struct {
                    triple: []const u8,
                    cpu_features: []const u8,
                },
                wasm_features: WasmFeatures,
            };

            const options = Options{
                .optimize = optimize,
                .symbol_prefix = symbol_prefix,
                .strip = false,
                .target = .{
                    .triple = target_triple,
                    .cpu_features = target.query.serializeCpuAlloc(b.allocator) catch @panic("oom"),
                },
                .wasm_features = wasm_features,
            };

            const run_codegen = b.addRunArtifact(codegen_exe);
            run_codegen.step.max_rss = byte_size.mib(3); // arbitrary amount
            run_codegen.addArg(stringifyZon(b, options, 1024));
            run_codegen.addFileArg(target_info);
            run_codegen.addFileArg(detected_intrinsics);
            handlers_module.addObjectFile(run_codegen.addOutputFileArg("wasmstint-interpreter.bc"));

            module_options.addOption([]const u8, "symbol_prefix", symbol_prefix);
        }

        const test_wasmstint_module = b.createModule(.{
            .root_source_file = b.path("src/root.zig"),
            .target = target,
            .optimize = optimize,
        });
        {
            const tests = b.addTest(.{
                .name = "wasmstint",
                .root_module = test_wasmstint_module,
                .use_llvm = use_llvm.ifPreferred(),
                .max_rss = byte_size.mib(470),
            });
            for (&[3]struct { []const u8, *Build.Module }{
                .{ "coz", coz_module },
                .{ "allocators", allocators_module },
                .{ "opcodes", opcodes_module },
            }) |info| {
                tests.root_module.addImport(info.@"0", info.@"1");
            }

            const run_tests = &b.addRunArtifact(tests).step;
            run_tests.max_rss = byte_size.mib(43);
            unit_tests_step.dependOn(run_tests);
        }
        {
            const tests = b.addTest(.{
                .name = "wasmstint.handlers",
                .root_module = b.createModule(.{
                    .root_source_file = b.path("src/handlers.zig"),
                    .target = target,
                    .optimize = optimize,
                }),
                .use_llvm = use_llvm.ifPreferred(),
                .max_rss = byte_size.mib(458),
            });
            for (&[2]struct { []const u8, *Build.Module }{
                .{ "opcodes", opcodes_module },
                .{ "wasmstint", test_wasmstint_module },
            }) |info| {
                tests.root_module.addImport(info.@"0", info.@"1");
            }

            const run_tests = &b.addRunArtifact(tests).step;
            run_tests.max_rss = byte_size.mib(25);
            unit_tests_step.dependOn(run_tests);
        }
        {
            const tests = b.addTest(.{
                .name = "wasmstint.interpreter",
                .root_module = b.createModule(.{
                    .root_source_file = b.path("src/interpreter.zig"),
                    .target = target,
                    .optimize = optimize,
                }),
                .use_llvm = use_llvm.ifPreferred(),
                .max_rss = byte_size.mib(473),
            });
            for (&[2]struct { []const u8, *Build.Module }{
                .{ "coz", coz_module },
                .{ "wasmstint", test_wasmstint_module },
            }) |info| {
                tests.root_module.addImport(info.@"0", info.@"1");
            }

            const run_tests = &b.addRunArtifact(tests).step;
            run_tests.max_rss = byte_size.mib(25);
            unit_tests_step.dependOn(run_tests);
        }

        break :wasmstint root_module;
    };
    {
        const tests = b.addTest(.{
            .name = "Interpreter",
            .root_module = b.createModule(.{
                .root_source_file = b.path("tests/Interpreter/root.zig"),
                .target = target,
                .optimize = optimize,
            }),
            .use_llvm = use_llvm.ifPreferred(),
            .max_rss = byte_size.mib(681),
        });
        for (&[3]struct { []const u8, *Build.Module }{
            .{ "wasm_features", wasm_options },
            .{ "wasmstint", wasmstint_module },
            .{ "WasmBuilder", wasm_builder_module },
        }) |info| {
            tests.root_module.addImport(info.@"0", info.@"1");
        }

        const run_tests = &b.addRunArtifact(tests).step;
        run_tests.max_rss = byte_size.mib(50); // arbitrary amount
        unit_tests_step.dependOn(run_tests);
    }

    const spectest_exe = runner: {
        var executables: [2]*Step.Compile = undefined;
        for (&executables) |*e| {
            const module = b.createModule(.{
                .root_source_file = b.path("src/spectest/main.zig"),
                .target = target,
                .optimize = optimize,
                .pic = pic,
            });
            for (&[5]struct { []const u8, *Build.Module }{
                .{ "file_content", file_content_module },
                .{ "wasmstint", wasmstint_module },
                .{ "cli_args", cli_args_module },
                .{ "coz", coz_module },
                .{ "allocators", allocators_module },
            }) |info| {
                module.addImport(info.@"0", info.@"1");
            }

            e.* = b.addExecutable(.{
                .name = "wasmstint-spectest",
                .root_module = module,
                .max_rss = byte_size.mib(793),
            });
        }

        const runner_exe, const check = executables;
        runner_exe.use_llvm = use_llvm.ifPreferred();

        b.getInstallStep().dependOn(&b.addInstallArtifact(runner_exe, .{}).step);
        check_step.dependOn(&check.step);

        {
            const run = b.addRunArtifact(runner_exe);
            if (b.args) |args| {
                run.addArgs(args);
            }

            b.step("run-wast", "Run the specification JSON test interpreter").dependOn(&run.step);
        }

        break :runner runner_exe;
    };

    {
        const wasip1_module = b.createModule(.{
            .root_source_file = b.path("src/WasiPreview1.zig"),
            .target = target,
            .optimize = optimize,
            // .link_libc = link_libc,
        });
        for (&[4]struct { []const u8, *Build.Module }{
            .{ "wasmstint", wasmstint_module },
            .{ "coz", coz_module },
            .{ "allocators", allocators_module },
            .{ "sys", sys_module },
        }) |info| {
            wasip1_module.addImport(info.@"0", info.@"1");
        }

        const wasip1_exe = exe: {
            var executables: [2]*Step.Compile = undefined;
            for (&executables) |*e| {
                const module = b.createModule(.{
                    .root_source_file = b.path("src/WasiPreview1/main.zig"),
                    .target = target,
                    .optimize = optimize,
                    .pic = pic,
                });
                for (&[7]struct { []const u8, *Build.Module }{
                    .{ "file_content", file_content_module },
                    .{ "wasmstint", wasmstint_module },
                    .{ "cli_args", cli_args_module },
                    .{ "WasiPreview1", wasip1_module },
                    .{ "coz", coz_module },
                    .{ "allocators", allocators_module },
                    .{ "sys", sys_module },
                }) |info| {
                    module.addImport(info.@"0", info.@"1");
                }

                e.* = b.addExecutable(.{
                    .name = "wasmstint-wasip1",
                    .root_module = module,
                    .max_rss = byte_size.mib(755),
                });
            }

            const runner_exe, const check = executables;
            runner_exe.use_llvm = use_llvm.ifPreferred();

            b.getInstallStep().dependOn(&b.addInstallArtifact(runner_exe, .{}).step);
            check_step.dependOn(&check.step);

            {
                const run = b.addRunArtifact(runner_exe);
                if (b.args) |args| {
                    run.addArgs(args);
                }

                b.step("run-wasip1", "Run the WASI (preview 1) application interpreter")
                    .dependOn(&run.step);
            }

            break :exe runner_exe;
        };

        const wasm_target = target: {
            var features_buf: [7]std.Target.wasm.Feature = undefined;
            var features = std.ArrayList(std.Target.wasm.Feature).initBuffer(&features_buf);
            if (wasm_features.simd128) {
                features.appendAssumeCapacity(.simd128);
            }
            if (wasm_features.tail_call) {
                features.appendAssumeCapacity(.tail_call);
            }

            features.appendSliceAssumeCapacity(&[5]std.Target.wasm.Feature{
                .bulk_memory,
                .multivalue,
                .extended_const,
                .mutable_globals,
                .nontrapping_fptoint,
            });
            break :target b.resolveTargetQuery(.{
                .cpu_arch = .wasm32,
                .os_tag = .wasi,
                .cpu_features_add = std.Target.wasm.featureSet(features.items),
            });
        };

        const tests_dir = b.path("tests/wasip1/zig");
        const tests_dir_handle = b.build_root.handle.openDir(
            b.graph.io,
            tests_dir.src_path.sub_path,
            .{ .iterate = true },
        ) catch @panic("could not open tests directory");

        const install_step = b.step("install-wasip1-samples", "Build sample WASI 0.1 programs");
        const test_step = b.step("test-wasip1-samples", "Test sample WASI 0.1 programs");

        const subprocess_module = b.createModule(.{
            .root_source_file = b.path("src/subprocess.zig"),
            .target = target,
            .optimize = optimize,
        });

        var tests_iter = tests_dir_handle.iterateAssumeFirstIteration();
        const bad_test_entry = "bad entry in tests directory";
        while (tests_iter.next(b.graph.io) catch @panic(bad_test_entry)) |tests_entry| {
            if (tests_entry.kind != .file or
                !std.mem.eql(u8, ".zig", std.fs.path.extension(tests_entry.name)))
            {
                continue;
            }

            const exe_name = b.dupe(tests_entry.name[0 .. tests_entry.name.len - 4]);
            const root_source_file = tests_dir.path(b, tests_entry.name);

            var executables: [2]*Step.Compile = undefined;
            for (&executables) |*e| {
                e.* = b.addExecutable(.{
                    .name = exe_name,
                    .root_module = b.createModule(.{
                        .root_source_file = root_source_file,
                        .target = wasm_target,
                        .optimize = optimize,
                    }),
                    .max_rss = byte_size.mib(242),
                });
            }

            const sample_exe, const check = executables;
            sample_exe.use_llvm = use_llvm.ifPreferred();
            check_step.dependOn(&check.step);

            install_step.dependOn(&b.addInstallArtifact(
                sample_exe,
                .{ .dest_dir = .{ .override = .{ .custom = "samples/zig" } } },
            ).step);

            const test_options = b.addOptions();
            test_options.addOptionPath("wasm", sample_exe.getEmittedBin());
            test_options.addOptionPath("interpreter", wasip1_exe.getEmittedBin());

            // TODO: To support running under QEMU, don't use subprocesses, maybe make a custom runner exe instead
            // - accepts both expected outputs and wasm to run
            // - unfortunately requires spearate WASIp1 runner
            const invoke_test = b.addTest(.{
                .name = sample_exe.name,
                .root_module = b.createModule(.{
                    .root_source_file = sample_exe.root_module.root_source_file,
                    .target = target,
                    .optimize = .Debug,
                }),
                .max_rss = byte_size.mib(399),
                .use_llvm = if (use_llvm == .never) false else null,
            });
            invoke_test.root_module.addOptions("test_paths", test_options);
            invoke_test.root_module.addImport("subprocess", subprocess_module);

            // Can't add to "check" step, since it would require building the WASM.
            const run_test = b.addRunArtifact(invoke_test);
            run_test.step.max_rss = byte_size.mib(44);
            test_step.dependOn(&run_test.step);
        }
    }

    wabt: {
        const wabt_dep = b.lazyDependency("wabt", .{}) orelse break :wabt;
        const spectest_dep = b.lazyDependency("spectest", .{}) orelse break :wabt;
        const wast2json = tools: {
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
                "-O1",
            };

            const wabt_lib = b.addLibrary(.{
                .name = "wabt",
                .root_module = b.createModule(.{
                    .target = b.graph.host,
                    .optimize = .ReleaseFast,
                }),
                .use_llvm = true,
                .max_rss = byte_size.mib(500), // arbitrary amount
            });
            wabt_lib.root_module.addConfigHeader(config_header);
            wabt_lib.root_module.addIncludePath(wabt_dep.path("include"));
            wabt_lib.root_module.addCSourceFiles(.{
                .root = wabt_dep.path("."),
                .files = &@import("tools/wabt.zon").src,
                .flags = flags,
            });
            wabt_lib.root_module.link_libcpp = true;

            const wast2json = b.addExecutable(.{
                .name = "wast2json",
                .root_module = b.createModule(.{
                    .target = b.graph.host,
                    .optimize = .ReleaseFast,
                }),
                .use_llvm = true,
                .max_rss = byte_size.mib(500),
            });
            wast2json.root_module.addConfigHeader(config_header);
            wast2json.root_module.addIncludePath(wabt_dep.path("include"));
            wast2json.root_module.addCSourceFile(.{
                .file = wabt_dep.path("src/tools/wast2json.cc"),
                .flags = flags,
            });
            wast2json.root_module.linkLibrary(wabt_lib);
            wast2json.root_module.link_libcpp = true;

            {
                const run = b.addRunArtifact(wast2json);
                if (b.args) |args| {
                    run.addArgs(args);
                }
                b.step("run-wast2json", "Run WABT wast2json executable").dependOn(&run.step);
            }

            break :tools wast2json;
        };

        const test_groups = @import("tests/testsuite.zon");
        const test_group_names = std.enums.values(std.meta.FieldEnum(@TypeOf(test_groups)));

        const test_spec_all_step = b.step("test-spec", "Run all specification tests");

        for (test_group_names) |group| {
            const group_tests: []const []const u8 = switch (group) {
                inline else => |current_group| &@field(test_groups, @tagName(current_group)),
            };
            const test_spec_group_step = step: switch (group) {
                inline else => |current_group| {
                    const group_name = comptime @tagName(current_group);
                    break :step b.step(
                        "test-spec-" ++ group_name,
                        "Run " ++ group_name ++ " specification tests",
                    );
                },
            };

            switch (group) {
                .simd => if (!wasm_features.simd128) {
                    test_spec_group_step.dependOn(
                        &b.addFail("to run SIMD tests, pass -Dsimd128").step,
                    );
                    continue;
                },
                .@"tail-call" => if (!wasm_features.tail_call) {
                    test_spec_group_step.dependOn(
                        &b.addFail("to run tail call tests, pass -Dtail-call").step,
                    );
                    continue;
                },
                else => {},
            }

            for (group_tests) |name| {
                const wast_name = b.fmt("{s}.wast", .{name});
                const path = spectest_dep.path(wast_name);
                test_spec_group_step.dependOn(
                    buildWastTest(b, spectest_exe, path, wast2json, wast_name),
                );
            }

            test_spec_all_step.dependOn(test_spec_group_step);
        }
        {
            const test_fuzzed_step = b.step(
                "test-spec-fuzzed",
                "Run WAST test cases discovered by fuzzing",
            );
            const fuzzed_test_dir = b.path("tests/fuzzed");
            for (&[_]struct { tests: []const []const u8, enabled: bool }{
                .{
                    .tests = &.{ "validation.wast", "execution.wast", "parsing.wast" },
                    .enabled = true,
                },
                .{
                    .tests = &.{"wasmi_diff.wast"},
                    .enabled = wasm_features.simd128,
                },
                // TODO: test for no tail call
            }) |group| {
                if (!group.enabled) {
                    continue;
                }

                for (group.tests) |name| {
                    const path = fuzzed_test_dir.path(b, name);
                    const test_step = buildWastTest(b, spectest_exe, path, wast2json, name);
                    test_fuzzed_step.dependOn(test_step);
                }
            }

            test_spec_all_step.dependOn(test_fuzzed_step);
        }
        {
            const test_regression_step = b.step(
                "test-spec-regression",
                "Run WAST test cases to check bug fixes",
            );
            const regression_test_names = [_][]const u8{ "x86_64_sysv.wast", "sleb128.wast" };
            const regression_test_dir = b.path("tests/regression");
            for (regression_test_names) |name| {
                const path = regression_test_dir.path(b, name);
                test_regression_step.dependOn(
                    buildWastTest(b, spectest_exe, path, wast2json, name),
                );
            }

            test_spec_all_step.dependOn(test_regression_step);
        }

        {
            const test_disabled_features = b.step(
                "test-spec-disabled",
                "Run WAST test cases for disabled features",
            );
            if (!wasm_features.simd128) {
                const path = b.path("tests/features/no-simd.wast");
                test_disabled_features.dependOn(
                    buildWastTest(b, spectest_exe, path, wast2json, "no-simd.wast"),
                );
            }

            test_spec_all_step.dependOn(test_disabled_features);
        }
    }
    {
        const fuzz_data_module = b.createModule(.{
            .root_source_file = b.path("fuzz/data.zig"),
            .target = target,
            .optimize = optimize,
        });
        {
            const ffi_test = b.addTest(.{
                .name = "fuzz_data",
                .root_module = fuzz_data_module,
                .max_rss = byte_size.mib(464),
                .use_llvm = use_llvm.ifPreferred(),
            });
            const ffi_tests_run = &b.addRunArtifact(ffi_test).step;
            ffi_tests_run.max_rss = byte_size.mib(16);
            unit_tests_step.dependOn(ffi_tests_run);
        }

        var rust_include_paths_buf: [2]Build.LazyPath = undefined;
        var rust_include_paths = std.ArrayList(Build.LazyPath).initBuffer(&rust_include_paths_buf);

        // Currently, this does not invoke `cargo build release`
        const rust_target_dir = b.path("fuzz/ffi/target");
        const native_target = b.graph.host.result;
        const chosen_target = target.result;
        if (native_target.cpu.arch == chosen_target.cpu.arch and
            native_target.os.tag == chosen_target.os.tag and
            native_target.abi == chosen_target.abi)
        {
            // Path to artifact for native target
            rust_include_paths.appendAssumeCapacity(rust_target_dir.path(b, "release"));
        } else if (chosen_target.cpu.arch == .aarch64 and
            chosen_target.os.tag == .linux and
            chosen_target.abi == .gnu)
        {
            const path = rust_target_dir.path(b, "aarch64-unknown-linux-gnu/release");
            rust_include_paths.appendAssumeCapacity(path);
        } else if (chosen_target.cpu.arch == .x86_64 and
            chosen_target.os.tag == .windows and
            chosen_target.abi == .gnu)
        {
            const path = rust_target_dir.path(b, "x86_64-pc-windows-gnu/release");
            rust_include_paths.appendAssumeCapacity(path);
        }

        // Rust can't compile `cdylib` on `aarch64-unknown-linux-musl`

        const fail_no_rust_include = if (rust_include_paths.items.len == 0)
            &b.addFail(
                \\could not determine include path for FFI wrapper:
                \\ run cargo build in ./fuzz/ffi
                \\ or manually add include path",
            ).step
        else
            null;

        const chosen_fuzz_runner = b.option(
            FuzzRunner,
            "fuzz-runner",
            "Specifies how a fuzz target is run",
        ) orelse FuzzRunner.standalone;

        const ffi_module = b.createModule(.{
            .root_source_file = b.path("fuzz/ffi/src/ffi.zig"),
            .link_libc = true, // links to Rust cdylib
            .target = target,
            .optimize = optimize,
        });
        ffi_module.addImport("wasm_features", wasm_options);
        ffi_module.addImport("fuzz_data", fuzz_data_module);

        for (rust_include_paths.items) |include_path| {
            ffi_module.addLibraryPath(include_path);
        }

        ffi_module.linkSystemLibrary(
            "wasmstint_fuzz_ffi",
            .{ .preferred_link_mode = .dynamic, .search_strategy = .paths_first },
        );

        // https://fitzgen.com/2022/10/24/how-fuzzy-are-your-fuzzers.html
        const smoke_test_step = b.step(
            "test-fuzz-smoke",
            "Run fuzz target tests to check properties (requires Rust)",
        );

        const FuzzTarget = enum {
            parsing,
            validation,
            execution,
            @"wasmi-diff",
        };

        for (std.enums.values(FuzzTarget)) |fuzz_target| {
            const target_module = b.createModule(.{
                .root_source_file = b.path(b.fmt("fuzz/targets/{t}.zig", .{fuzz_target})),
                .target = target,
                .optimize = optimize,
            });
            for (&[3]struct { []const u8, *Build.Module }{
                .{ "wasmstint", wasmstint_module },
                .{ "fuzz_data", fuzz_data_module },
                .{ "wasm_features", wasm_options },
            }) |info| {
                target_module.addImport(info.@"0", info.@"1");
            }

            const needs_ffi = switch (fuzz_target) {
                .parsing => false,
                else => true,
            };

            if (needs_ffi) {
                target_module.addImport("ffi", ffi_module);
            }

            const step_name = b.fmt("fuzz-{t}", .{fuzz_target});
            const smoke_test_name = b.fmt("{s}-smoke", .{step_name});
            const smoke_test: ?struct {
                max_rss: usize,
            } = switch (fuzz_target) {
                .validation => .{
                    .max_rss = byte_size.mib(184),
                },
                else => null,
            };
            // If in the future, Zig's builtin fuzz runner needs to be used, maybe passing
            // module options to toggle counters/smoke test will work.
            if (smoke_test) |test_info| {
                const run_smoke_test = &b.addRunArtifact(b.addTest(.{
                    .name = smoke_test_name,
                    .root_module = target_module,
                    .max_rss = test_info.max_rss,
                    .use_llvm = use_llvm.ifPreferred(),
                })).step;
                run_smoke_test.max_rss = byte_size.mib(15);
                smoke_test_step.dependOn(run_smoke_test);
            }

            const fuzz_target_name: []const u8 = b.fmt("{s}{s}", .{
                step_name,
                switch (interpreter_backend) {
                    .zig => "",
                    .assembly => "-asm",
                    .@"llvm-ir" => "-bc",
                },
            });
            const libfuzzer_harness_lib = b.addLibrary(.{
                .name = b.fmt("{s}-libfuzzer", .{fuzz_target_name}),
                .root_module = b.createModule(.{
                    .root_source_file = b.path("fuzz/harness/libfuzzer.zig"),
                    .target = target,
                    .optimize = optimize,
                    .pic = true, // afl-clang-lto seems to require PIC
                    .link_libc = true,
                }),
                .max_rss = byte_size.mib(498),
                .use_llvm = true,
                // .use_lld = options.project.use_llvm.interpreter,
            });
            libfuzzer_harness_lib.sanitize_coverage_trace_pc_guard = true; // required for AFL++
            libfuzzer_harness_lib.lto = .full;
            libfuzzer_harness_lib.bundle_compiler_rt = true;
            for (&[2]struct { []const u8, *Build.Module }{
                .{ "target", target_module },
                .{ "fuzz_data", fuzz_data_module },
            }) |info| {
                libfuzzer_harness_lib.root_module.addImport(info.@"0", info.@"1");
            }
            if (needs_ffi) {
                libfuzzer_harness_lib.root_module.addImport("ffi", ffi_module);
            }

            // TODO(zig): limit parallelism of afl-clang-lto https://github.com/ziglang/zig/issues/12101
            const afl_clang_lto = b.addSystemCommand(
                &.{ "afl-clang-lto", "-g", "-Wall", "-fsanitize=fuzzer", "-lwasmstint_fuzz_ffi", "-v" },
            );
            afl_clang_lto.disable_zig_progress = true;

            if (fail_no_rust_include) |fail| {
                afl_clang_lto.step.dependOn(fail);
            }

            if (pic != true) {
                afl_clang_lto.step.dependOn(&b.addFail("AFL fuzz harness requires -Dpic=true").step);
            }

            { // Unfortunately, filtering by file seems to be broken
                afl_clang_lto.addFileInput(b.path("fuzz/denylist.txt"));
                afl_clang_lto.setEnvironmentVariable(
                    "AFL_LLVM_DENYLIST",
                    // TODO(zig): allow environment variable of lazy path
                    // At least paths seem to be relative to the build script
                    "./fuzz/denylist.txt",
                );
            }

            afl_clang_lto.step.max_rss = byte_size.mib(268);

            afl_clang_lto.addArg("-o");
            const afl_output_exe: []const u8 = b.fmt("{s}-afl", .{fuzz_target_name});
            const afl_exe = afl_clang_lto.addOutputFileArg(afl_output_exe);

            afl_clang_lto.addArtifactArg(libfuzzer_harness_lib);

            for (rust_include_paths.items) |include_path| {
                afl_clang_lto.addArg("-L");
                afl_clang_lto.addDirectoryArg(include_path);
            }

            const standalone_exe = b.addExecutable(.{
                .name = b.fmt("{s}-standalone", .{fuzz_target_name}),
                .root_module = b.createModule(.{
                    .root_source_file = b.path("fuzz/harness/main.zig"),
                    .target = target,
                    .optimize = optimize,
                    .pic = pic,
                }),
                .max_rss = byte_size.mib(373),
                .use_llvm = use_llvm.ifPreferred(),
            });
            if (fail_no_rust_include) |fail| {
                standalone_exe.step.dependOn(fail);
            }
            for (&[5]struct { []const u8, *Build.Module }{
                .{ "target", target_module },
                .{ "ffi", ffi_module },
                .{ "fuzz_data", fuzz_data_module },
                .{ "file_content", file_content_module },
                .{ "cli_args", cli_args_module },
            }) |info| {
                standalone_exe.root_module.addImport(info.@"0", info.@"1");
            }

            const runner_step: *Step.Run = switch (chosen_fuzz_runner) {
                .afl => afl: {
                    const run_afl = Step.Run.create(b, afl_output_exe);
                    run_afl.addFileArg(afl_exe);
                    break :afl run_afl;
                },
                .standalone => b.addRunArtifact(standalone_exe),
            };

            if (b.args) |args| {
                runner_step.addArgs(args);
            }

            b.step(step_name, "Run a fuzz test (requires Rust)").dependOn(&runner_step.step);
        }
    }
}

fn buildWastTest(
    b: *Build,
    runner: *Step.Compile,
    wast_path: Build.LazyPath,
    wast2json_exe: *Step.Compile,
    name: []const u8,
) *Step {
    std.debug.assert(std.mem.endsWith(u8, name, ".wast"));
    var wast2json = b.addRunArtifact(wast2json_exe);
    wast2json.step.max_rss = byte_size.mib(19);
    wast2json.addFileArg(wast_path);
    wast2json.addArgs(&.{
        "--enable-extended-const",
        // "--disable-simd",
        "--enable-tail-call",
        "--output",
    });
    const output_json = wast2json.addOutputFileArg(b.fmt("{s}.json", .{name[0 .. name.len - 5]}));

    const run_test = b.addRunArtifact(runner);
    run_test.stdio_limit = .limited(15 * 1024 * 1024);
    run_test.step.max_rss = byte_size.mib(45);
    run_test.setName(name);
    run_test.addArg("--run");
    run_test.addFileArg(output_json);
    run_test.expectExitCode(0);
    return &run_test.step;
}

const std = @import("std");
const builtin = @import("builtin");
const Build = std.Build;
const Step = Build.Step;
