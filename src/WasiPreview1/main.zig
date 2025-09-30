const default_invoke = "_start";
const memory_export = "memory";

const Arguments = cli_args.CliArgs(.{
    .description = "Interpreters WebAssembly programs using the `wasi_snapshot_preview1` ABI",
    .flags = &[_]cli_args.Flag{
        cli_args.Flag.string(
            .{
                .long = "module",
                .short = 'm',
                .description = "Path to .wasm program to execute",
            },
            "PATH",
        ).required(),
        cli_args.Flag.string(
            .{
                .long = "invoke",
                .description = "Name of the function to call",
            },
            "NAME",
        ).withDefault(default_invoke),

        cli_args.Flag.boolean(.{
            .long = "print-exit-code",
            .description = "Prints the application's unmodified exit code to stderr",
        }),

        cli_args.Flag.integer(
            .{
                .long = "rt-rng-seed",
                .description = "RNG seed used for internal data structures",
            },
            "SEED",
            u128,
        ),

        cli_args.Flag.integerSizeSuffix(
            .{
                .long = "max-stack-size",
                .description = "Limits the size of the WASM value/call stack",
            },
            u32,
        ).withDefault(8192),
        cli_args.Flag.integerSizeSuffix(
            .{
                .long = "max-memory-size",
                .description = "Upper bound on the size of WASM linear memory, in bytes",
            },
            usize,
        ).withDefault(1 * 1024 * 1024 * 1024), // 1 GiB

        cli_args.Flag.remainder,

        env_flag,
    },
});

const env_flag = cli_args.Flag.custom(
    .{ .long = "env", .description = "Set or inherit an environment variable for the program" },
    .{ .optional = false, .name = "NAME[=VAL]" },
);

// TODO: As an optimization, when env var import is required, continue a filling of a EnvMap, pausing when
// current variable being looked for is found (this avoids making a huge EnvMap, but is this premature optimization?)

fn oom(context: []const u8) noreturn {
    std.debug.panic("out of memory: {s}", .{context});
}

const ErrorCode = enum(u8) {
    failure = 1,
    bad_arg = 2,

    fn printInitialMessage(
        comptime fmt: []const u8,
        args: anytype,
        color: std.Io.tty.Config,
        stderr: *std.Io.Writer,
    ) std.Io.Writer.Error!void {
        color.setColor(stderr, .bright_red) catch {};
        stderr.writeAll("error: ") catch {};
        color.setColor(stderr, .reset) catch {};
        stderr.print(fmt ++ "\n", args) catch {};
    }

    fn printWithFollowup(
        code: ErrorCode,
        comptime fmt: []const u8,
        args: anytype,
        context: anytype,
        comptime printFollowupMessage: fn (
            @TypeOf(context),
            std.Io.tty.Config,
            *std.Io.Writer,
        ) std.Io.Writer.Error!void,
    ) u8 {
        @branchHint(.cold);
        var buf: [256]u8 align(16) = undefined;
        const stderr = std.debug.lockStderrWriter(&buf);
        const color = std.Io.tty.detectConfig(
            @as(*std.fs.File.Writer, @fieldParentPtr("interface", stderr)).file,
        );
        printInitialMessage(fmt, args, color, stderr) catch {};
        printFollowupMessage(context, color, stderr) catch {};
        stderr.flush() catch {};
        return @intFromEnum(code);
    }

    fn print(code: ErrorCode, comptime fmt: []const u8, args: anytype) u8 {
        return printWithFollowup(
            code,
            fmt,
            args,
            {},
            struct {
                fn nothing(
                    _: void,
                    _: std.Io.tty.Config,
                    _: *std.Io.Writer,
                ) std.Io.Writer.Error!void {}
            }.nothing,
        );
    }
};

const ParsedArguments = struct {
    forwarded: WasiPreview1.Arguments.List,
    flags: Arguments.Parsed,
    environ: WasiPreview1.Environ,
};

fn parseArguments(scratch: *ArenaAllocator, arena: *ArenaAllocator) ParsedArguments {
    var parser: Arguments = undefined;
    parser.init();

    const ParseCustomArguments = struct {
        const use_windows_peb = builtin.os.tag == .windows and !builtin.link_libc;
        environ: WasiPreview1.Environ.List = .empty,
        scratch: *ArenaAllocator,
        scanned_env_vars: ScannedEnvVars = .empty,
        unscanned_env_vars: if (use_windows_peb) ?[*:0]u16 else [][*:0]u8,

        const ScannedEnvVars = std.ArrayHashMapUnmanaged(
            WasiPreview1.Environ.Pair,
            void,
            ScannedEnvVarsContext,
            true,
        );

        const ScannedEnvVarsContext = struct {
            pub fn hash(_: @This(), key: WasiPreview1.Environ.Pair) u32 {
                return std.hash.CityHash32.hash(key.name());
            }

            pub fn eql(
                _: @This(),
                a: WasiPreview1.Environ.Pair,
                b: WasiPreview1.Environ.Pair,
                _: usize,
            ) bool {
                return std.mem.eql(u8, a.name(), b.name());
            }
        };

        fn init(args: *@This(), scratch_arena: *ArenaAllocator) void {
            args.* = .{
                .scratch = scratch_arena,
                .unscanned_env_vars = if (use_windows_peb)
                    std.os.windows.peb().ProcessParameters.Environment
                else
                    std.os.environ,
            };

            if (!use_windows_peb) {
                args.scanned_env_vars.ensureTotalCapacity(
                    scratch_arena.allocator(),
                    args.unscanned_env_vars.len,
                ) catch oom("scanned env vars");
            }
        }

        fn emptyEnviron(
            key: [:0]const u8,
            results_arena: *ArenaAllocator,
        ) WasiPreview1.Environ.Pair {
            const key_truncated = key[0..@min(key.len, WasiPreview1.Environ.Pair.max_len)];
            const s = results_arena.allocator().alloc(u8, key_truncated.len + 1) catch
                oom("empty env var");
            s[key_truncated.len] = '=';
            const pair = WasiPreview1.Environ.Pair.initTruncated(s) catch unreachable;
            std.debug.assert(pair.value().len == 0);
            return pair;
        }

        const ScannedEnvironGetContext = struct {
            pub fn hash(_: @This(), key: [:0]const u8) u32 {
                return std.hash.CityHash32.hash(key);
            }

            pub fn eql(
                _: @This(),
                a: [:0]const u8,
                b: WasiPreview1.Environ.Pair,
                _: usize,
            ) bool {
                return std.mem.eql(u8, a, b.name());
            }
        };

        fn scanNextInheritedEnviron(
            self: *@This(),
            key: [:0]const u8,
            results_arena: *ArenaAllocator,
        ) WasiPreview1.Environ.Pair {
            if (self.scanned_env_vars.getKeyAdapted(key, ScannedEnvironGetContext{})) |found| {
                return found;
            } else if (use_windows_peb) {
                std.debug.panic("TODO: std.unicode.calcWtf8Len");
            } else {
                while (self.unscanned_env_vars.len > 0) {
                    defer self.unscanned_env_vars = self.unscanned_env_vars[1..];

                    const entry = WasiPreview1.Environ.Pair.initTruncated(
                        std.mem.sliceTo(self.unscanned_env_vars[0], 0),
                    ) catch unreachable;

                    self.scanned_env_vars.putAssumeCapacity(entry, {});

                    if (std.mem.eql(u8, key, entry.name())) {
                        return entry.dupe(results_arena.allocator()) catch
                            oom("inherited env var");
                    }
                }

                return emptyEnviron(key, results_arena);
            }
        }

        fn parse(
            self: *@This(),
            comptime flag: Arguments.FlagEnum,
            args: *cli_args.ArgIterator,
            results_arena: *ArenaAllocator,
            diag: ?*cli_args.Flag.Diagnostics,
        ) cli_args.Flag.InvalidError!void {
            switch (flag) {
                .env => {
                    const str = args.next() orelse return env_flag.info.reportMissing(
                        diag,
                        env_flag.arg_help.?,
                    );

                    const pair = pair: {
                        const set = WasiPreview1.Environ.Pair.initTruncated(str) catch
                            break :pair self.scanNextInheritedEnviron(str, results_arena);

                        break :pair try set.dupe(results_arena.allocator());
                    };

                    try self.environ.append(self.scratch.allocator(), pair);
                },
                else => unreachable,
            }
        }
    };

    var custom_args: ParseCustomArguments = undefined;
    custom_args.init(scratch);
    var args = cli_args.ArgIterator.initProcessArgs(scratch) catch oom("argv");
    _ = args.next().?;
    const parsed = parser.remainingArgumentsWithCustom(
        &args,
        arena,
        &custom_args,
        ParseCustomArguments.parse,
    ) catch oom("CLI arguments");

    var forwarded = WasiPreview1.Arguments.List.initCapacity(
        arena.allocator(),
        std.math.cast(u32, args.remaining.len + 1) orelse
            return oom("too many CLI arguments to forward"),
    ) catch oom("forwarded CLI argument list");

    forwarded.appendBounded(.empty) catch unreachable; // reserve space for program name

    while (args.nextDupe(arena) catch oom("forwarded CLI argument")) |a| {
        forwarded.appendBounded(.initTruncated(a)) catch oom("forwarded CLI argument");
    }

    return .{
        .flags = parsed,
        .forwarded = forwarded,
        .environ = (custom_args.environ.dupe(arena.allocator()) catch oom("env vars")).environ(),
    };
}

const max_fuel = wasmstint.Interpreter.Fuel{ .remaining = std.math.maxInt(u32) };

pub fn main() u8 {
    var arena = ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    var scratch = ArenaAllocator.init(std.heap.page_allocator);
    defer scratch.deinit();

    const all_arguments = parseArguments(&scratch, &arena);
    const arguments = all_arguments.flags;

    if (std.mem.eql(u8, arguments.invoke, memory_export)) {
        return ErrorCode.bad_arg.print("cannot use " ++ memory_export ++ " as an entrypoint", .{});
    }

    const fmt_wasm_path = std.fmt.allocPrint(
        arena.allocator(),
        "{f}",
        .{std.unicode.fmtUtf8(arguments.module)},
    ) catch oom("path to wasm file");

    const forwarded_arguments = args: {
        var forwarded = all_arguments.forwarded;
        const program_name = arena.allocator().dupe(
            u8,
            std.fs.path.basename(arguments.module),
        ) catch oom("program name");

        _ = forwarded.replaceAt(
            0,
            .initTruncated(program_name),
        ) catch oom("forwarded CLI argument 0");

        break :args forwarded.arguments();
    };

    const wasm_binary = wasmstint.FileContent.readFileZ(
        std.fs.cwd(),
        arguments.module,
    ) catch |e| switch (e) {
        error.OutOfMemory => oom("module bytes"),
        else => |io_err| return ErrorCode.bad_arg.print(
            "failed to open program file {s}, {t}",
            .{ fmt_wasm_path, io_err },
        ),
    };

    const csprng = WasiPreview1.Csprng.os;
    const rt_rng_num: u128 = arguments.@"rt-rng-seed" orelse seed: {
        var seed: u128 = undefined;
        csprng.get(std.mem.asBytes(&seed)) catch |e|
            return ErrorCode.failure.print("could not access OS CSPRNG: {t}", .{e});
        break :seed seed;
    };

    const rt_rng_seeds: [2]u64 = .{ @truncate(rt_rng_num), @truncate(rt_rng_num >> 64) };

    _ = scratch.reset(.retain_capacity);
    var parse_diagnostics = std.Io.Writer.Allocating.init(arena.allocator());
    const parsed_module = module: {
        var wasm: []const u8 = wasm_binary.contents;
        break :module wasmstint.Module.parse(
            arena.allocator(),
            &wasm,
            &scratch,
            .{ .diagnostics = .init(&parse_diagnostics.writer), .random_seed = rt_rng_seeds[0] },
        ) catch |e| switch (e) {
            error.OutOfMemory => oom("module"),
            error.InvalidWasm => return ErrorCode.failure.print(
                "module {s} is invalid, {s}",
                .{ fmt_wasm_path, parse_diagnostics.written() },
            ),
            error.MalformedWasm => return ErrorCode.failure.print(
                "failed to parse module {s}: {s}",
                .{ fmt_wasm_path, parse_diagnostics.written() },
            ),
            else => return ErrorCode.failure.print(
                "could not parse module {s}: {t}",
                .{ fmt_wasm_path, e },
            ),
        };
    };
    _ = scratch.reset(.retain_capacity);

    std.debug.assert(parse_diagnostics.written().len == 0);
    // TODO: switch to enable lazy validation, also helper thread to validate in background
    const validation_finished = parsed_module.finishCodeValidation(
        arena.allocator(),
        &scratch,
        .init(&parse_diagnostics.writer),
    ) catch |e| switch (e) {
        error.OutOfMemory => oom("module code entries"),
        error.InvalidWasm => return ErrorCode.failure.print(
            "invalid function in module {s}, {s}",
            .{ fmt_wasm_path, parse_diagnostics.written() },
        ),
        error.MalformedWasm => return ErrorCode.failure.print(
            "malformed function in module {s}, {s}",
            .{ fmt_wasm_path, parse_diagnostics.written() },
        ),
        else => return ErrorCode.failure.print(
            "failed to parse function in module {s}: {t}",
            .{ fmt_wasm_path, e },
        ),
    };
    _ = scratch.reset(.retain_capacity);

    std.debug.assert(validation_finished);

    var wasi = WasiPreview1.init(
        std.heap.page_allocator,
        .{
            .args = forwarded_arguments,
            .environ = all_arguments.environ,
            .fd_rng_seed = rt_rng_seeds[1],
            .csprng = csprng,
        },
    ) catch |e| switch (e) {
        error.OutOfMemory => oom("WASIp1 state"),
    };
    defer wasi.deinit();

    var import_error: wasmstint.runtime.ImportProvider.FailedRequest = undefined;
    var module_allocating = wasmstint.runtime.ModuleAllocating.begin(
        parsed_module,
        wasi.importProvider(),
        arena.allocator(),
        &import_error,
    ) catch |e| switch (e) {
        error.OutOfMemory => oom("WASM module allocation"),
        error.ImportFailure => return ErrorCode.failure.print("{f}", .{import_error}),
    };

    while (module_allocating.nextMemoryType()) |ty| {
        wasmstint.runtime.paged_memory.allocate(
            &module_allocating,
            ty.limits.min * wasmstint.runtime.MemInst.page_size,
            arguments.@"max-memory-size",
        ) catch |e| switch (e) {
            error.LimitsMismatch => unreachable, // bad mem
            error.OutOfMemory => oom("WASM linear memory"),
        };
    }

    while (module_allocating.nextTableType()) |_| {
        wasmstint.runtime.table_allocator.allocateForModule(
            &module_allocating,
            arena.allocator(),
            arguments.@"max-memory-size" / 16,
        ) catch |e| switch (e) {
            error.LimitsMismatch => unreachable, // bad table
            error.OutOfMemory => oom("WASM table"),
        };
    }

    var module_allocated = module_allocating.finish() catch unreachable;

    var interp: wasmstint.Interpreter = undefined;
    {
        // TODO: allocator for interpreter that uses windows VirtualAlloc reserve
        const start = interp.init(
            std.heap.page_allocator,
            .{ .stack_reserve = arguments.@"max-stack-size" },
        ) catch oom("interpreter stack");

        var instantiate_fuel = max_fuel;
        const instantiate_state = start.instantiateModule(
            arena.allocator(),
            &module_allocated,
            &instantiate_fuel,
        ) catch oom("WASM module instantiation");

        switch (mainLoop(
            instantiate_state,
            .{ .limited = &instantiate_fuel },
            arena.allocator(),
            &wasi,
            null,
        )) {
            .finished => |done| {
                // WASM spec says start (not to be confused with `_start`) has no results
                std.debug.assert(done.result_types.len == 0);
            },
            .failure => |exit_code| {
                @branchHint(.cold);
                return exit_code;
            },
        }
    }

    const module = module_allocated.assumeInstantiated();
    const fmt_entrypoint = std.unicode.fmtUtf8(arguments.invoke);
    const exports: struct {
        memory: *wasmstint.runtime.MemInst,
        entrypoint: wasmstint.runtime.FuncAddr,
    } = exports: {
        const all_exports = module.exports();

        var entrypoint: ?wasmstint.runtime.FuncAddr = null;
        var memory: ?*wasmstint.runtime.MemInst = null;

        // Check that memory name != entrypoint name occurs earlier
        for (0..all_exports.len) |i| {
            const exp = all_exports.at(i);
            const exp_name = exp.name.bytes();
            if (std.mem.eql(u8, exp_name, arguments.invoke)) {
                std.debug.assert(entrypoint == null);
                entrypoint = switch (exp.val) {
                    .func => |func| func,
                    else => return ErrorCode.failure.print(
                        "expected entrypoint {f} to be a function, but got a {s}",
                        .{ fmt_entrypoint, @tagName(exp.val) },
                    ),
                };
            } else if (std.mem.eql(u8, memory_export, exp_name)) {
                std.debug.assert(memory == null);
                memory = switch (exp.val) {
                    .mem => |mem| mem,
                    else => return ErrorCode.failure.print(
                        memory_export ++ " export was unexpectedly a {s}",
                        .{@tagName(exp.val)},
                    ),
                };
            }

            if (entrypoint != null and memory != null) {
                break;
            }
        }

        break :exports .{
            .entrypoint = entrypoint orelse return ErrorCode.failure.printWithFollowup(
                "could not find exported entrypoint {f}",
                .{fmt_entrypoint},
                all_exports,
                struct {
                    fn printFollowupMessage(
                        available_exports: wasmstint.runtime.ModuleInst.ExportVals,
                        color: std.Io.tty.Config,
                        out: *std.Io.Writer,
                    ) std.Io.Writer.Error!void {
                        color.setColor(out, .bright_cyan) catch {};
                        try out.writeAll("note: ");
                        color.setColor(out, .reset) catch {};
                        if (available_exports.len == 0) {
                            try out.writeAll("module does not provide any exports\n");
                        } else {
                            try out.writeAll("module's available entry points are:\n");
                            for (0..available_exports.len) |i| {
                                const exp = available_exports.at(i);
                                if (exp.val != .func) {
                                    continue;
                                }

                                const func = exp.val.func.signature();
                                if (func.param_count != 0 or func.result_count != 0) {
                                    continue;
                                }

                                try out.print(
                                    "{f}\n",
                                    .{std.unicode.fmtUtf8(exp.name.bytes())},
                                );
                            }
                        }
                    }
                }.printFollowupMessage,
            ),
            .memory = memory orelse
                return ErrorCode.failure.print("could not find exported memory", .{}),
        };
    };

    switch (mainLoop(
        start_call: {
            var starting_fuel = max_fuel;
            break :start_call interp.reset().awaiting_host.beginCall(
                std.heap.page_allocator,
                exports.entrypoint,
                &.{},
                &starting_fuel,
            ) catch |e| switch (e) {
                error.OutOfMemory => oom("entrypoint function call"),
                error.ValueTypeOrCountMismatch => return ErrorCode.failure.print(
                    "expected entrypoint function {f} to have no arguments",
                    .{fmt_entrypoint},
                ),
                error.ValidationNeeded => unreachable,
            };
        },
        .unlimited,
        arena.allocator(),
        &wasi,
        exports.memory,
    )) {
        .finished => |done| {
            std.debug.assert(done.result_types.len == 0);
            // TODO: get exit code
        },
        .failure => |exit_code| {
            @branchHint(.cold);
            return exit_code;
        },
    }

    defer interp.deinit(std.heap.page_allocator);

    if (arguments.@"print-exit-code") {
        // ("\nExited with code: {}\n");
    }

    @panic("TODO");

    // TODO: exit codes nonsense https://github.com/WebAssembly/wasi-cli/issues/11
}

const LoopResult = union(enum) {
    finished: wasmstint.Interpreter.State.AwaitingHost,
    failure: u8,
};

const FuelChecking = union(enum) {
    unlimited,
    limited: *wasmstint.Interpreter.Fuel,
};

fn mainLoop(
    initial_state: wasmstint.Interpreter.State,
    fuel_checking: FuelChecking,
    table_allocator: std.mem.Allocator,
    wasi: *WasiPreview1,
    memory: ?*wasmstint.runtime.MemInst,
) LoopResult {
    var local_fuel = max_fuel;
    const fuel = switch (fuel_checking) {
        .unlimited => &local_fuel,
        .limited => |limit| limit,
    };

    var state = initial_state;
    while (true) {
        state = next: switch (state) {
            .awaiting_host => |*host| if (host.currentHostFunction() != null) {
                if (memory) |mem_inst| {
                    break :next wasi.dispatch(host, mem_inst, fuel);
                } else {
                    @branchHint(.cold);
                    return .{
                        .failure = ErrorCode.failure.print(
                            "WASI cannot access exports until module initializer has finished running",
                            .{},
                        ),
                    };
                }
            } else {
                return .{ .finished = host.* };
            },
            .awaiting_validation => unreachable,
            .call_stack_exhaustion => oom("call stack exhausted"), // TODO: print stack trace
            .interrupted => |*interrupt| {
                switch (interrupt.cause) {
                    .out_of_fuel => switch (fuel_checking) {
                        .limited => {
                            @branchHint(.cold);
                            // TODO: print stack trace
                            return .{ .failure = ErrorCode.failure.print("out of fuel", .{}) };
                        },
                        .unlimited => {},
                    },
                    .memory_grow => |*grow| wasmstint.runtime.paged_memory.grow(grow),
                    .table_grow => |*grow| wasmstint.runtime.table_allocator.grow(
                        grow,
                        table_allocator,
                    ),
                }

                break :next interrupt.resumeExecution(fuel);
            },
            .trapped => |*trapped| {
                @branchHint(.cold);
                return .{ .failure = ErrorCode.failure.print("trap {t}", .{trapped.trap.code}) };
            },
        };
    }
}

const std = @import("std");
const builtin = @import("builtin");
const ArenaAllocator = std.heap.ArenaAllocator;
const wasmstint = @import("wasmstint");
const cli_args = @import("cli_args");
const WasiPreview1 = @import("WasiPreview1");
