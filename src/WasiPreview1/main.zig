const default_invoke = "_start";
const memory_export = "memory";

const Arguments = cli_args.CliArgs(.{
    .description = "Interpreter of WebAssembly programs using the `wasi_snapshot_preview1` ABI",
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
                .long = "rt-memory-limit",
                .description = "Upper bound on memory usage for runtime structures, in bytes",
            },
            u32,
        ).withDefault(16 * 1024 * 1024),

        cli_args.Flag.integerSizeSuffix(
            .{
                .long = "max-stack-size",
                .description = "Limits the size of the WASM value/call stack",
            },
            u32,
        ).withDefault(1024 * 256),
        cli_args.Flag.integerSizeSuffix(
            .{
                .long = "max-memory-size",
                .description = "Upper bound on the size of WASM linear memory, in bytes",
            },
            usize,
        ).withDefault(1 * 1024 * 1024 * 1024), // 1 GiB

        cli_args.Flag.string(
            .{
                .long = "log-file",
                .description = "Write log messages to the given file. Defaults to stderr.",
            },
            "PATH",
        ),

        cli_args.Flag.enumeration(
            std.log.Level,
            .{ .long = "log-level", .description = "Which log messages to include." },
            "LEVEL",
        ),

        env_flag,

        dir_flag,

        cli_args.Flag.remainder,
    },
});

const env_flag = cli_args.Flag.custom(
    .{ .long = "env", .description = "Set or inherit an environment variable for the program" },
    .{ .name = "NAME[=VAL]" },
);

const dir_flag = cli_args.Flag.custom(
    .{
        .long = "dir",
        .description = "Pass pre-opened directory to the program\n\n" ++
            "    GUEST is the name of the directory from the perspective of the program.\n\n" ++
            "    PERM is either \"ro\" for read-only access, or \"rw\" for read-write access.",
    },
    .{ .name = "HOST GUEST PERM" },
);

fn oom(context: []const u8) noreturn {
    std.debug.panic("out of memory: {s}", .{context});
}

const Error = error{
    BadCliFlag,
    GenericError,
};

const fail = struct {
    fn printInitialMessage(
        comptime fmt: []const u8,
        args: anytype,
        stderr: Io.Terminal,
    ) Io.Writer.Error!void {
        stderr.setColor(.bright_red) catch {};
        stderr.writer.writeAll("error: ") catch {};
        stderr.setColor(.reset) catch {};
        stderr.writer.print(fmt ++ "\n", args) catch {};
    }

    fn formatWithFollowup(
        err: Error,
        comptime fmt: []const u8,
        args: anytype,
        context: anytype,
        comptime printFollowupMessage: fn (@TypeOf(context), Io.Terminal) Io.Writer.Error!void,
    ) Error {
        @branchHint(.cold);
        var buf: [256]u8 align(16) = undefined;
        const stderr = std.debug.lockStderr(&buf).terminal();
        printInitialMessage(fmt, args, stderr) catch {};
        printFollowupMessage(context, stderr) catch {};
        stderr.writer.flush() catch {};
        return err;
    }

    fn format(err: Error, comptime fmt: []const u8, args: anytype) Error {
        return formatWithFollowup(
            err,
            fmt,
            args,
            {},
            struct {
                fn nothing(_: void, _: Io.Terminal) Io.Writer.Error!void {}
            }.nothing,
        );
    }

    fn print(err: Error, msg: []const u8) Error {
        return format(err, "{s}", .{msg});
    }
};

const ParsedArguments = struct {
    forwarded: WasiPreview1.Arguments.List,
    flags: Arguments.Parsed,
    environ: WasiPreview1.Environ,
    preopen_dirs: []const PreopenDir,
};

const PreopenDir = struct {
    /// Path to open.
    ///
    /// Opened before execution of WASM begins.
    host: [:0]const u8,
    /// Path of the directory from the point of view of the guest.
    guest: WasiPreview1.Path,
    permissions: WasiPreview1.PreopenDir.Permissions = .none,
};

const CustomArgumentParser = struct {
    const use_windows_peb = builtin.os.tag == .windows and !builtin.link_libc;

    arena: *ArenaAllocator,
    environ: WasiPreview1.Environ.List = .empty,
    environ_map: std.process.Environ.Map,
    preopen_dirs: std.ArrayList(PreopenDir) = .empty,

    fn init(parser: *CustomArgumentParser, environ: std.process.Environ, arena: *ArenaAllocator) void {
        parser.* = .{
            .arena = arena,
            .environ_map = environ.createMap(arena.allocator()) catch oom("env map"),
        };
    }

    fn lookupEnviron(
        parser: *CustomArgumentParser,
        key: [:0]const u8,
    ) std.mem.Allocator.Error!WasiPreview1.Environ.Pair {
        if (parser.environ_map.get(key)) |v| {
            return WasiPreview1.Environ.Pair.initTruncated(v) catch unreachable;
        } else {
            @branchHint(.unlikely);
            const key_truncated = key[0..@min(key.len, WasiPreview1.Environ.Pair.max_len - 1)];
            const buf = try parser.arena.allocator().alloc(u8, key_truncated.len + 1);
            buf[key_truncated.len] = '=';
            @memcpy(buf[0..key_truncated.len], key[0..key_truncated.len]);
            const empty = WasiPreview1.Environ.Pair.initTruncated(buf) catch unreachable;
            std.debug.assert(empty.value().len == 0);
            return empty;
        }
    }

    fn parse(
        parser: *CustomArgumentParser,
        comptime flag: Arguments.FlagEnum,
        args: *cli_args.ArgIterator,
        results_arena: *ArenaAllocator,
        diag: ?*cli_args.Flag.Diagnostics,
    ) cli_args.Flag.InvalidError!void {
        switch (flag) {
            .env => {
                const key = args.next() orelse
                    return env_flag.info.reportMissing(diag, env_flag.arg_help.?);

                const pair = pair: {
                    const set = WasiPreview1.Environ.Pair.initTruncated(key) catch |e| switch (e) {
                        error.MissingEqualsSign => try parser.lookupEnviron(key),
                    };

                    break :pair try set.dupe(results_arena.allocator());
                };

                try parser.environ.append(parser.arena.allocator(), pair);
            },
            .dir => {
                const host = try args.nextDupe(results_arena) orelse {
                    return cli_args.Flag.Diagnostics.report(
                        diag,
                        "missing HOST directory path for --dir flag",
                    );
                };

                const host_fmt = std.unicode.fmtUtf8(host);
                const guest = try args.nextDupe(results_arena) orelse {
                    return cli_args.Flag.Diagnostics.reportFmt(
                        diag,
                        results_arena,
                        "missing GUEST directory name for --dir {f}",
                        .{host_fmt},
                    );
                };
                const guest_fmt = std.unicode.fmtUtf8(guest);
                const guest_utf8 = WasiPreview1.Path.init(guest) catch |e| return switch (e) {
                    error.InvalidUtf8 => cli_args.Flag.Diagnostics.reportFmt(
                        diag,
                        results_arena,
                        "GUEST directory {[guest]f} must be valid UTF-8 in --dir {[host]f}",
                        .{ .host = host_fmt, .guest = guest_fmt },
                    ),
                    error.PathTooLong => cli_args.Flag.Diagnostics.reportFmt(
                        diag,
                        results_arena,
                        "length of GUEST directory is too long in --dir {[host]f} {[guest]f}",
                        .{ .host = host_fmt, .guest = guest_fmt },
                    ),
                };

                const entry = try parser.preopen_dirs.addOne(parser.arena.allocator());
                entry.* = PreopenDir{ .host = host, .guest = guest_utf8 };

                const bad_perm_note =
                    "note: pass 'ro' for read-only access, or 'rw' for read-write access";

                const perm = args.next() orelse {
                    return cli_args.Flag.Diagnostics.reportFmt(
                        diag,
                        results_arena,
                        "missing PERM string for --dir {f} {s}\n" ++ bad_perm_note,
                        .{ host_fmt, guest },
                    );
                };

                if (std.mem.eql(u8, perm, "rw")) {
                    entry.permissions.write = true;
                } else if (!std.mem.eql(u8, perm, "ro")) {
                    return cli_args.Flag.Diagnostics.reportFmt(
                        diag,
                        results_arena,
                        "unknown permission {f} in --dir {f} {s}",
                        .{
                            std.unicode.fmtUtf8(perm),
                            host_fmt,
                            guest,
                        },
                    );
                }
            },
            else => unreachable,
        }
    }
};

fn parseArguments(
    init: *const std.process.Init.Minimal,
    scratch: *ArenaAllocator,
    arena: *ArenaAllocator,
) ParsedArguments {
    var parser: Arguments = undefined;
    parser.init();

    var custom_args: CustomArgumentParser = undefined;
    custom_args.init(init.environ, scratch);
    var args = cli_args.ArgIterator.initProcessArgs(scratch, init.args) catch oom("argv");
    _ = args.next().?;
    const parsed = parser.remainingArgumentsWithCustom(
        &args,
        arena,
        &custom_args,
        CustomArgumentParser.parse,
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
        .preopen_dirs = arena.allocator().dupe(PreopenDir, custom_args.preopen_dirs.items) catch
            oom("preopen dirs"),
    };
}

var log_file: ?Io.File = null;
var log_level: ?std.log.Level = std_options.log_level;
var log_counter: u64 = 0;

fn logger(
    comptime level: std.log.Level,
    comptime scope: @EnumLiteral(),
    comptime format: []const u8,
    args: anytype,
) void {
    if (log_level == null or @intFromEnum(level) > @intFromEnum(log_level.?)) {
        return;
    }

    var buffer: [1024]u8 align(16) = undefined;
    var log_file_writer: std.Io.File.Writer = undefined;
    var writer: *Io.Writer = if (log_file) |f| writer: {
        log_file_writer = f.writerStreaming(std.Options.debug_io, &buffer);
        break :writer &log_file_writer.interface;
    } else &std.debug.lockStderr(&buffer).file_writer.interface;

    // Zig `std` does not yet providing printing of timestamps.
    defer log_counter +%= 1;

    const level_prefix = comptime level.asText();
    const scope_prefix = if (scope == .default) ": " else "(" ++ @tagName(scope) ++ "): ";
    writer.print("[{d:0>6}] " ++ level_prefix ++ scope_prefix, .{log_counter}) catch {};
    writer.print(format ++ "\n", args) catch {};

    if (log_file) |_| {
        writer.flush() catch {};
    } else {
        std.debug.unlockStderr();
    }
}

pub const std_options = std.Options{
    .logFn = logger,
    .log_level = .debug,
};

pub fn main(init: std.process.Init.Minimal) void {
    const exit_code: u32 = @bitCast(
        realMain(init) catch |e| switch (e) {
            error.BadCliFlag => if (builtin.os.tag == .windows) @as(i32, -1) else 2,
            error.GenericError => 1,
        },
    );

    if (builtin.os.tag == .windows) {
        // TODO: check exit_code != 3 (abort) https://github.com/WebAssembly/wasi-cli/issues/11
        std.os.windows.ntdll.RtlExitUserProcess(exit_code);
    } else {
        std.process.exit(
            std.math.cast(u8, exit_code) orelse @panic("TODO: how to truncate exit code"),
        );
    }
}

const max_fuel = wasmstint.Interpreter.Fuel{ .remaining = std.math.maxInt(u32) };

fn printExitCode(arguments: *const Arguments.Parsed, code: i32) void {
    if (arguments.@"print-exit-code") {
        std.debug.print("\nExited with code: {}\n", .{code});
    }
}

fn realMain(init: std.process.Init.Minimal) Error!i32 {
    var memory_limit: usize = std.math.maxInt(usize);
    var limited_page_allocator = allocators.LimitedAllocator.init(
        &memory_limit,
        std.heap.page_allocator,
    );

    var arena = ArenaAllocator.init(limited_page_allocator.allocator());
    defer arena.deinit();
    var scratch = ArenaAllocator.init(limited_page_allocator.allocator());
    defer scratch.deinit();

    const all_arguments = parseArguments(&init, &scratch, &arena);
    const arguments = all_arguments.flags;

    memory_limit = @min(memory_limit, arguments.@"rt-memory-limit");

    if (std.mem.eql(u8, arguments.invoke, memory_export)) {
        return fail.print(error.BadCliFlag, "cannot use " ++ memory_export ++ " as an entrypoint");
    }

    var io_threaded = Io.Threaded.init_single_threaded;
    const io = io_threaded.io();
    const cwd = Io.Dir.cwd();

    log_level = arguments.@"log-level";
    if (arguments.@"log-file") |path| {
        log_file = Io.Dir.createFile(
            cwd,
            io,
            path,
            // https://github.com/ziglang/zig/issues/14375
            Io.File.CreateFlags{ .truncate = false },
        ) catch return fail.format(
            error.GenericError,
            "could not create log file {f}",
            .{std.unicode.fmtUtf8(path)},
        );
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

    _ = scratch.reset(.retain_capacity);
    var wasm_binary = file_content.readFilePortable(
        io,
        cwd,
        arguments.module,
        if (builtin.os.tag == .windows) scratch.allocator() else arena.allocator(),
    ) catch |e| switch (e) {
        error.OutOfMemory => oom("module bytes"),
        else => |io_err| return fail.format(
            error.GenericError,
            "failed to open program file {s}, {t}",
            .{ fmt_wasm_path, io_err },
        ),
    };
    defer if (builtin.mode == .Debug) wasm_binary.deinit();

    const rt_rng_num: u128 = arguments.@"rt-rng-seed" orelse seed: {
        var seed: u128 = undefined;
        io.randomSecure(std.mem.asBytes(&seed)) catch |e| switch (e) {
            error.EntropyUnavailable => return fail
                .print(error.GenericError, "could not access OS CSPRNG"),
            error.Canceled => unreachable,
        };
        break :seed seed;
    };

    const rt_rng_seeds: [2]u64 = .{ @truncate(rt_rng_num), @truncate(rt_rng_num >> 64) };

    _ = scratch.reset(.retain_capacity);
    var parse_diagnostics = wasmstint.Module.ParseDiagnostics.init(&arena);
    var parse_names_diagnostics = wasmstint.Module.ParseDiagnostics.init(&arena);
    const parsed_module = module: {
        var wasm: []const u8 = wasm_binary.contents();
        break :module wasmstint.Module.parse(
            arena.allocator(),
            &wasm,
            &scratch,
            wasmstint.Module.ParseOptions{
                .diagnostics = &parse_diagnostics,
                .random_seed = rt_rng_seeds[0],
                .parse_names = if (builtin.mode == .Debug)
                    .{ .parse = &parse_names_diagnostics }
                else
                    .parse_without_diagnostics,
            },
        ) catch |e| switch (e) {
            error.OutOfMemory => oom("module"),
            error.InvalidWasm => return fail.format(
                error.GenericError,
                "module {s} is invalid, {s}",
                .{ fmt_wasm_path, parse_diagnostics.message.? },
            ),
            error.MalformedWasm, error.WasmImplementationLimit => return fail.format(
                error.GenericError,
                "failed to parse module {s}: {s}",
                .{ fmt_wasm_path, parse_diagnostics.message.? },
            ),
        };
    };
    _ = scratch.reset(.retain_capacity);

    if (builtin.mode == .Debug and parse_names_diagnostics.message != null) {
        std.debug.print("\nmalformed name section: {s}\n", .{parse_names_diagnostics.message.?});
    }

    // TODO: switch to enable lazy validation, also helper thread to validate in background
    const validation_finished = parsed_module.finishCodeValidation(
        arena.allocator(),
        &scratch,
        &parse_diagnostics,
    ) catch |e| switch (e) {
        error.OutOfMemory => oom("module code entries"),
        error.InvalidWasm => return fail.format(
            error.GenericError,
            "invalid function in module {s}, {s}",
            .{ fmt_wasm_path, parse_diagnostics.message.? },
        ),
        error.MalformedWasm, error.WasmImplementationLimit => return fail.format(
            error.GenericError,
            "malformed function in module {s}, {s}",
            .{ fmt_wasm_path, parse_diagnostics.message.? },
        ),
    };
    _ = scratch.reset(.retain_capacity);

    std.debug.assert(validation_finished);

    var preopens = scratch.allocator().alloc(
        WasiPreview1.PreopenDir,
        all_arguments.preopen_dirs.len,
    ) catch oom("preopen list");

    {
        var preopen_path_arena = ArenaAllocator.init(scratch.allocator());
        for (preopens, all_arguments.preopen_dirs) |*dst, *src| {
            dst.* = WasiPreview1.PreopenDir.openAtZ(
                sys.Dir{ .handle = cwd.handle },
                // TODO(Zig): cli argument iteration should be able to return [:0]u16 on windows
                sys.path.allocFromBytesZ(
                    src.host,
                    .alloc_windows,
                    preopen_path_arena.allocator(),
                ) catch |e| switch (e) {
                    error.OutOfMemory => oom("preopen host path"),
                    error.InvalidWtf8 => unreachable,
                },
                src.permissions,
                src.guest,
            ) catch |e| return fail.format(
                error.GenericError,
                "{t}: failed to open preopen directory {f}",
                .{ e, std.unicode.fmtUtf8(src.host) },
            );
            _ = preopen_path_arena.reset(.retain_capacity);
        }
    }
    _ = scratch.reset(.retain_capacity);

    var wasi = WasiPreview1.init(
        limited_page_allocator.allocator(), // std.heap.smp_allocator,
        io,
        .{
            .args = forwarded_arguments,
            .environ = all_arguments.environ,
            .fd_rng_seed = rt_rng_seeds[1],
        },
        &preopens,
    ) catch |e| switch (e) {
        error.OutOfMemory => oom("WASIp1 state"),
    };
    defer wasi.deinit();

    std.debug.assert(preopens.len == 0); // `wasi` now responsible for closing preopen handles
    _ = scratch.reset(.retain_capacity);

    const defined_mem_types = parsed_module.memDefinedTypes();
    const defined_memories = arena.allocator().alloc(
        wasmstint.runtime.MemInst.Mapped,
        defined_mem_types.len,
    ) catch oom("defined memories list");
    const defined_memories_buf = scratch.allocator().alloc(
        *wasmstint.runtime.MemInst,
        defined_memories.len,
    ) catch oom("defined memories buf");
    for (defined_memories, defined_memories_buf, defined_mem_types) |*mem, *inst, *mem_type| {
        mem.* = wasmstint.runtime.MemInst.Mapped.allocateFromType(
            mem_type,
            mem_type.limits.min * wasmstint.runtime.MemInst.page_size,
            arguments.@"max-memory-size",
        ) catch oom("memory inst");
        inst.* = &mem.memory;
    }

    const defined_table_types = parsed_module.tableDefinedTypes();
    const defined_tables = arena.allocator().alloc(
        wasmstint.runtime.TableInst.Allocated,
        defined_table_types.len,
    ) catch oom("defined tables list");
    const defined_tables_buf = scratch.allocator().alloc(
        *wasmstint.runtime.TableInst,
        defined_tables.len,
    ) catch oom("defined tables buf");
    for (defined_tables, defined_tables_buf, defined_table_types) |*table, *inst, *table_type| {
        table.* = wasmstint.runtime.TableInst.Allocated.allocateFromType(
            arena.allocator(),
            table_type,
            null,
            @intCast(table_type.limits.min),
            @intCast(arguments.@"max-memory-size" / 8),
        ) catch oom("table inst");
        inst.* = &table.table;
    }

    var import_error: wasmstint.runtime.ImportProvider.FailedRequest = undefined;
    var module_alloc = wasmstint.runtime.ModuleAlloc.allocateWithDefinitions(
        parsed_module,
        arena.allocator(),
        wasi.importProvider(),
        &import_error,
        .{
            .tables = defined_tables_buf,
            .memories = defined_memories_buf,
        },
    ) catch |e| switch (e) {
        error.OutOfMemory => oom("WASM module allocation"),
        error.ImportFailure => return fail.format(error.GenericError, "{f}", .{import_error}),
    };
    _ = scratch.reset(.retain_capacity);

    var interp_allocator = allocators.PageAllocation.init(
        .{},
        arguments.@"max-stack-size" *| 16,
    ) catch oom("interpreter stack reserve");
    defer if (builtin.mode == .Debug) interp_allocator.deinit();

    var interp: wasmstint.Interpreter = undefined;
    defer interp.deinit(interp_allocator.allocator());
    {
        const start = interp.init(
            interp_allocator.allocator(),
            .{ .stack_reserve = arguments.@"max-stack-size" },
        ) catch oom("interpreter stack");

        var instantiate_fuel = max_fuel;
        const instantiate_state = start.awaiting_host.instantiateModule(
            arena.allocator(),
            &module_alloc,
            &instantiate_fuel,
        ) catch oom("WASM module instantiation");

        const init_result = try mainLoop(
            instantiate_state,
            .{ .limited = &instantiate_fuel },
            &wasi,
            null,
        );

        if (init_result) |exit| {
            printExitCode(&arguments, exit);
            return exit;
        }
    }

    const module = module_alloc.assumeInstantiated();
    const fmt_entrypoint = std.unicode.fmtUtf8(arguments.invoke);
    const exports: struct {
        memory: *wasmstint.runtime.MemInst,
        entrypoint: wasmstint.runtime.FuncRef,
    } = exports: {
        const all_exports = module.exports();

        var entrypoint: ?wasmstint.runtime.FuncRef = null;
        var memory: ?*wasmstint.runtime.MemInst = null;

        // Check that memory name != entrypoint name occurs earlier
        for (0..all_exports.len) |i| {
            const exp = all_exports.at(i);
            const exp_name = exp.name.bytes();
            if (std.mem.eql(u8, exp_name, arguments.invoke)) {
                std.debug.assert(entrypoint == null);
                entrypoint = switch (exp.val) {
                    .func => |func| func,
                    else => return fail.format(
                        error.GenericError,
                        "expected entrypoint {f} to be a function, but got a {s}",
                        .{ fmt_entrypoint, @tagName(exp.val) },
                    ),
                };
            } else if (std.mem.eql(u8, memory_export, exp_name)) {
                std.debug.assert(memory == null);
                memory = switch (exp.val) {
                    .mem => |mem| mem,
                    else => return fail.format(
                        error.GenericError,
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
            .entrypoint = entrypoint orelse return fail.formatWithFollowup(
                error.GenericError,
                "could not find exported entrypoint {f}",
                .{fmt_entrypoint},
                all_exports,
                struct {
                    fn printFollowupMessage(
                        available_exports: wasmstint.runtime.ModuleInst.Export.List,
                        stderr: std.Io.Terminal,
                    ) Io.Writer.Error!void {
                        stderr.setColor(.bright_cyan) catch {};
                        try stderr.writer.writeAll("note: ");
                        stderr.setColor(.reset) catch {};
                        if (available_exports.len == 0) {
                            try stderr.writer.writeAll("module does not provide any exports\n");
                        } else {
                            try stderr.writer.writeAll("module's available entry points are:\n");
                            for (0..available_exports.len) |i| {
                                const exp = available_exports.at(i);
                                if (exp.val != .func) {
                                    continue;
                                }

                                const func = exp.val.func.signature();
                                if (func.param_count != 0 or func.result_count != 0) {
                                    continue;
                                }

                                try stderr.writer.print(
                                    "{f}\n",
                                    .{std.unicode.fmtUtf8(exp.name.bytes())},
                                );
                            }
                        }
                    }
                }.printFollowupMessage,
            ),
            .memory = memory orelse
                return fail.format(error.GenericError, "could not find exported memory", .{}),
        };
    };

    const main_result = try mainLoop(
        start_call: {
            var starting_fuel = max_fuel;
            break :start_call interp.reset().awaiting_host.beginCall(
                std.heap.page_allocator,
                exports.entrypoint.funcInst(),
                &.{},
                &starting_fuel,
            ) catch |e| switch (e) {
                error.OutOfMemory => oom("entrypoint function call"),
                error.SignatureMismatch => return fail.format(
                    error.GenericError,
                    "expected entrypoint function {f} to have no arguments",
                    .{fmt_entrypoint},
                ),
                error.ValidationNeeded => unreachable,
            };
        },
        .unlimited,
        &wasi,
        exports.memory,
    );

    if (main_result) |exit| {
        printExitCode(&arguments, exit);
        return exit;
    }

    // TODO: Should proc_exit be assumed to always be called? (indicate error do to "fallthrough"?)
    return 0;
}

const FuelChecking = union(enum) {
    unlimited,
    limited: *wasmstint.Interpreter.Fuel,
};

fn mainLoop(
    initial_state: wasmstint.Interpreter.State,
    fuel_checking: FuelChecking,
    wasi: *WasiPreview1,
    memory: ?*wasmstint.runtime.MemInst,
) Error!?i32 {
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
                    switch (wasi.dispatch(host, mem_inst, fuel)) {
                        .@"continue" => |next| break :next next,
                        .proc_exit => |code| return code,
                    }
                } else {
                    return fail.format(
                        error.GenericError,
                        "WASI cannot access exports until module initializer has finished running",
                        .{},
                    );
                }
            } else {
                // WASM spec says start (not to be confused with `_start`) has no results
                // All WASI entrypoints also have no results.
                std.debug.assert(host.resultTypes().len == 0);
                return null;
            },
            .awaiting_validation => unreachable,
            .call_stack_exhaustion => oom("call stack exhausted"), // TODO: print stack trace
            .interrupted => |*interrupt| {
                switch (interrupt.cause().*) {
                    .out_of_fuel => switch (fuel_checking) {
                        .limited => {
                            // TODO: print stack trace
                            return fail.print(error.GenericError, "out of fuel");
                        },
                        .unlimited => {},
                    },
                    inline .memory_grow, .table_grow => |grow_request| grow_request.grow() catch {},
                }

                break :next interrupt.resumeExecution(fuel);
            },
            .trapped => |*trapped| {
                const stack_trace = trapped.inner.walkCallStack();
                return fail.format(
                    error.GenericError,
                    "trap {t}\nstack trace:\n{f}",
                    .{ trapped.trap().code, stack_trace },
                );
            },
        };
    }
}

const std = @import("std");
const Io = std.Io;
const builtin = @import("builtin");
const ArenaAllocator = std.heap.ArenaAllocator;
const sys = @import("sys");
const file_content = @import("file_content");
const allocators = @import("allocators");
const wasmstint = @import("wasmstint");
const cli_args = @import("cli_args");
const WasiPreview1 = @import("WasiPreview1");
const coz = @import("coz");

test {
    _ = main;
}
