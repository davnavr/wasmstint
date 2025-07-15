//! Executes WASM JSON spec tests.

inline fn oom(_: std.mem.Allocator.Error) noreturn {
    @panic("OOM");
}

const Arguments = cli_args.CliArgs(.{
    .description = "WebAssembly specification JSON test interpreter.",
    .flags = &[_]cli_args.Flag{
        .string(
            .{
                .long = "run",
                .short = 'r',
                .description = "Path to .json specification test file",
            },
            "PATH",
        ),

        cli_args.Flag.intUnsigned(
            .{ .long = "rng-seed", .description = "Specifies the RNG seed to use" },
            "SEED",
            u256,
        ).optional(),

        cli_args.Flag.intUnsigned(
            .{
                .long = "fuel",
                .description = "Limits the number of WASM instructions executed",
            },
            "AMOUNT",
            u64,
        ).withDefault(3_000_000),

        cli_args.Flag.intUnsigned(
            .{
                .long = "max-stack-size",
                .description = "Limits the size of the WASM value and call stacks",
            },
            "AMOUNT",
            u64,
        ).withDefault(500),

        .boolean(.{ .long = "wait-for-debugger" }),
    },
});

fn parseProgramArguments(scratch: *ArenaAllocator, arena: *ArenaAllocator) Arguments.Parsed {
    var buf: [512]u8 align(16) = undefined;
    var buf_allocator = std.heap.FixedBufferAllocator.init(&buf);
    const parser = Arguments.init(buf_allocator.allocator()) catch |e| oom(e);
    return parser.programArguments(scratch, arena) catch |e| oom(e);
}

pub fn main() u8 {
    var scratch = ArenaAllocator.init(std.heap.page_allocator);
    defer scratch.deinit();

    var arena = ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    const arguments = parseProgramArguments(&scratch, &arena);

    if (arguments.@"wait-for-debugger") {
        wasmstint.waitForDebugger();
    }

    const cwd = std.fs.cwd();
    const json_file = cwd.openFileZ(arguments.run, .{ .mode = .read_only }) catch |e| {
        std.debug.print(
            "Failed to open file {f}: {t}\n",
            .{ std.unicode.fmtUtf8(arguments.run), e },
        );
        return 1;
    };
    defer json_file.close();

    const initial_rng = rng: {
        var init = std.Random.Xoshiro256{ .s = undefined };
        if (arguments.@"rng-seed") |seed|
            init.s = @bitCast(seed)
        else
            std.posix.getrandom(std.mem.asBytes(&init.s)) catch @panic("cannot obtain RNG");

        break :rng init;
    };

    const color_config = std.Io.tty.detectConfig(std.fs.File.stderr());
    _ = color_config;

    _ = initial_rng;

    return 0;
}

const SpectestImports = struct {
    lookup: std.StringHashMapUnmanaged(wasmstint.runtime.ExternVal),
    registered: RegisteredImports = .empty,
    registered_context: RegisteredImportsContext,

    const RegisteredImports = std.HashMapUnmanaged(
        ImportName,
        wasmstint.runtime.ExternVal,
        RegisteredImportsContext,
        std.hash_map.default_max_load_percentage,
    );

    const RegisteredImportsContext = struct {
        seed: u32,

        pub fn hash(ctx: RegisteredImportsContext, key: ImportName) u64 {
            var hasher = std.hash.Wyhash.init(ctx.seed);
            hasher.update(key.module());
            hasher.update("\xFF");
            hasher.update(key.name());
            return hasher.final();
        }

        pub fn eql(_: RegisteredImportsContext, a: ImportName, b: ImportName) bool {
            return std.mem.eql(u8, a.module(), b.module()) and
                std.mem.eql(u8, a.name(), b.name());
        }
    };

    const ImportName = struct {
        module_ptr: [*]const u8,
        module_len: u32,
        name_len: u32,
        name_ptr: [*]const u8,

        fn init(module_bytes: []const u8, name_bytes: []const u8) ImportName {
            return .{
                .module_ptr = module_bytes.ptr,
                .module_len = @intCast(module_bytes.len),
                .name_ptr = name_bytes.ptr,
                .name_len = @intCast(name_bytes.len),
            };
        }

        fn module(self: *const ImportName) []const u8 {
            return self.module_ptr[0..self.module_len];
        }

        fn name(self: *const ImportName) []const u8 {
            return self.name_ptr[0..self.name_len];
        }
    };

    const PrintFunction = enum(u8) {
        print = 0,
        print_i32,
        print_i64,
        print_f32,
        print_f64,
        print_i32_f32,
        print_f64_f64,

        const param_types = [_]wasmstint.Module.ValType{
            .i32,
            .f32,
            .i64,
            .f64,
            .f64,
        };

        fn signature(func: PrintFunction) wasmstint.Module.FuncType {
            return switch (func) {
                .print => .empty,
                .print_i32 => .{ .types = param_types[0..1].ptr, .param_count = 1, .result_count = 0 },
                .print_i64 => .{ .types = param_types[2..3].ptr, .param_count = 1, .result_count = 0 },
                .print_f32 => .{ .types = param_types[1..2].ptr, .param_count = 1, .result_count = 0 },
                .print_f64 => .{ .types = param_types[3..4].ptr, .param_count = 1, .result_count = 0 },
                .print_i32_f32 => .{ .types = param_types[0..2].ptr, .param_count = 2, .result_count = 0 },
                .print_f64_f64 => .{ .types = param_types[3..5].ptr, .param_count = 2, .result_count = 0 },
            };
        }

        const all = std.enums.values(PrintFunction);

        const functions: [all.len]wasmstint.runtime.FuncAddr.Host = functions: {
            var result: [all.len]wasmstint.runtime.FuncAddr.Host = undefined;
            for (all) |func| {
                result[@intFromEnum(func)] = .{ .signature = func.signature() };
            }
            break :functions result;
        };

        fn hostFunc(func: PrintFunction) *const wasmstint.runtime.FuncAddr.Host {
            return &functions[@intFromEnum(func)];
        }

        fn addr(func: PrintFunction) wasmstint.runtime.FuncAddr {
            return wasmstint.runtime.FuncAddr.init(.{
                .host = .{
                    .func = @constCast(func.hostFunc()),
                    .data = null,
                },
            });
        }
    };

    const globals = struct {
        const @"i32" = wasmstint.runtime.GlobalAddr{
            .global_type = .{ .mut = .@"const", .val_type = .i32 },
            .value = @constCast(@ptrCast(&@as(i32, 666))),
        };

        const @"i64" = wasmstint.runtime.GlobalAddr{
            .global_type = .{ .mut = .@"const", .val_type = .i64 },
            .value = @constCast(@ptrCast(&@as(i64, 666))),
        };

        const @"f32" = wasmstint.runtime.GlobalAddr{
            .global_type = .{ .mut = .@"const", .val_type = .f32 },
            .value = @constCast(@ptrCast(&@as(f32, 666.6))),
        };

        const @"f64" = wasmstint.runtime.GlobalAddr{
            .global_type = .{ .mut = .@"const", .val_type = .f64 },
            .value = @constCast(@ptrCast(&@as(f64, 666.6))),
        };

        const names = [4][]const u8{ "i32", "i64", "f32", "f64" };
    };

    fn init(
        arena: *ArenaAllocator,
        rng: std.Random,
        memory: *wasmstint.runtime.MemInst,
        table: wasmstint.runtime.TableAddr,
    ) Allocator.Error!SpectestImports {
        var imports = SpectestImports{
            .lookup = std.StringHashMapUnmanaged(wasmstint.runtime.ExternVal).empty,
            .registered_context = .{ .seed = rng.int(u32) },
        };

        try imports.lookup.ensureTotalCapacity(
            arena.allocator(),
            PrintFunction.all.len + globals.names.len + 2,
        );

        errdefer comptime unreachable;

        for (PrintFunction.all) |func| {
            imports.lookup.putAssumeCapacityNoClobber(
                @tagName(func),
                .{ .func = func.addr() },
            );
        }

        inline for (globals.names) |name| {
            imports.lookup.putAssumeCapacityNoClobber(
                "global_" ++ name,
                .{ .global = @field(globals, name) },
            );
        }

        imports.lookup.putAssumeCapacityNoClobber("memory", .{ .mem = memory });
        imports.lookup.putAssumeCapacityNoClobber("table", .{ .table = table });

        return imports;
    }

    fn provider(host: *SpectestImports) wasmstint.runtime.ImportProvider {
        return .{
            .ctx = host,
            .resolve = resolve,
        };
    }

    fn resolve(
        ctx: *anyopaque,
        module: std.unicode.Utf8View,
        name: std.unicode.Utf8View,
        desc: wasmstint.runtime.ImportProvider.Desc,
    ) ?wasmstint.runtime.ExternVal {
        const host: *const SpectestImports = @ptrCast(@alignCast(ctx));
        _ = desc;

        return if (std.mem.eql(u8, "spectest", module.bytes))
            host.lookup.get(name.bytes)
        else
            host.registered.getContext(
                ImportName.init(module.bytes, name.bytes),
                host.registered_context,
            );
    }
};

// TODO: What if arguments could be allocated directly in the Interpreter's value_stack?

const State = struct {
    const ModuleInst = wasmstint.runtime.ModuleInst;
    const Interpreter = wasmstint.Interpreter;

    script_path: []const u8,

    /// Allocated in the `run_arena`.
    module_lookups: std.StringHashMapUnmanaged(ModuleInst) = .empty,
    current_module: ?ModuleInst = null,

    /// Live for the execution of a single command.
    cmd_arena: ArenaAllocator,

    store: *wasmstint.runtime.ModuleAllocator.WithinArena,

    const Error = error{ScriptError} || Allocator.Error;

    fn runToCompletion(
        state: *State,
        interpreter: *Interpreter,
        fuel: *Interpreter.Fuel,
        // parent: Wast.sexpr.TokenId,
    ) Allocator.Error!void {
        // TODO: Use fuel
        for (0..1_024) |_| {
            switch (interpreter.state) {
                .awaiting_host => |*host| if (interpreter.call_stack.items.len == 0) {
                    return;
                } else {
                    const callee = host.currentHostFunction().?;
                    const print_func_idx = @divExact(
                        @intFromPtr(callee.func) - @intFromPtr(&SpectestImports.PrintFunction.functions),
                        @sizeOf(wasmstint.runtime.FuncAddr.Host),
                    );

                    const print_func = SpectestImports.PrintFunction.all[print_func_idx];

                    std.Progress.lockStdErr();
                    defer std.Progress.unlockStdErr();

                    var stderr_buf = std.io.BufferedWriter(128, std.fs.File.Writer){
                        .unbuffered_writer = std.Io.getStdErr().writer(),
                    };
                    defer stderr_buf.flush() catch {};

                    // const stderr = stderr_buf.writer();
                    // stderr.print(
                    //     "{s}:{} - {s}(",
                    //     .{
                    //         state.script_path,
                    //         state.errors.locator.locate(
                    //             state.errors.tree.source,
                    //             parent.offset(state.errors.tree).start,
                    //         ),
                    //         @tagName(print_func),
                    //     },
                    // ) catch {};

                    _ = print_func;
                    // switch (print_func) {
                    //     .print => {},
                    //     .print_i32 => stderr.print(
                    //         "{}",
                    //         host.valuesTyped(struct { i32 }) catch unreachable,
                    //     ) catch {},
                    //     .print_i64 => stderr.print(
                    //         "{}",
                    //         host.valuesTyped(struct { i64 }) catch unreachable,
                    //     ) catch {},
                    //     .print_f32 => stderr.print(
                    //         "{}",
                    //         host.valuesTyped(struct { f32 }) catch unreachable,
                    //     ) catch {},
                    //     .print_f64 => stderr.print(
                    //         "{}",
                    //         host.valuesTyped(struct { f64 }) catch unreachable,
                    //     ) catch {},
                    //     .print_i32_f32 => stderr.print(
                    //         "{}, {}",
                    //         host.valuesTyped(struct { i32, f32 }) catch unreachable,
                    //     ) catch {},
                    //     .print_f64_f64 => stderr.print(
                    //         "{}, {}",
                    //         host.valuesTyped(struct { f64, f64 }) catch unreachable,
                    //     ) catch {},
                    // }

                    _ = host.returnFromHostTyped({}, fuel) catch unreachable;

                    // stderr.writeAll(")\n") catch {};
                },
                .awaiting_validation => unreachable,
                .call_stack_exhaustion => |*oof| {
                    _ = oof.resumeExecution(state.cmd_arena.allocator(), fuel) catch
                        return;
                },
                .interrupted => |*interrupt| {
                    switch (interrupt.cause) {
                        .out_of_fuel => return,
                        .memory_grow => |grow| {
                            const new_cap = @min(
                                @max(
                                    grow.delta + grow.memory.size,
                                    grow.memory.capacity *| 2,
                                ),
                                grow.memory.limit,
                            );

                            const remapped = state.store.arena.allocator().remap(
                                grow.memory.base[0..grow.memory.capacity],
                                new_cap,
                            );

                            if (remapped) |new_buf| {
                                _ = grow.resize(new_buf);
                            } else resize_failed: {
                                _ = grow.resize(
                                    state.store.arena.allocator().alignedAlloc(
                                        u8,
                                        wasmstint.runtime.MemInst.buffer_align,
                                        new_cap,
                                    ) catch break :resize_failed,
                                );
                            }
                        },
                        .table_grow => |grow| resize_failed: {
                            const table = grow.table.table;
                            const new_cap = @min(
                                @max(grow.delta + table.len, table.capacity *| 2),
                                table.limit,
                            ) * table.stride.toBytes();

                            const remapped = state.store.arena.allocator().remap(
                                table.base.ptr[0 .. table.capacity * table.stride.toBytes()],
                                new_cap,
                            );

                            if (remapped) |new_buf| {
                                _ = grow.resize(new_buf);
                            } else {
                                _ = grow.resize(
                                    state.store.arena.allocator().alignedAlloc(
                                        u8,
                                        wasmstint.runtime.TableInst.buffer_align,
                                        new_cap,
                                    ) catch break :resize_failed,
                                );
                            }
                        },
                    }

                    _ = interrupt.resumeExecution(fuel);
                },
                .trapped => return,
            }
        }

        @panic("Possible infinite loop in interpreter handler");
    }

    const trap_code_lookup = std.StaticStringMap(Interpreter.Trap.Code).initComptime(.{
        .{ "unreachable", .unreachable_code_reached },
        .{ "integer divide by zero", .integer_division_by_zero },
        .{ "integer overflow", .integer_overflow },
        .{ "invalid conversion to integer", .invalid_conversion_to_integer },
        .{ "out of bounds memory access", .memory_access_out_of_bounds },
        .{ "out of bounds table access", .table_access_out_of_bounds },
        .{ "uninitialized element", .indirect_call_to_null },
        .{ "indirect call type mismatch element", .indirect_call_signature_mismatch },
        .{ "indirect call type mismatch", .indirect_call_signature_mismatch },
        .{ "undefined element", .table_access_out_of_bounds },
    });
};

const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const ArenaAllocator = std.heap.ArenaAllocator;
const wasmstint = @import("wasmstint");
const cli_args = @import("cli_args");
