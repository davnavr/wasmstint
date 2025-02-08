const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const ArenaAllocator = std.heap.ArenaAllocator;
const wasmstint = @import("wasmstint");
const Wast = wasmstint.Wast;

const Arguments = struct {
    run: []const [:0]const u8,
    rng_seed: u256 = 42,

    const Flag = enum {
        run,
        wait_for_debugger,

        const lookup = std.StaticStringMap(Flag).initComptime(.{
            .{ "--run", .run },
            .{ "-r", .run },
            .{ "--wait-for-debugger", .wait_for_debugger },
        });
    };

    fn parse(arena: *ArenaAllocator, scratch: *ArenaAllocator) !Arguments {
        var arguments = Arguments{
            .run = &[0][:0]const u8{},
        };

        var run_paths = std.SegmentedList([:0]const u8, 4){};

        var iter = try std.process.argsWithAllocator(scratch.allocator());
        _ = iter.next(); // exe_name
        while (iter.next()) |arg| {
            const flag = Flag.lookup.get(arg) orelse {
                std.debug.print("Unknown flag: {s}\n", .{arg});
                return error.InvalidCommandLineArgument;
            };

            switch (flag) {
                .run => {
                    const script_path = try run_paths.addOne(scratch.allocator());
                    script_path.* = try arena.allocator().dupeZ(
                        u8,
                        iter.next() orelse return error.InvalidCommandLineArgument,
                    );
                },
                .wait_for_debugger => if (builtin.target.os.tag == .windows) {
                    std.debug.print("Attach debugger to process {}\n", .{std.os.windows.GetCurrentProcessId()});

                    const debugapi = struct {
                        pub extern "kernel32" fn IsDebuggerPresent() callconv(.winapi) std.os.windows.BOOL;
                    };

                    while (debugapi.IsDebuggerPresent() == 0) {
                        std.Thread.sleep(100);
                    }
                } else {
                    if (builtin.target.os.tag == .linux) {
                        std.debug.print("Attach debugger to process {}\n", .{std.os.linux.getpid()});
                    }

                    var dbg: usize = 0;
                    const dbg_ptr: *volatile usize = &dbg;
                    while (dbg_ptr.* == 0) {
                        std.Thread.sleep(100);
                    }
                },
            }
        }

        const run_paths_final = try arena.allocator().alloc([:0]const u8, run_paths.count());
        run_paths.writeToSlice(run_paths_final, 0);
        arguments.run = run_paths_final;

        return arguments;
    }
};

const file_max_bytes = @as(usize, 1) << 21; // 2 MiB

pub fn main() !u8 {
    var arguments_arena = ArenaAllocator.init(std.heap.page_allocator);
    defer arguments_arena.deinit();

    var scratch = ArenaAllocator.init(std.heap.page_allocator);
    defer scratch.deinit();

    const arguments = try Arguments.parse(&arguments_arena, &scratch);

    var file_buffer = std.ArrayList(u8).init(std.heap.page_allocator);
    defer file_buffer.deinit();

    var encoding_buffer = std.ArrayList(u8).init(std.heap.page_allocator);
    defer encoding_buffer.deinit();

    var parse_arena = ArenaAllocator.init(std.heap.page_allocator);
    defer parse_arena.deinit();

    const color_config = std.io.tty.detectConfig(std.io.getStdErr());
    const cwd = std.fs.cwd();

    const initial_rng = rng: {
        var init = std.Random.Xoshiro256{ .s = undefined };
        init.s = @bitCast(arguments.rng_seed);
        break :rng init;
    };

    var fail = false;
    for (arguments.run) |script_path| {
        const script_buf: []const u8 = buf: {
            const script_file = cwd.openFileZ(script_path, .{}) catch |e| {
                std.debug.print("Could not open script file {s}: {!}", .{ script_path, e });
                return e;
            };

            defer script_file.close();

            file_buffer.clearRetainingCapacity();
            size_estimate: {
                const metadata = script_file.metadata() catch break :size_estimate;
                try file_buffer.ensureTotalCapacity(std.math.cast(usize, metadata.size()) orelse return error.OutOfMemory);
            }

            script_file.reader().readAllArrayList(&file_buffer, file_max_bytes) catch |e| {
                if (e != error.OutOfMemory) std.debug.print("Could not read script file {s}", .{script_path});
                return e;
            };

            break :buf file_buffer.items;
        };

        _ = parse_arena.reset(.retain_capacity);
        {
            // Try to allocate some space upfront.
            _ = parse_arena.allocator().alloc(u8, script_buf.len) catch {};
            _ = parse_arena.reset(.retain_capacity);
        }

        var errors = Wast.Errors.init(parse_arena.allocator());

        _ = scratch.reset(.retain_capacity);
        const script_tree = try Wast.sexpr.Tree.parseFromSlice(
            script_buf,
            parse_arena.allocator(),
            &scratch,
            &errors,
        );

        // TODO: Figure out if using an arena here might actually faster than using the GPA.
        var parse_array = Wast.Arena.init(parse_arena.allocator());
        var parse_caches = Wast.Caches.init(parse_arena.allocator());

        _ = scratch.reset(.retain_capacity);
        const script = Wast.parse(
            &script_tree,
            &parse_array,
            &parse_caches,
            &errors,
            &scratch,
        ) catch |e| switch (e) {
            error.OutOfMemory => return e,
        };

        var pass_count: u32 = 0;
        if (errors.list.len == 0) {
            var rng = initial_rng;
            pass_count = try runScript(
                &script,
                rng.random(),
                &encoding_buffer,
                &parse_arena,
                &errors,
            );
        }

        {
            _ = scratch.reset(.retain_capacity);
            const buf_writer = try scratch.allocator().create(
                std.io.BufferedWriter(
                    4096,
                    std.fs.File.Writer,
                ),
            );

            const raw_stderr = std.io.getStdErr();
            buf_writer.* = .{ .unbuffered_writer = raw_stderr.writer() };
            var w = buf_writer.writer();

            var errors_iter = errors.list.constIterator(0);
            while (errors_iter.next()) |err| {
                try w.print(
                    "{s}:{}: ",
                    .{
                        script_path, err.loc,
                    },
                );

                switch (color_config) {
                    .escape_codes => try w.writeAll("\x1B[31m" ++ "error" ++ "\x1B[39m"),
                    else => try w.writeAll("error"),
                }

                try w.print(": {s}\n", .{err.msg});
                try err.src.print(w);

                try w.writeByte('\n');
            }

            if (errors.list.len > 0) {
                if (color_config == .escape_codes) {
                    try w.writeAll("\x1B[31m");
                }

                try w.print("{} errors", .{errors.list.count()});

                if (color_config == .escape_codes) {
                    try w.writeAll("\x1B[39m");
                }

                try w.writeAll(", ");
            }

            if (color_config == .escape_codes) {
                try w.writeAll("\x1B[32m");
            }

            try w.print("{} passed", .{pass_count});

            if (color_config == .escape_codes) {
                try w.writeAll("\x1B[39m");
            }

            try w.print(" - {s}\n", .{script_path});

            try buf_writer.flush();
        }

        if (errors.list.len > 0) fail = true;
    }

    return if (fail) 1 else 0;
}

const SpectestImports = struct {
    lookup: std.StringHashMapUnmanaged(wasmstint.runtime.ExternVal),

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

        var functions: [all.len]wasmstint.runtime.FuncAddr.Host = functions: {
            var result: [all.len]wasmstint.runtime.FuncAddr.Host = undefined;
            for (all) |func| {
                result[@intFromEnum(func)] = .{ .signature = func.signature() };
            }
            break :functions result;
        };

        fn addr(func: PrintFunction) wasmstint.runtime.FuncAddr {
            return wasmstint.runtime.FuncAddr.init(.{
                .host = .{
                    .func = &functions[@intFromEnum(func)],
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

    fn init(arena: *ArenaAllocator) Allocator.Error!SpectestImports {
        var imports = SpectestImports{
            .lookup = std.StringHashMapUnmanaged(wasmstint.runtime.ExternVal).empty,
        };

        try imports.lookup.ensureTotalCapacity(
            arena.allocator(),
            PrintFunction.all.len + globals.names.len,
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
        const host: *SpectestImports = @ptrCast(@alignCast(ctx));
        _ = desc;

        if (!std.mem.eql(u8, "spectest", module.bytes))
            return null;

        return host.lookup.get(name.bytes);
    }
};

// TODO: What if arguments could be allocated directly in the Interpreter's value_stack?
fn allocateFunctionArguments(
    script: *const Wast,
    arguments: Wast.Command.Arguments,
    arena: *ArenaAllocator,
    errors: *Wast.sexpr.Parser.Context,
) Wast.sexpr.Parser.ParseError![]const wasmstint.Interpreter.TaggedValue {
    const src_arguments: []const Wast.Command.Const = arguments.items(script.arena);
    const dst_values = try arena.allocator().alloc(wasmstint.Interpreter.TaggedValue, src_arguments.len);

    for (src_arguments, dst_values) |*src, *dst| {
        dst.* = switch (src.keyword.tag(script.tree)) {
            .@"keyword_i32.const" => .{ .i32 = src.value.i32 },
            .@"keyword_i64.const" => .{ .i64 = src.value.i64.get(script.arena) },
            .@"keyword_f32.const" => .{ .f32 = @bitCast(src.value.f32) },
            .@"keyword_f64.const" => .{ .f64 = @bitCast(src.value.f64.get(script.arena)) },
            .@"keyword_ref.extern" => .{
                .externref = .{
                    .nat = wasmstint.runtime.ExternAddr.Nat.fromInt(src.value.ref_extern),
                },
            },
            else => |bad| return (try errors.errorFmtAtToken(
                src.keyword,
                "TODO: encode argument {s}",
                .{@tagName(bad)},
            )).err,
        };
    }

    return dst_values;
}

inline fn wrapInterpreterError(result: anytype) Allocator.Error!@typeInfo(@TypeOf(result)).error_union.payload {
    return result catch |e| switch (e) {
        error.OutOfMemory => |oom| return oom,
        wasmstint.Interpreter.Error.InvalidInterpreterState => unreachable,
    };
}

const State = struct {
    const ModuleInst = wasmstint.runtime.ModuleInst;
    const Interpreter = wasmstint.Interpreter;

    errors: Wast.sexpr.Parser.Context,

    /// Allocated in the `run_arena`.
    module_lookups: std.AutoHashMapUnmanaged(Wast.Ident.Interned, ModuleInst) = .empty,

    /// Live until the next `module` command is executed.
    next_module_arena: ArenaAllocator,
    /// Allocated either in the `next_module_arena` or the `run_arena`.
    current_module: ?ModuleInst = null,

    /// Live for the execution of a single command.
    cmd_arena: ArenaAllocator,

    const Error = error{ScriptError} || Allocator.Error;

    inline fn scriptError(report: Allocator.Error!Wast.Errors.Report) Error {
        _ = try report;
        return error.ScriptError;
    }

    const ErrorContext = Wast.sexpr.Parser.Context;

    fn getModuleInst(state: *State, id: Wast.Ident.Symbolic, parent: Wast.sexpr.TokenId) Error!ModuleInst {
        return if (id.some)
            if (state.module_lookups.get(id.ident)) |found|
                found
            else
                scriptError(state.errors.errorAtToken(id.token, "no module with the given name was instantiated"))
        else if (state.current_module) |current|
            current
        else
            scriptError(state.errors.errorAtToken(parent, "no module has been instantiated at this point"));
    }

    fn runToCompletion(state: *State, interpreter: *Interpreter) Allocator.Error!void {
        // state_label:
        switch (interpreter.state) {
            .awaiting_lazy_validation => unreachable,
            .interrupted => |cause| switch (cause) {
                .out_of_fuel, .call_stack_exhaustion => return,
                .validation_finished => unreachable,
            },
            .trapped => return,
            .awaiting_host => if (interpreter.call_stack.items.len == 0) {
                return;
            } else {
                _ = state;
                std.debug.panic("TODO: Handle host call", .{});
            },
        }

        comptime unreachable;
    }

    fn errorInterpreterTrap(state: *State, parent: Wast.sexpr.TokenId, trap_code: Interpreter.TrapCode) Error {
        return scriptError(state.errors.errorFmtAtToken(parent, "unexpected trap, {any}", .{trap_code}));
    }

    fn errorInterpreterInterrupted(
        state: *State,
        parent: Wast.sexpr.TokenId,
        cause: Interpreter.InterruptionCause,
    ) Error {
        const msg = switch (cause) {
            .validation_finished => unreachable,
            .out_of_fuel => "unexpected error, execution ran out of fuel",
            .call_stack_exhaustion => "unexpected error, call stack exhausted",
        };

        return scriptError(state.errors.errorAtToken(parent, msg));
    }

    fn errorInterpreterResults(
        state: *State,
        parent: Wast.sexpr.TokenId,
        interpreter: *const Interpreter,
    ) Error {
        const results = interpreter.copyResultValues(&state.cmd_arena) catch |e| switch (e) {
            error.OutOfMemory => |oom| return oom,
            error.InvalidInterpreterState => unreachable,
        };

        const Results = struct {
            values: []const wasmstint.Interpreter.TaggedValue,

            pub fn format(self: @This(), comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
                _ = fmt;
                _ = options;
                try writer.print("{} results", .{self.values.len});
                if (self.values.len > 0) {
                    try writer.writeByte(':');
                    for (self.values) |value| {
                        try writer.writeByte(' ');
                        switch (value) {
                            .i32 => |i| try writer.print(
                                "(i32.const 0x{[u]X:0>8} (; {[u]}, {[s]} ;))",
                                .{ .u = i, .s = @as(u32, @bitCast(i)) },
                            ),
                            .i64 => |i| try writer.print(
                                "(i64.const 0x{[u]X:0>16} (; {[u]}, {[s]} ;))",
                                .{ .u = i, .s = @as(u64, @bitCast(i)) },
                            ),
                            .f32 => |z| try writer.print(
                                "(f32.const 0x{[z]x} (; {[z]}, {[z]e} ;))",
                                .{ .z = z },
                            ),
                            .f64 => |z| try writer.print(
                                "(f32.const 0x{[z]x} (; {[z]}, {[z]e} ;))",
                                .{ .z = z },
                            ),
                            .externref => |extern_ref| if (extern_ref.nat.toInt()) |nat|
                                try writer.print("(ref.extern {})", .{nat})
                            else
                                try writer.writeAll("(ref.null extern)"),
                            .funcref => try writer.writeAll("(ref.func ???)"),
                        }
                    }
                }
            }
        };

        return scriptError(state.errors.errorFmtAtToken(
            parent,
            "call unexpectedly succeeded with {}",
            .{Results{ .values = results }},
        ));
    }

    fn expectTypedValue(
        state: *State,
        parent: Wast.sexpr.TokenId,
        value: *const Interpreter.TaggedValue,
        pos: u32,
        comptime tag: std.meta.Tag(Interpreter.TaggedValue),
    ) Error!@FieldType(Interpreter.TaggedValue, @tagName(tag)) {
        return if (value.* != tag)
            scriptError(state.errors.errorFmtAtToken(
                parent,
                "expected result #{} to be a " ++ @tagName(tag) ++ ", but got a {s}",
                .{ pos, @tagName(value.*) },
            ))
        else
            @field(value, @tagName(tag));
    }

    fn checkIntegerResult(
        state: *State,
        expected_token: Wast.sexpr.TokenId,
        expected: anytype,
        actual: @TypeOf(expected),
    ) Error!void {
        const Unsigned = std.meta.Int(.unsigned, @typeInfo(@TypeOf(expected)).int.bits);

        if (expected != actual) {
            return scriptError(state.errors.errorFmtAtToken(
                expected_token,
                "expected 0x{[expected_u]X:0>[width]} " ++
                    "({[expected_s]} signed, {[expected_u]} unsigned)" ++
                    ", but got 0x{[actual_u]X:0>[width]} " ++
                    "({[actual_s]} signed, {[actual_u]} unsigned)",
                .{
                    .expected_s = expected,
                    .expected_u = @as(Unsigned, @bitCast(expected)),
                    .actual_s = actual,
                    .actual_u = @as(Unsigned, @bitCast(actual)),
                    .width = @sizeOf(@TypeOf(expected_token)) * 2,
                },
            ));
        }
    }

    fn checkFloatResult(
        state: *State,
        expected: *const Wast.Command.Result,
        accessor: anytype,
        actual: anytype,
    ) Error!void {
        const print_width = @sizeOf(@TypeOf(actual)) * 2;
        const PayloadInt = std.meta.Int(.unsigned, std.math.floatMantissaBits(@TypeOf(actual)));
        const Bits = std.meta.Int(.unsigned, @typeInfo(@TypeOf(actual)).float.bits);

        const actual_bits: Bits = @bitCast(actual);

        const actual_nan_payload: PayloadInt = @intCast(actual_bits & std.math.maxInt(PayloadInt));
        const canonical_nan_payload: PayloadInt = 1 << (@bitSizeOf(PayloadInt) - 1);

        switch (expected.value_token.tag(state.errors.tree)) {
            .integer, .float, .keyword_nan, .keyword_inf => {
                const expected_bits: Bits = @call(
                    .always_inline,
                    @TypeOf(accessor).bits,
                    .{ accessor, expected },
                );

                if (actual_bits != expected_bits)
                    return scriptError(state.errors.errorFmtAtToken(
                        expected.value_token,
                        "expected 0x{[expected_b]X:0>[width]} ({[expected_f]}), " ++
                            "but got 0x{[actual_b]X:0>[width]} ({[actual_f]})",
                        .{
                            .expected_b = expected_bits,
                            .expected_f = @as(@TypeOf(actual), @bitCast(expected_bits)),
                            .actual_b = actual_bits,
                            .actual_f = actual,
                            .width = print_width,
                        },
                    ));
            },
            .@"keyword_nan:canonical" => {
                // https://webassembly.github.io/spec/core/syntax/values.html#canonical-nan
                if (!std.math.isNan(actual) or actual_nan_payload != canonical_nan_payload)
                    return scriptError(state.errors.errorFmtAtToken(
                        expected.value_token,
                        "expected canonical NaN, but got 0x{[bits]X:0>[width]} ({[float]})",
                        .{
                            .bits = actual_bits,
                            .width = print_width,
                            .float = actual,
                        },
                    ));
            },
            .@"keyword_nan:arithmetic" => {
                if (!std.math.isNan(actual) or (actual_nan_payload & canonical_nan_payload) == 0)
                    return scriptError(state.errors.errorFmtAtToken(
                        expected.value_token,
                        "expected arithmetic NaN, but got 0x{[bits]X:0>[width]} ({[float]})",
                        .{
                            .bits = actual_bits,
                            .width = print_width,
                            .float = actual,
                        },
                    ));
            },
            else => |bad| return scriptError(state.errors.errorFmtAtToken(
                expected.keyword,
                "TODO: handle " ++ @typeName(@TypeOf(expected)) ++ " result {s}",
                .{@tagName(bad)},
            )),
        }
    }

    fn expectResultValues(
        state: *State,
        interpreter: *Interpreter,
        parent: Wast.sexpr.TokenId,
        script: *const Wast,
        results: []const Wast.Command.Result,
    ) Error!void {
        try state.runToCompletion(interpreter);
        switch (interpreter.state) {
            .awaiting_lazy_validation => unreachable,
            .trapped => |code| return state.errorInterpreterTrap(parent, code),
            .interrupted => |cause| return state.errorInterpreterInterrupted(parent, cause),
            .awaiting_host => std.debug.assert(interpreter.call_stack.items.len == 0),
        }

        const actual_results: []const Interpreter.TaggedValue = try wrapInterpreterError(
            interpreter.copyResultValues(&state.cmd_arena),
        );

        if (actual_results.len != results.len) {
            return scriptError(state.errors.errorFmtAtToken(
                parent,
                "expected {} results, but got {}",
                .{ results.len, actual_results.len },
            ));
        }

        for (actual_results, results, 0..) |*actual, *expected, index| {
            const pos: u32 = @intCast(index);
            switch (expected.keyword.tag(state.errors.tree)) {
                .@"keyword_i32.const" => try state.checkIntegerResult(
                    expected.value_token,
                    expected.value.i32,
                    try state.expectTypedValue(
                        expected.value_token,
                        actual,
                        pos,
                        .i32,
                    ),
                ),
                .@"keyword_i64.const" => try state.checkIntegerResult(
                    expected.value_token,
                    expected.value.i64.get(script.arena),
                    try state.expectTypedValue(
                        expected.value_token,
                        actual,
                        pos,
                        .i64,
                    ),
                ),
                .@"keyword_f32.const" => {
                    const GetF32 = struct {
                        fn bits(_: @This(), result: *const Wast.Command.Result) u32 {
                            return result.value.f32;
                        }
                    };

                    try state.checkFloatResult(
                        expected,
                        GetF32{},
                        try state.expectTypedValue(
                            expected.value_token,
                            actual,
                            pos,
                            .f32,
                        ),
                    );
                },
                .@"keyword_f64.const" => {
                    const GetF64 = struct {
                        arena: *const Wast.Arena,

                        fn bits(ctx: @This(), result: *const Wast.Command.Result) u64 {
                            return result.value.f64.get(ctx.arena);
                        }
                    };

                    try state.checkFloatResult(
                        expected,
                        GetF64{ .arena = script.arena },
                        try state.expectTypedValue(
                            expected.value_token,
                            actual,
                            pos,
                            .f64,
                        ),
                    );
                },
                else => |bad| return scriptError(state.errors.errorFmtAtToken(
                    expected.keyword,
                    "TODO: handle result {s}",
                    .{@tagName(bad)},
                )),
            }
        }
    }

    const trap_code_lookup = std.StaticStringMap(Interpreter.TrapCode).initComptime(.{
        .{ "unreachable", .unreachable_code_reached },
        .{ "integer divide by zero", .integer_division_by_zero },
        .{ "integer overflow", .integer_overflow },
        .{ "invalid conversion to integer", .invalid_conversion_to_integer },
        .{ "out of bounds memory access", .memory_access_out_of_bounds },
    });

    fn expectTrap(
        state: *State,
        script: *const Wast,
        interpreter: *Interpreter,
        parent: Wast.sexpr.TokenId,
        failure: *const Wast.Command.Failure,
    ) Error!void {
        try state.runToCompletion(interpreter);
        const trap_code: Interpreter.TrapCode = switch (interpreter.state) {
            .awaiting_lazy_validation => unreachable,
            .trapped => |code| code,
            .interrupted => |cause| return state.errorInterpreterInterrupted(parent, cause),
            .awaiting_host => return state.errorInterpreterResults(parent, interpreter),
        };

        const expected_code = trap_code_lookup.get(failure.msg.slice(script.arena)) orelse return scriptError(
            state.errors.errorFmtAtToken(
                parent,
                "call failed with wrong trap code ({})",
                .{trap_code},
            ),
        );

        if (trap_code != expected_code) return scriptError(
            state.errors.errorFmtAtToken(
                parent,
                "expected call to fail with trap code {}, but got {}",
                .{ expected_code, trap_code },
            ),
        );
    }

    fn expectExhaustion(
        state: *State,
        script: *const Wast,
        interpreter: *Interpreter,
        parent: Wast.sexpr.TokenId,
        failure: *const Wast.Command.Failure,
    ) Error!void {
        try state.runToCompletion(interpreter);
        const interruption_cause: Interpreter.InterruptionCause = switch (interpreter.state) {
            .awaiting_lazy_validation => unreachable,
            .trapped => |code| return state.errorInterpreterTrap(parent, code),
            .interrupted => |cause| cause,
            .awaiting_host => return state.errorInterpreterResults(parent, interpreter),
        };

        switch (interruption_cause) {
            .validation_finished => unreachable,
            .out_of_fuel, .call_stack_exhaustion => {},
        }

        const expected_msg = "call stack exhausted";
        if (!std.mem.eql(u8, failure.msg.slice(script.arena), expected_msg)) {
            return scriptError(state.errors.errorAtToken(parent, "expected failure string \"" ++ expected_msg ++ "\""));
        }
    }

    fn beginAction(
        state: *State,
        script: *const Wast,
        keyword: Wast.sexpr.TokenId,
        action: *const Wast.Command.Action,
        interpreter: *Interpreter,
        fuel: *Interpreter.Fuel,
    ) Error!void {
        const module = try state.getModuleInst(action.module, keyword);
        switch (action.keyword.tag(state.errors.tree)) {
            .keyword_invoke => {
                const export_name = script.nameContents(action.name.id);
                const target_export = module.findExport(export_name) catch return scriptError(
                    state.errors.errorFmtAtToken(
                        action.name.token,
                        "no exported value found with name {s}",
                        .{export_name},
                    ),
                );

                const callee = target_export.func;
                const arguments = allocateFunctionArguments(
                    script,
                    action.target.invoke.arguments,
                    &state.cmd_arena,
                    &state.errors,
                ) catch |e| return switch (e) {
                    error.OutOfMemory => |oom| oom,
                    error.ReportedParserError => error.ScriptError,
                };

                interpreter.beginCall(
                    state.cmd_arena.allocator(),
                    callee,
                    arguments,
                    fuel,
                ) catch |e| return switch (e) {
                    error.OutOfMemory => |oom| oom,
                    error.InvalidInterpreterState => unreachable,
                    error.ArgumentTypeOrCountMismatch => scriptError(
                        state.errors.errorAtToken(
                            action.keyword,
                            "argument count or type mismatch",
                        ),
                    ),
                };
            },
            else => unreachable,
        }
    }
};

fn runScript(
    script: *const Wast,
    rng: std.Random,
    encoding_buffer: *std.ArrayList(u8),
    run_arena: *ArenaAllocator, // Must not be reset for the lifetime of this function call.
    errors: *Wast.Errors,
) Allocator.Error!u32 {
    var store = wasmstint.runtime.ModuleAllocator.WithinArena{ .arena = run_arena };
    var state: State = .{
        .errors = .{ .tree = script.tree, .errors = errors },
        .next_module_arena = ArenaAllocator.init(run_arena.allocator()),
        .cmd_arena = ArenaAllocator.init(run_arena.allocator()),
    };

    var pass_count: u32 = 0;
    run_cmds: for (script.commands.items(script.arena)) |cmd| {
        defer _ = state.cmd_arena.reset(.retain_capacity);

        var fuel = wasmstint.Interpreter.Fuel{ .remaining = 2_000 };
        var interp = try wasmstint.Interpreter.init(state.cmd_arena.allocator(), .{});
        defer interp.reset();

        switch (cmd.keyword.tag(script.tree)) {
            .keyword_module => {
                _ = state.next_module_arena.reset(.retain_capacity);
                const module: *const Wast.Module = cmd.inner.module.getPtr(script.arena);

                const module_arena = if (module.name.some) run_arena else &state.next_module_arena;
                encoding_buffer.clearRetainingCapacity();
                const before_encode_error_count = errors.list.len;
                try module.encode(
                    script.tree,
                    script.arena.dataSlice(),
                    script.caches,
                    encoding_buffer.writer(),
                    errors,
                    &state.cmd_arena,
                );

                if (before_encode_error_count < errors.list.len)
                    break :run_cmds;

                var module_contents: []const u8 = if (module.name.some)
                    try run_arena.allocator().dupe(u8, encoding_buffer.items)
                else
                    encoding_buffer.items;

                const parsed_module = try module_arena.allocator().create(wasmstint.Module);
                parsed_module.* = wasmstint.Module.parse(
                    module_arena.allocator(),
                    &module_contents,
                    &state.cmd_arena,
                    rng,
                    .{ .realloc_contents = true },
                ) catch |e| switch (e) {
                    error.OutOfMemory => |oom| return oom,
                    else => |parse_error| {
                        std.debug.print("TODO: Module parse error {}\n", .{parse_error});
                        if (@errorReturnTrace()) |err_trace| {
                            std.debug.dumpStackTrace(err_trace.*);
                        }

                        _ = try state.errors.errorAtToken(cmd.keyword, "module failed to parse");
                        break :run_cmds;
                    },
                };

                //parsed_module.finishCodeValidationInParallel(state.cmd_arena, thread_pool)
                const validation_finished = parsed_module.finishCodeValidation(
                    module_arena.allocator(),
                    &state.cmd_arena,
                ) catch |e| switch (e) {
                    error.OutOfMemory => |oom| return oom,
                    else => |validation_err| {
                        std.debug.print("TODO: Code validation error {}\n", .{validation_err});
                        if (@errorReturnTrace()) |err_trace| {
                            std.debug.dumpStackTrace(err_trace.*);
                        }

                        _ = try state.errors.errorAtToken(cmd.keyword, "module was invalid");
                        break :run_cmds;
                    },
                };

                std.debug.assert(validation_finished);

                var imports = try SpectestImports.init(module_arena);
                var import_error: wasmstint.runtime.ImportProvider.FailedRequest = undefined;
                var module_alloc = wasmstint.runtime.ModuleAlloc.allocate(
                    parsed_module,
                    imports.provider(),
                    module_arena.allocator(),
                    store.allocator(),
                    &import_error,
                ) catch |e| switch (e) {
                    error.OutOfMemory => |oom| return oom,
                    error.ImportFailure => {
                        _ = try state.errors.errorFmtAtToken(
                            cmd.keyword,
                            "could not provide import {s} {s}",
                            .{
                                import_error.module.bytes,
                                import_error.name.bytes,
                            },
                        );
                        break :run_cmds;
                    },
                };

                try wrapInterpreterError(
                    interp.instantiateModule(
                        state.cmd_arena.allocator(),
                        &module_alloc,
                        &fuel,
                    ),
                );

                state.expectResultValues(
                    &interp,
                    cmd.keyword,
                    script,
                    &[0]Wast.Command.Result{},
                ) catch |e| switch (e) {
                    error.OutOfMemory => |oom| return oom,
                    error.ScriptError => {
                        _ = try state.errors.errorAtToken(
                            cmd.keyword,
                            "module start function failed",
                        );
                        break :run_cmds;
                    },
                };

                const module_inst = module_alloc.expectInstantiated();
                state.current_module = module_inst;

                if (module.name.some) {
                    // Are duplicate module names an error? or should it just overwrite?
                    _ = try state.module_lookups.fetchPut(
                        run_arena.allocator(),
                        module.name.ident,
                        module_inst,
                    );
                }
            },
            .keyword_assert_return => {
                const assert_return: *const Wast.Command.AssertReturn = cmd.inner.assert_return.getPtr(script.arena);

                state.beginAction(
                    script,
                    cmd.keyword,
                    assert_return.action.getPtr(script.arena),
                    &interp,
                    &fuel,
                ) catch |e| switch (e) {
                    error.OutOfMemory => |oom| return oom,
                    error.ScriptError => break :run_cmds,
                };

                state.expectResultValues(
                    &interp,
                    cmd.keyword,
                    script,
                    assert_return.results.items(script.arena),
                ) catch |e| switch (e) {
                    error.OutOfMemory => |oom| return oom,
                    error.ScriptError => break :run_cmds,
                };
            },
            .keyword_assert_trap => {
                const assert_trap: *const Wast.Command.AssertTrap = cmd.inner.assert_trap.getPtr(script.arena);

                state.beginAction(
                    script,
                    cmd.keyword,
                    assert_trap.action.getPtr(script.arena),
                    &interp,
                    &fuel,
                ) catch |e| switch (e) {
                    error.OutOfMemory => |oom| return oom,
                    error.ScriptError => break :run_cmds,
                };

                state.expectTrap(
                    script,
                    &interp,
                    cmd.keyword,
                    &assert_trap.failure,
                ) catch |e| switch (e) {
                    error.OutOfMemory => |oom| return oom,
                    error.ScriptError => break :run_cmds,
                };
            },
            .keyword_assert_exhaustion => {
                const assert_exhaustion: *const Wast.Command.AssertExhaustion = cmd.inner.assert_exhaustion.getPtr(script.arena);

                state.beginAction(
                    script,
                    cmd.keyword,
                    assert_exhaustion.action.getPtr(script.arena),
                    &interp,
                    &fuel,
                ) catch |e| switch (e) {
                    error.OutOfMemory => |oom| return oom,
                    error.ScriptError => break :run_cmds,
                };
            },
            .keyword_assert_invalid => {
                if (true) continue; // For debugging purposes only!

                var alloca = ArenaAllocator.init(state.cmd_arena.allocator());
                const assert_invalid: *const Wast.Command.AssertInvalid = cmd.inner.assert_invalid.getPtr(script.arena);

                // TODO: Actually check that validation fails with the right message.

                var module_errors = Wast.Errors.init(state.cmd_arena.allocator());

                encoding_buffer.clearRetainingCapacity();
                try assert_invalid.module.encode(
                    script.tree,
                    script.arena.dataSlice(),
                    script.caches,
                    encoding_buffer.writer(),
                    &module_errors,
                    &alloca,
                );

                if (module_errors.list.len > 0) continue;

                var module_contents: []const u8 = encoding_buffer.items;
                _ = wasmstint.Module.parse(
                    state.cmd_arena.allocator(),
                    &module_contents,
                    &alloca,
                    rng,
                    .{ .realloc_contents = true },
                ) catch |e| switch (e) {
                    error.OutOfMemory => |oom| return oom,
                    else => continue,
                };

                _ = try state.errors.errorAtToken(cmd.keyword, "module unexpectedly succeeded validation");
            },
            .keyword_assert_malformed => {
                if (true) continue; // For debugging purposes only!

                unreachable; // TODO: Process 'assert_malformed'
            },
            else => {
                _ = try state.errors.errorAtToken(
                    cmd.keyword,
                    "TODO: process command",
                );
                // unreachable
            },
        }

        pass_count += 1;
    }

    return pass_count;
}
