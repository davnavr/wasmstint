const State = @This();

const NamedModule = struct {
    line: usize,
    instance: ModuleInst,
};

module_arena: ArenaAllocator,
/// Allocated in `std.heap.page_allocator`.
module_lookup: std.StringHashMapUnmanaged(NamedModule),
current_module: ?ModuleInst,
interpreter_allocator: std.mem.Allocator,
max_memory_size: usize,
interpreter: Interpreter,
starting_fuel: Interpreter.Fuel,

imports: *Imports,
script_dir: std.fs.Dir,
rng: *std.Random.Xoshiro256,

const Error = error{ScriptError};

pub fn init(
    state: *State,
    interpreter_allocator: std.mem.Allocator,
    max_memory_size: usize,
    starting_fuel: Interpreter.Fuel,
    imports: *Imports,
    script_dir: std.fs.Dir,
    rng: *std.Random.Xoshiro256,
) void {
    state.* = .{
        .module_arena = ArenaAllocator.init(std.heap.page_allocator),
        .module_lookup = .empty,
        .current_module = null,
        .interpreter_allocator = interpreter_allocator,
        .max_memory_size = max_memory_size,
        .interpreter = undefined,
        .starting_fuel = starting_fuel,
        .imports = imports,
        .script_dir = script_dir,
        .rng = rng,
    };
    _ = wasmstint.Interpreter.init(&state.interpreter, interpreter_allocator, .{}) catch
        @panic("oom");
}

pub const Output = struct {
    tty_config: std.Io.tty.Config,
    writer: *std.Io.Writer,

    pub inline fn setColor(output: *const Output, color: std.Io.tty.Color) void {
        output.tty_config.setColor(output.writer, color) catch {};
    }

    pub inline fn print(output: *const Output, comptime fmt: []const u8, args: anytype) void {
        output.writer.print(fmt, args) catch {};
    }

    pub inline fn writeAll(output: *const Output, bytes: []const u8) void {
        output.writer.writeAll(bytes) catch {};
    }

    pub fn writeErrorPreamble(output: *const Output) void {
        output.setColor(.bright_red);
        output.writeAll("error: ");
        output.setColor(.reset);
    }
};

fn fail(output: Output, message: []const u8) Error {
    output.writeErrorPreamble();
    output.writeAll(message);
    output.writer.writeByte('\n') catch {};
    return error.ScriptError;
}

fn failFmt(output: Output, comptime fmt: []const u8, args: anytype) Error {
    output.writeErrorPreamble();
    output.print(fmt ++ "\n", args);
    return error.ScriptError;
}

pub fn processCommand(
    state: *State,
    command: *const Parser.Command,
    output: Output,
    scratch: *ArenaAllocator,
) Error!void {
    switch (command.type) {
        .module => try state.processModuleCommand(command, output, scratch),
        .action => |*act| {
            var fuel = state.starting_fuel;
            switch (try state.processActionCommand(act, output, &fuel, scratch)) {
                .invoke => |invoke_state| _ = state.runToCompletion(
                    invoke_state,
                    &fuel,
                    output,
                    &state.module_arena,
                ),
                .get => {},
            }
        },
        .assert_return => |*assert_return| try state.processAssertReturn(
            assert_return,
            output,
            scratch,
        ),
        .assert_exhaustion => |*assert_exhaustion| try state.processAssertExhaustion(
            assert_exhaustion,
            output,
            scratch,
        ),
        .assert_trap => |*assert_trap| try state.processAssertTrap(assert_trap, output, scratch),
        .assert_invalid => |*assert_invalid| try state.processAssertInvalid(
            assert_invalid,
            output,
            scratch,
        ),
        .assert_malformed => |*assert_malformed| try state.processAssertMalformed(
            assert_malformed,
            output,
            scratch,
        ),
        .assert_uninstantiable => |*assert_uninstantiable| try state.processAssertUninstantiable(
            assert_uninstantiable,
            output,
            scratch,
        ),
        .assert_unlinkable => |*assert_unlinkable| try state.processAssertUnlinkable(
            assert_unlinkable,
            output,
            scratch,
        ),
        .register => |*register| try state.processRegisterCommand(register, output),
    }
}

fn openModuleContents(
    state: *State,
    filename: [:0]const u8,
    output: Output,
) Error!wasmstint.FileContent {
    return wasmstint.FileContent.readFileZ(
        state.script_dir,
        filename,
    ) catch |e| switch (e) {
        error.OutOfMemory => @panic("oom"),
        else => |io_err| failFmt(
            output,
            "I/O error while reading file \"{f}\": {t}",
            .{ std.unicode.fmtUtf8(filename), io_err },
        ),
    };
}

fn finishModuleAllocation(
    max_memory_size: usize,
    module: *wasmstint.runtime.ModuleAllocating,
    arena: *ArenaAllocator,
) Error!wasmstint.runtime.ModuleAlloc {
    while (module.nextMemoryType()) |ty| {
        wasmstint.runtime.paged_memory.allocate(
            module,
            ty.limits.min * wasmstint.runtime.MemInst.page_size,
            max_memory_size,
        ) catch @panic("bad mem");
    }

    while (module.nextTableType()) |_| {
        wasmstint.runtime.table_allocator.allocateForModule(
            module,
            arena.allocator(),
            65536, // 1 MiB, 16 bytes per funcref
        ) catch @panic("bad table");
    }

    return module.finish() catch @panic("bad alloc");
}

fn processModuleCommand(
    state: *State,
    command: *const Parser.Command,
    output: Output,
    alloca: *ArenaAllocator,
) Error!void {
    defer _ = alloca.reset(.retain_capacity);
    var scratch = ArenaAllocator.init(alloca.allocator());

    const module = &command.type.module;
    const module_lookup_entry = if (module.name) |name| has_name: {
        const entry = state.module_lookup.getOrPut(std.heap.page_allocator, name) catch
            @panic("oom");

        if (entry.found_existing) return failFmt(
            output,
            "module with name \"{s}\" was already defined on line {}",
            .{ name, entry.value_ptr.line },
        );

        break :has_name entry;
    } else null;

    const module_binary = try state.openModuleContents(module.filename, output);
    const fmt_filename = std.unicode.fmtUtf8(module.filename);
    // errdefer module_binary.deinit();

    var parse_diagnostics = std.Io.Writer.Allocating.initCapacity(alloca.allocator(), 128) catch
        @panic("oom");
    const parsed_module = module: {
        var wasm: []const u8 = module_binary.contents;
        break :module wasmstint.Module.parse(
            state.module_arena.allocator(),
            &wasm,
            &scratch,
            .{
                .random_seed = state.rng.random().int(u64),
                .diagnostics = .init(&parse_diagnostics.writer),
            },
        ) catch |e| return switch (e) {
            error.OutOfMemory => @panic("oom"),
            error.InvalidWasm => failFmt(
                output,
                "failed to validate module {f}: {s}",
                .{ fmt_filename, parse_diagnostics.written() },
            ),
            error.MalformedWasm => failFmt(
                output,
                "failed to parse module {f}: {s}",
                .{ fmt_filename, parse_diagnostics.written() },
            ),
            else => return failFmt(output, "failed to parse module {f}: {t}", .{ fmt_filename, e }),
        };
    };
    _ = scratch.reset(.retain_capacity);

    // `assert_invalid` commands mean lazy validation won't work
    parse_diagnostics.clearRetainingCapacity();
    const validation_finished = parsed_module.finishCodeValidation(
        state.module_arena.allocator(),
        &scratch,
        .init(&parse_diagnostics.writer),
    ) catch |e| switch (e) {
        error.OutOfMemory => @panic("oom"),
        error.InvalidWasm, error.MalformedWasm => return failFmt(
            output,
            "failed to validate code for module {f}: {s}",
            .{ fmt_filename, parse_diagnostics.written() },
        ),
        else => return failFmt(
            output,
            "failed to parse module code {f}: {t}",
            .{ fmt_filename, e },
        ),
    };

    scratch = undefined;
    _ = alloca.reset(.retain_capacity);

    std.debug.assert(validation_finished);

    var import_error: wasmstint.runtime.ImportProvider.FailedRequest = undefined;
    var module_allocating = wasmstint.runtime.ModuleAllocating.begin(
        parsed_module,
        state.imports.provider(),
        state.module_arena.allocator(),
        &import_error,
    ) catch |e| switch (e) {
        error.OutOfMemory => @panic("oom"),
        error.ImportFailure => return failFmt(output, "{f}", .{import_error}),
    };

    var module_alloc = try finishModuleAllocation(
        state.max_memory_size,
        &module_allocating,
        &state.module_arena,
    );

    var fuel = state.starting_fuel;
    var interp = state.interpreter.reset();
    interp = interp.awaiting_host.instantiateModule(
        state.module_arena.allocator(),
        &module_alloc,
        &fuel,
    ) catch @panic("oom");

    _ = try state.expectResultValues(
        interp,
        &fuel,
        &Parser.Command.Expected.Vec{},
        output,
        alloca,
    );

    const module_inst = module_alloc.assumeInstantiated();
    state.current_module = module_inst;

    if (module_lookup_entry) |entry| {
        entry.value_ptr.* = .{ .instance = module_inst, .line = command.line };
    }

    output.print("instantiated \"{f}\"\n", .{fmt_filename});
}

/// Gets the module with the given `name`, or returns the most recent module if `name` is `null`.
fn findModuleInst(state: *const State, name: ?[]const u8, output: Output) Error!ModuleInst {
    if (name) |find_name| {
        const named = state.module_lookup.get(find_name) orelse return failFmt(
            output,
            "no module with name \"{s}\" has been instantiated at this point",
            .{find_name},
        );
        return named.instance;
    } else if (state.current_module) |module| {
        return module;
    } else {
        return fail(output, "no module has been instantiated at this point");
    }
}

fn processRegisterCommand(
    state: *State,
    command: *const Parser.Command.Register,
    output: Output,
) Error!void {
    const target_module: ModuleInst = try state.findModuleInst(command.name, output);
    const export_vals = target_module.exports();

    state.imports.registered.ensureUnusedCapacityContext(
        std.heap.page_allocator,
        export_vals.len,
        state.imports.registered_context,
    ) catch @panic("oom");

    for (0..export_vals.len) |i| {
        const val = export_vals.at(i);
        state.imports.registered.putAssumeCapacityContext(
            Imports.Name.init(command.as, val.name),
            val.val,
            state.imports.registered_context,
        );
    }

    output.print(
        "registered module \"{f}\" exports under \"{s}\"\n",
        .{ fmtModuleName(command.name), command.as },
    );
}

fn failCallStackExhausted(state: *const State, output: Output) Error {
    return failFmt(
        output,
        "call stack exhausted after {} frames",
        .{state.interpreter.call_depth},
    );
}

fn failInterpreterTrap(
    trap: *const Interpreter.Trap,
    output: Output,
) Error {
    return failFmt(output, "unexpected trap {t}: {f}", .{ trap.code, TrapMessage.init(trap) });
}

fn failInterpreterInterrupted(
    cause: Interpreter.InterruptionCause,
    output: Output,
) Error {
    const message = switch (cause) {
        .out_of_fuel => "interpreter ran out of fuel",
        .memory_grow, .table_grow => unreachable,
    };

    return fail(output, message);
}

fn resultIntegerMatches(
    expected: anytype,
    actual: std.meta.Int(.signed, @typeInfo(@TypeOf(expected)).int.bits),
    index: usize,
    output: Output,
) Error!void {
    const actual_unsigned: @TypeOf(expected) = @bitCast(actual);
    if (expected != actual_unsigned) return failFmt(
        output,
        "expected 0x{[expected_u]X:0>[width]} " ++
            "({[expected_s]} signed, {[expected_u]} unsigned)" ++
            ", got 0x{[actual_u]X:0>[width]} " ++
            "({[actual_s]} signed, {[actual_u]} unsigned) at position {[pos]}",
        .{
            .expected_s = @as(@TypeOf(actual), @bitCast(expected)),
            .expected_u = expected,
            .actual_s = actual,
            .actual_u = actual_unsigned,
            .width = @sizeOf(@TypeOf(expected)) * 2,
            .pos = index,
        },
    );
}

fn resultFloatMatchesBits(
    expected_bits: anytype,
    actual: std.meta.Float(@typeInfo(@TypeOf(expected_bits)).int.bits),
    index: usize,
    output: Output,
) Error!void {
    const actual_bits: @TypeOf(expected_bits) = @bitCast(actual);
    if (expected_bits != actual_bits) return failFmt(
        output,
        "expected 0x{[expected_b]X:0>[width]} ({[expected_f]}), " ++
            "got 0x{[actual_b]X:0>[width]} ({[actual_f]}) at position {[pos]}",
        .{
            .expected_b = expected_bits,
            .expected_f = @as(@TypeOf(actual), @bitCast(expected_bits)),
            .actual_b = actual_bits,
            .actual_f = actual,
            .width = @sizeOf(@TypeOf(actual)) * 2,
            .pos = index,
        },
    );
}

pub fn resultFloatMatchesNan(
    expected: Parser.Command.Expected.Nan,
    actual: anytype,
    index: usize,
    output: Output,
) Error!void {
    const print_width = @sizeOf(@TypeOf(actual)) * 2;

    const Bits = std.meta.Int(.unsigned, @typeInfo(@TypeOf(actual)).float.bits);

    const PayloadInt = std.meta.Int(.unsigned, std.math.floatMantissaBits(@TypeOf(actual)));
    const nan_payload_mask = std.math.maxInt(PayloadInt);
    const canonical_nan_payload: PayloadInt = 1 << (@bitSizeOf(PayloadInt) - 1);

    const actual_bits: Bits = @bitCast(actual);
    const actual_nan_payload: PayloadInt = @intCast(actual_bits & nan_payload_mask);

    bad: {
        if (!std.math.isNan(actual)) break :bad;

        switch (expected) {
            .canonical => if (actual_nan_payload != canonical_nan_payload)
                break :bad,
            .arithmetic => if ((actual_nan_payload & canonical_nan_payload) == 0)
                break :bad,
        }

        return;
    }

    return failFmt(
        output,
        "expected {[nan]t:} NaN, got 0x{[bits]X:0>[width]} ({[float]}) at position {[pos]}",
        .{
            .nan = expected,
            .bits = actual_bits,
            .width = print_width,
            .float = actual,
            .pos = index,
        },
    );
}

fn expectTypedValue(
    value: *const Interpreter.TaggedValue,
    comptime tag: std.meta.Tag(Interpreter.TaggedValue),
    index: usize,
    output: Output,
) Error!@FieldType(Interpreter.TaggedValue, @tagName(tag)) {
    return if (value.* != tag)
        failFmt(
            output,
            "expected " ++ @tagName(tag) ++ " at position {}, but got a {t}",
            .{ index, value.* },
        )
    else
        @field(value, @tagName(tag));
}

fn resultValueMatches(
    actual: *const Interpreter.TaggedValue,
    expected: *const Parser.Command.Expected,
    index: usize,
    output: Output,
) Error!void {
    switch (expected.*) {
        .i32 => |expected_i| try resultIntegerMatches(
            expected_i,
            try expectTypedValue(actual, .i32, index, output),
            index,
            output,
        ),
        .i64 => |expected_i| try resultIntegerMatches(
            expected_i,
            try expectTypedValue(actual, .i64, index, output),
            index,
            output,
        ),
        .f32 => |expected_f| try resultFloatMatchesBits(
            expected_f,
            try expectTypedValue(actual, .f32, index, output),
            index,
            output,
        ),
        .f64 => |expected_f| try resultFloatMatchesBits(
            expected_f,
            try expectTypedValue(actual, .f64, index, output),
            index,
            output,
        ),
        .f32_nan => |nan| try resultFloatMatchesNan(
            nan,
            try expectTypedValue(actual, .f32, index, output),
            index,
            output,
        ),
        .f64_nan => |nan| try resultFloatMatchesNan(
            nan,
            try expectTypedValue(actual, .f64, index, output),
            index,
            output,
        ),
        .funcref => {
            const actual_ref = (try expectTypedValue(actual, .funcref, index, output)).funcInst();
            if (actual_ref) |non_null| {
                return failFmt(
                    output,
                    "expected null, got {f} at position {}",
                    .{ non_null, index },
                );
            }
        },
        .externref => |extern_ref| {
            const actual_ref = (try expectTypedValue(actual, .externref, index, output)).nat;
            const expected_ref = if (extern_ref) |n|
                wasmstint.runtime.ExternAddr.Nat.fromInt(n)
            else
                .null;

            if (!actual_ref.eql(expected_ref)) {
                return failFmt(
                    output,
                    "expected {f}, got {f}",
                    .{ expected_ref, actual_ref },
                );
            }
        },
    }
}

fn expectResultValues(
    state: *State,
    interp: Interpreter.State,
    fuel: *Interpreter.Fuel,
    expected: *const Parser.Command.Expected.Vec,
    output: Output,
    scratch: *ArenaAllocator,
) Error![]const Interpreter.TaggedValue {
    const result_state = switch (state.runToCompletion(interp, fuel, output, &state.module_arena)) {
        .awaiting_validation => unreachable,
        .call_stack_exhaustion => return state.failCallStackExhausted(output),
        .trapped => |trap| return failInterpreterTrap(&trap.trap, output),
        .interrupted => |interrupt| return failInterpreterInterrupted(interrupt.cause, output),
        .awaiting_host => |awaiting| awaiting,
    };

    std.debug.assert(state.interpreter.call_depth == 0);

    const actual_results: []const Interpreter.TaggedValue =
        result_state.allocResults(scratch.allocator()) catch @panic("oom");

    if (expected.len != actual_results.len) return failFmt(
        output,
        "expected {} results, but got {}",
        .{ expected.len, actual_results.len },
    );

    for (0.., actual_results) |i, *actual_val| {
        const expected_val: *const Parser.Command.Expected = expected.at(i);
        try resultValueMatches(actual_val, expected_val, i, output);
    }

    return actual_results;
}

fn runToCompletion(
    state: *State,
    interpreter_state: Interpreter.State,
    fuel: *Interpreter.Fuel,
    output: Output,
    /// Used to allocate tables.
    store_arena: *ArenaAllocator,
) Interpreter.State {
    var interp = interpreter_state;
    for (0..123456) |_| {
        interp = next: switch (interp) {
            .awaiting_host => |*host| if (host.currentHostFunction()) |callee| {
                const print_func_idx = @divExact(
                    @intFromPtr(callee.func) - @intFromPtr(&Imports.PrintFunction.functions),
                    @sizeOf(wasmstint.runtime.FuncAddr.Host),
                );

                const print_func = Imports.PrintFunction.all[print_func_idx];

                output.print("- {t}(", .{print_func});
                switch (print_func) {
                    .print => {},
                    .print_i32 => output.print(
                        "{}",
                        host.paramsTyped(struct { i32 }) catch unreachable,
                    ),
                    .print_i64 => output.print(
                        "{}",
                        host.paramsTyped(struct { i64 }) catch unreachable,
                    ),
                    .print_f32 => output.print(
                        "{}",
                        host.paramsTyped(struct { f32 }) catch unreachable,
                    ),
                    .print_f64 => output.print(
                        "{}",
                        host.paramsTyped(struct { f64 }) catch unreachable,
                    ),
                    .print_i32_f32 => output.print(
                        "{}, {}",
                        host.paramsTyped(struct { i32, f32 }) catch unreachable,
                    ),
                    .print_f64_f64 => output.print(
                        "{}, {}",
                        host.paramsTyped(struct { f64, f64 }) catch unreachable,
                    ),
                }
                output.writeAll(")\n");

                break :next host.returnFromHostTyped({}, fuel) catch unreachable;
            } else return interp,
            .awaiting_validation => unreachable,
            .call_stack_exhaustion => |*oof| oof.resumeExecution(
                state.interpreter_allocator,
                fuel,
            ) catch return interp,
            .interrupted => |*interrupt| {
                switch (interrupt.cause) {
                    .out_of_fuel => return interp,
                    .memory_grow => |*grow| {
                        wasmstint.runtime.paged_memory.grow(grow);
                        output.print(
                            "- handling memory.grow from {[old]} to {[new]}, " ++
                                "now {[current]} <= {[maximum]} ({[status]s}), was {[result]} pages\n",
                            .{
                                .old = grow.old_size,
                                .new = grow.new_size,
                                .current = grow.memory.size,
                                .maximum = grow.memory.limit,
                                .status = if (grow.memory.size == grow.new_size) "success" else "failure",
                                .result = grow.result.i32,
                            },
                        );
                    },
                    .table_grow => |*grow| wasmstint.runtime.table_allocator.grow(
                        grow,
                        store_arena.allocator(),
                    ),
                }

                break :next interrupt.resumeExecution(fuel);
            },
            .trapped => return interp,
        };
    }

    @panic("Possible infinite loop in interpreter handler");
}

const Action = union(enum) {
    invoke: Interpreter.State,
    get: Interpreter.TaggedValue,
};

fn formatModuleName(name: ?[]const u8, writer: *std.Io.Writer) std.Io.Writer.Error!void {
    if (name) |s| {
        try writer.print("module \"{s}\"", .{s});
    } else {
        try writer.writeAll("current module");
    }
}

fn fmtModuleName(name: ?[]const u8) std.fmt.Alt(?[]const u8, formatModuleName) {
    return .{ .data = name };
}

// TODO: What if arguments could be allocated directly in the Interpreter's value_stack?
fn allocateFunctionArguments(
    arguments: *const Parser.Command.Const.Vec,
    arena: *ArenaAllocator,
) []const Interpreter.TaggedValue {
    const dst_values = arena.allocator().alloc(Interpreter.TaggedValue, arguments.len) catch
        @panic("oom");

    for (dst_values, 0..) |*dst, i| {
        const src: *const Parser.Command.Const = arguments.at(i);
        dst.* = switch (src.*) {
            inline .i32, .i64, .f32, .f64 => |c, tag| @unionInit(
                Interpreter.TaggedValue,
                @tagName(tag),
                @bitCast(c),
            ),
            .funcref => .{ .funcref = wasmstint.runtime.FuncAddr.Nullable.null },
            .externref => |extern_ref| .{
                .externref = .{
                    .nat = if (extern_ref) |addr| .fromInt(addr) else .null,
                },
            },
        };
    }

    return dst_values;
}

fn processActionCommand(
    state: *State,
    command: *const Parser.Command.Action,
    output: Output,
    fuel: *Interpreter.Fuel,
    scratch: *ArenaAllocator,
) Error!Action {
    const module = try state.findModuleInst(command.module, output);
    const fmt_module = fmtModuleName(command.module);
    const target_export = module.findExport(command.field) catch |e| switch (e) {
        error.ExportNotFound => return failFmt(
            output,
            "{f} does not provide export with name \"{s}\"",
            .{ fmt_module, command.field },
        ),
    };

    switch (command.type) {
        .invoke => |*invoke| {
            const callee = switch (target_export) {
                .func => |f| f,
                else => return failFmt(
                    output,
                    "expected function export \"{s}\" from {f}, got {f}",
                    .{ command.field, fmt_module, target_export },
                ),
            };

            const invoke_state = state.interpreter.reset().awaiting_host.beginCall(
                state.interpreter_allocator,
                callee,
                allocateFunctionArguments(&invoke.args, scratch),
                fuel,
            ) catch |e| switch (e) {
                error.OutOfMemory => @panic("oom"),
                error.ValueTypeOrCountMismatch => {
                    const signature = callee.signature();
                    return if (signature.param_count != invoke.args.len) failFmt(
                        output,
                        "(export \"{s}\" {f}) from {f} expected {} arguments, got {}",
                        .{
                            command.field,
                            fmt_module,
                            callee,
                            signature.param_count,
                            invoke.args.len,
                        },
                    ) else failFmt(
                        output,
                        "argument type mismatch calling (export \"{s}\" {f}) from {f}",
                        .{ command.field, fmt_module, callee },
                    );
                },
                error.ValidationNeeded => unreachable,
            };
            _ = scratch.reset(.retain_capacity);

            return .{ .invoke = invoke_state };
        },
        .get => {
            const global: wasmstint.runtime.GlobalAddr = switch (target_export) {
                .global => |g| g,
                else => return failFmt(
                    output,
                    "expected global export \"{s}\" from {f}, got {f}",
                    .{ command.field, fmt_module, target_export },
                ),
            };

            const value: Interpreter.TaggedValue = switch (global.global_type.val_type) {
                .i32 => .{
                    .i32 = @as(*const i32, @ptrCast(@alignCast(global.value))).*,
                },
                .f32 => .{
                    .f32 = @as(*const f32, @ptrCast(@alignCast(global.value))).*,
                },
                .i64 => .{
                    .i64 = @as(*const i64, @ptrCast(@alignCast(global.value))).*,
                },
                .f64 => .{
                    .f64 = @as(*const f64, @ptrCast(@alignCast(global.value))).*,
                },
                .externref => .{
                    .externref = @as(
                        *const wasmstint.runtime.ExternAddr,
                        @ptrCast(@alignCast(global.value)),
                    ).*,
                },
                .funcref => .{
                    .funcref = @as(
                        *const wasmstint.runtime.FuncAddr.Nullable,
                        @ptrCast(@alignCast(global.value)),
                    ).*,
                },
                .v128 => unreachable,
            };

            return .{ .get = value };
        },
    }
}

fn failInterpreterResults(
    interp: Interpreter.State.AwaitingHost,
    expected: []const u8,
    scratch: *ArenaAllocator,
    output: Output,
) Error {
    const results = interp.allocResults(scratch.allocator()) catch @panic("oom");

    return if (results.len > 0)
        failFmt(
            output,
            "call unexpectedly returned {f}, expected {s}",
            .{ Interpreter.TaggedValue.sliceFormatter(results), expected },
        )
    else
        failFmt(output, "call unexpectedly succeeded, expected {s}", .{expected});
}

/// Recreates a spec test interpreter trap message
const TrapMessage = union(enum) {
    string: [:0]const u8,
    indirect_call_to_null: *const Interpreter.Trap.IndirectCallToNull,
    memory_access_out_of_bounds: *const Interpreter.Trap.MemoryAccessOutOfBounds,
    table_access_out_of_bounds: *const Interpreter.Trap.TableAccessOutOfBounds,

    fn init(trap: *const Interpreter.Trap) TrapMessage {
        return switch (trap.code) {
            .unreachable_code_reached => .{ .string = "unreachable executed" },
            .integer_division_by_zero => .{ .string = "integer divide by zero" },
            .integer_overflow => .{ .string = "integer overflow" },
            .invalid_conversion_to_integer => .{ .string = "invalid conversion to integer" },
            .memory_access_out_of_bounds => .{
                .memory_access_out_of_bounds = &trap.information.memory_access_out_of_bounds,
            },
            .table_access_out_of_bounds => .{
                .table_access_out_of_bounds = &trap.information.table_access_out_of_bounds,
            },
            .indirect_call_to_null => .{
                .indirect_call_to_null = &trap.information.indirect_call_to_null,
            },
            // .indirect_call_signature_mismatch
            else => |bad| std.debug.panic("TODO: trap message recreation for {t}", .{bad}),
        };
    }

    pub fn format(message: TrapMessage, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        switch (message) {
            .string => |s| try writer.writeAll(s),
            .memory_access_out_of_bounds => |oob| {
                try writer.writeAll("out of bounds memory access: ");
                switch (oob.cause) {
                    .access => {
                        const access = oob.info.access;
                        try writer.print(
                            "access at {}+{} >= max value {}",
                            .{ access.address, access.size.toByteUnits(), access.maximum },
                        );
                    },
                    inline else => |tag| try writer.print("{t} out of bounds", .{tag}),
                }
            },
            .table_access_out_of_bounds => |oob| {
                try writer.writeAll("out of bounds table access: ");
                switch (oob.cause) {
                    inline .@"table.get", .@"table.set" => |*access, tag| {
                        try writer.print(
                            "{t} at {} >= max value {}",
                            .{ tag, access.index, access.maximum },
                        );
                    },
                    inline .call_indirect => |_, tag| try writer.print(
                        "{t} undefined element",
                        .{tag},
                    ),
                    inline else => |_, tag| try writer.print("{t} out of bounds", .{tag}),
                }
            },
            .indirect_call_to_null => |call_info| {
                try writer.print("uninitialized element {}", .{call_info.index});
            },
        }
    }

    fn toString(message: TrapMessage, allocator: std.mem.Allocator) error{OutOfMemory}![]const u8 {
        return switch (message) {
            .string => |s| s,
            else => std.fmt.allocPrint(allocator, "{f}", .{message}),
        };
    }
};

fn expectTrap(
    state: *State,
    interp: Interpreter.State,
    store_arena: *ArenaAllocator,
    fuel: *Interpreter.Fuel,
    expected: []const u8,
    scratch: *ArenaAllocator,
    output: Output,
) Error![]const u8 {
    const result_state = state.runToCompletion(interp, fuel, output, store_arena);
    const trap: *const Interpreter.Trap = switch (result_state) {
        .awaiting_validation => unreachable,
        .trapped => |trapped| &trapped.trap,
        .call_stack_exhaustion => return state.failCallStackExhausted(output),
        .interrupted => |interrupt| return failInterpreterInterrupted(interrupt.cause, output),
        .awaiting_host => |awaiting| return failInterpreterResults(
            awaiting,
            expected,
            scratch,
            output,
        ),
    };

    const actual: []const u8 = TrapMessage.init(trap).toString(scratch.allocator()) catch
        @panic("oom");

    if (std.mem.indexOf(u8, actual, expected) == null) {
        return failFmt(
            output,
            "incorrect trap message\nexpected: \"{s}\"\n  actual: \"{s}\"",
            .{ expected, actual },
        );
    }

    return actual;
}

fn processAssertReturn(
    state: *State,
    command: *const Parser.Command.AssertReturn,
    output: Output,
    scratch: *ArenaAllocator,
) Error!void {
    var fuel = state.starting_fuel;
    const action = try state.processActionCommand(&command.action, output, &fuel, scratch);
    switch (action) {
        .invoke => |interp| {
            const results = try state.expectResultValues(
                interp,
                &fuel,
                &command.expected,
                output,
                scratch,
            );

            if (results.len > 0) {
                output.print(
                    "invoke \"{s}\" returned {f}\n",
                    .{
                        command.action.field,
                        Interpreter.TaggedValue.sliceFormatter(results),
                    },
                );
            }
        },
        .get => |actual_value| {
            if (command.expected.len != 1) {
                return failFmt(
                    output,
                    "'get' yields one value, but {} were expected",
                    .{command.expected.len},
                );
            }

            try resultValueMatches(&actual_value, command.expected.at(0), 0, output);

            output.print(
                "get \"{s}\" yielded {f}\n",
                .{ command.action.field, actual_value },
            );
        },
    }
}

fn processAssertTrap(
    state: *State,
    command: *const Parser.Command.AssertWithMessage,
    output: Output,
    scratch: *ArenaAllocator,
) Error!void {
    var fuel = state.starting_fuel;
    const finished_action = try state.processActionCommand(
        &command.action,
        output,
        &fuel,
        scratch,
    );

    if (finished_action != .invoke) {
        return failFmt(output, "cannot check '{t}' for traps", .{finished_action});
    }

    const message = try state.expectTrap(
        finished_action.invoke,
        &state.module_arena,
        &fuel,
        command.text,
        scratch,
        output,
    );
    output.print("invoke \"{s}\" trapped: \"{s}\"\n", .{ command.action.field, message });
}

fn processAssertExhaustion(
    state: *State,
    command: *const Parser.Command.AssertWithMessage,
    output: Output,
    scratch: *ArenaAllocator,
) Error!void {
    var fuel = state.starting_fuel;
    const finished_action = try state.processActionCommand(
        &command.action,
        output,
        &fuel,
        scratch,
    );

    if (finished_action != .invoke) {
        return failFmt(output, "cannot check '{t}' for resource exhaustion", .{finished_action});
    }

    switch (state.runToCompletion(finished_action.invoke, &fuel, output, &state.module_arena)) {
        .awaiting_validation => unreachable,
        .call_stack_exhaustion => {},
        .trapped => |trap| return failInterpreterTrap(&trap.trap, output),
        .interrupted => |interrupt| if (interrupt.cause != .out_of_fuel) {
            return failInterpreterInterrupted(interrupt.cause, output);
        },
        .awaiting_host => |awaiting| return failInterpreterResults(
            awaiting,
            "call stack exhaustion",
            scratch,
            output,
        ),
    }

    const expected_msg = "call stack exhausted";
    if (!std.mem.eql(u8, command.text, expected_msg)) {
        return failFmt(
            output,
            "expected error message \"{s}\", got \"" ++ expected_msg ++ "\"",
            .{command.text},
        );
    }

    output.print("invoke \"{s}\" exhausted call stack\n", .{command.action.field});
}

fn openAssertionModuleContents(
    state: *State,
    command: *const Parser.Command.AssertWithModule,
    output: Output,
) Error!?wasmstint.FileContent {
    return switch (command.module_type) {
        .binary => try state.openModuleContents(command.filename, output),
        .text => null,
    };
}

fn processAssertInvalid(
    state: *State,
    command: *const Parser.Command.AssertWithModule,
    output: Output,
    arena: *ArenaAllocator,
) Error!void {
    const fmt_filename = std.unicode.fmtUtf8(command.filename);
    const module_binary = (try state.openAssertionModuleContents(command, output)) orelse {
        output.print("skipping text module \"{f}\"\n", .{fmt_filename});
        return;
    };

    var scratch = std.heap.ArenaAllocator.init(arena.allocator());
    var wasm: []const u8 = module_binary.contents;
    var parse_diagnostics = std.Io.Writer.Allocating.initCapacity(arena.allocator(), 128) catch
        @panic("oom");
    validation_failed: {
        var parsed_module = wasmstint.Module.parse(
            arena.allocator(),
            &wasm,
            &scratch,
            .{
                .random_seed = state.rng.random().int(u64),
                .diagnostics = .init(&parse_diagnostics.writer),
            },
        ) catch |e| switch (e) {
            error.OutOfMemory => @panic("oom"),
            error.InvalidWasm => break :validation_failed,
            error.MalformedWasm => return failFmt(
                output,
                "expected validation error \"{s}\" for module \"{f}\", got syntax error: {s}",
                .{ command.text, fmt_filename, parse_diagnostics.written() },
            ),
            else => return failFmt(output, "failed to parse module {f}: {t}", .{ fmt_filename, e }),
        };

        _ = scratch.reset(.retain_capacity);

        // Validation error is in the code
        parse_diagnostics.clearRetainingCapacity();
        const validation_finished = parsed_module.finishCodeValidation(
            state.module_arena.allocator(),
            &scratch,
            .init(&parse_diagnostics.writer),
        ) catch |e| switch (e) {
            error.OutOfMemory => @panic("oom"),
            error.InvalidWasm => break :validation_failed,
            error.MalformedWasm => return failFmt(
                output,
                "expected code validation error \"{s}\" for module \"{f}\", got syntax error: {s}",
                .{ command.text, fmt_filename, parse_diagnostics.written() },
            ),
            else => return failFmt(
                output,
                "failed to parse module code {f}: {t}",
                .{ fmt_filename, e },
            ),
        };

        std.debug.assert(validation_finished);

        return failFmt(
            output,
            "module \"{f}\" unexpectedly passed validation, expected \"{s}\"",
            .{ fmt_filename, command.text },
        );
    }

    if (std.mem.indexOf(u8, parse_diagnostics.written(), command.text) == null) {
        return failFmt(
            output,
            "validation message mismatch for module \"{f}\"\nexpected: {s}\nactual: {s}",
            .{ fmt_filename, command.text, parse_diagnostics.written() },
        );
    }

    output.print("validation failed: {s}\n", .{parse_diagnostics.written()});
}

fn processAssertMalformed(
    state: *State,
    command: *const Parser.Command.AssertWithModule,
    output: Output,
    arena: *ArenaAllocator,
) Error!void {
    const fmt_filename = std.unicode.fmtUtf8(command.filename);
    const module_binary = (try state.openAssertionModuleContents(command, output)) orelse {
        output.print("skipping text module \"{f}\"\n", .{fmt_filename});
        return;
    };

    var scratch = std.heap.ArenaAllocator.init(arena.allocator());
    var wasm: []const u8 = module_binary.contents;
    var parse_diagnostics = std.Io.Writer.Allocating.initCapacity(arena.allocator(), 128) catch
        @panic("oom");
    parse_failed: {
        var parsed_module = wasmstint.Module.parse(
            arena.allocator(),
            &wasm,
            &scratch,
            .{
                .random_seed = state.rng.random().int(u64),
                .diagnostics = .init(&parse_diagnostics.writer),
            },
        ) catch |e| switch (e) {
            error.OutOfMemory => @panic("oom"),
            error.MalformedWasm => break :parse_failed,
            error.InvalidWasm => return failFmt(
                output,
                "expected parse error \"{s}\" for module \"{f}\", but got validation error: {s}",
                .{ command.text, fmt_filename, parse_diagnostics.written() },
            ),
            else => return failFmt(
                output,
                "failed to parse module {f}: {t}",
                .{ fmt_filename, e },
            ),
        };

        _ = scratch.reset(.retain_capacity);

        // Parse error is in the code
        parse_diagnostics.clearRetainingCapacity();
        const validation_finished = parsed_module.finishCodeValidation(
            state.module_arena.allocator(),
            &scratch,
            .init(&parse_diagnostics.writer),
        ) catch |e| switch (e) {
            error.OutOfMemory => @panic("oom"),
            error.MalformedWasm => break :parse_failed,
            error.InvalidWasm => return failFmt(
                output,
                "expected code parse error \"{s}\" for module \"{f}\", but got validation error: {s}",
                .{ command.text, fmt_filename, parse_diagnostics.written() },
            ),
            else => return failFmt(
                output,
                "failed to parse module code {f}: {t}",
                .{ fmt_filename, e },
            ),
        };

        std.debug.assert(validation_finished);

        return failFmt(
            output,
            "module \"{f}\" unexpectedly parsed successfully, expected \"{s}\"",
            .{ fmt_filename, command.text },
        );
    }

    if (std.mem.indexOf(u8, parse_diagnostics.written(), command.text) == null) {
        return failFmt(
            output,
            "parse error message mismatch for module \"{f}\"\nexpected: {s}\nactual: {s}",
            .{ fmt_filename, command.text, parse_diagnostics.written() },
        );
    }

    output.print("parse failed: {s}\n", .{parse_diagnostics.written()});
}

fn processAssertUninstantiable(
    state: *State,
    command: *const Parser.Command.AssertWithModule,
    output: Output,
    arena: *ArenaAllocator,
) Error!void {
    const fmt_filename = std.unicode.fmtUtf8(command.filename);
    const module_binary = (try state.openAssertionModuleContents(command, output)) orelse {
        output.print("skipping text module \"{f}\"\n", .{fmt_filename});
        return;
    };

    var scratch = std.heap.ArenaAllocator.init(arena.allocator());
    var wasm: []const u8 = module_binary.contents;
    var parse_diagnostics = std.Io.Writer.Allocating.initCapacity(arena.allocator(), 128) catch
        @panic("oom");
    const module = wasmstint.Module.parse(
        arena.allocator(),
        &wasm,
        &scratch,
        .{
            .random_seed = state.rng.random().int(u64),
            .diagnostics = .init(&parse_diagnostics.writer),
        },
    ) catch |e| return switch (e) {
        error.OutOfMemory => @panic("oom"),
        error.InvalidWasm, error.MalformedWasm => failFmt(
            output,
            "failed to validate module {f}: {s}",
            .{ fmt_filename, parse_diagnostics.written() },
        ),
        else => return failFmt(
            output,
            "failed to parse module {f}: {t}",
            .{ fmt_filename, e },
        ),
    };
    _ = scratch.reset(.retain_capacity);

    parse_diagnostics.clearRetainingCapacity();
    const validation_finished = module.finishCodeValidation(
        arena.allocator(),
        &scratch,
        .init(&parse_diagnostics.writer),
    ) catch |e| switch (e) {
        error.OutOfMemory => @panic("oom"),
        error.InvalidWasm, error.MalformedWasm => return failFmt(
            output,
            "failed to validate module code {f}: {s}",
            .{ fmt_filename, parse_diagnostics.written() },
        ),
        else => return failFmt(
            output,
            "failed to parse module code {f}: {t}",
            .{ fmt_filename, e },
        ),
    };
    _ = scratch.reset(.retain_capacity);

    std.debug.assert(validation_finished);

    var import_error: wasmstint.runtime.ImportProvider.FailedRequest = undefined;
    var module_allocating = wasmstint.runtime.ModuleAllocating.begin(
        module,
        state.imports.provider(),
        arena.allocator(),
        &import_error,
    ) catch |e| switch (e) {
        error.OutOfMemory => @panic("oom"),
        error.ImportFailure => return failFmt(output, "{f}", .{import_error}),
    };

    // Dangling allocations (pages for WASM memory)
    var module_alloc = try finishModuleAllocation(
        state.max_memory_size,
        &module_allocating,
        arena,
    );

    var fuel = state.starting_fuel;
    const instantiating = state.interpreter.reset().awaiting_host.instantiateModule(
        state.module_arena.allocator(),
        &module_alloc,
        &fuel,
    ) catch @panic("oom");

    const message = try state.expectTrap(
        instantiating,
        arena,
        &fuel,
        command.text,
        &scratch,
        output,
    );
    output.print("module instantiation \"{f}\" trapped: \"{s}\"\n", .{ fmt_filename, message });
}

fn processAssertUnlinkable(
    state: *State,
    command: *const Parser.Command.AssertWithModule,
    output: Output,
    arena: *ArenaAllocator,
) Error!void {
    const fmt_filename = std.unicode.fmtUtf8(command.filename);
    const module_binary = (try state.openAssertionModuleContents(command, output)) orelse {
        output.print("skipping text module \"{f}\"\n", .{fmt_filename});
        return;
    };

    var scratch = std.heap.ArenaAllocator.init(arena.allocator());
    var wasm: []const u8 = module_binary.contents;
    var parse_diagnostics = std.Io.Writer.Allocating.initCapacity(arena.allocator(), 128) catch
        @panic("oom");
    var module = wasmstint.Module.parse(
        arena.allocator(),
        &wasm,
        &scratch,
        .{
            .random_seed = state.rng.random().int(u64),
            .diagnostics = .init(&parse_diagnostics.writer),
        },
    ) catch |e| return switch (e) {
        error.OutOfMemory => @panic("oom"),
        error.InvalidWasm, error.MalformedWasm => failFmt(
            output,
            "failed to validate module {f}: {s}",
            .{ fmt_filename, parse_diagnostics.written() },
        ),
        else => return failFmt(
            output,
            "failed to parse module {f}: {t}",
            .{ fmt_filename, e },
        ),
    };
    _ = scratch.reset(.retain_capacity);

    parse_diagnostics.clearRetainingCapacity();
    const validation_finished = module.finishCodeValidation(
        arena.allocator(),
        &scratch,
        .init(&parse_diagnostics.writer),
    ) catch |e| switch (e) {
        error.OutOfMemory => @panic("oom"),
        error.InvalidWasm, error.MalformedWasm => return failFmt(
            output,
            "failed to validate module code {f}: {s}",
            .{ fmt_filename, parse_diagnostics.written() },
        ),
        else => return failFmt(
            output,
            "failed to parse module code {f}: {t}",
            .{ fmt_filename, e },
        ),
    };

    std.debug.assert(validation_finished);

    var import_error: wasmstint.runtime.ImportProvider.FailedRequest = undefined;
    _ = wasmstint.runtime.ModuleAllocating.begin(
        module,
        state.imports.provider(),
        arena.allocator(),
        &import_error,
    ) catch |e| switch (e) {
        error.OutOfMemory => @panic("oom"),
        error.ImportFailure => {
            const expected_message = switch (import_error.reason) {
                .none_provided => "unknown import",
                .type_mismatch, .wrong_desc => "incompatible import type",
            };

            if (std.mem.eql(u8, expected_message, command.text)) {
                output.print("module linking failed: {f}\n", .{import_error});
                return;
            } else return failFmt(
                output,
                "could not match expected error \"{s}\" with \"{f}\"",
                .{ command.text, import_error },
            );
        },
    };

    return failFmt(output, "expected linker error for module \"{f}\"", .{fmt_filename});
}

const std = @import("std");
const builtin = @import("builtin");
const ArenaAllocator = std.heap.ArenaAllocator;
const wasmstint = @import("wasmstint");
const ModuleInst = wasmstint.runtime.ModuleInst;
const Interpreter = wasmstint.Interpreter;
const Parser = @import("Parser.zig");
const Imports = @import("Imports.zig");
