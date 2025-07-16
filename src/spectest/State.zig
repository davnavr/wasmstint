const State = @This();

const NamedModule = struct {
    line: usize,
    instance: ModuleInst,
};

/// Allocated in the `run_arena`.
module_arena: ArenaAllocator,
/// Allocated in `std.heap.page_allocator`.
module_lookup: std.StringHashMapUnmanaged(NamedModule),
current_module: ?ModuleInst,
interpreter_allocator: std.mem.Allocator,
interpreter: Interpreter,
starting_fuel: Interpreter.Fuel,

store: wasmstint.runtime.ModuleAllocator,
imports: *Imports,
script_dir: std.fs.Dir,
rng: *std.Random.Xoshiro256,

const Error = error{ScriptError};

pub fn init(
    state: *State,
    interpreter_allocator: std.mem.Allocator,
    starting_fuel: Interpreter.Fuel,
    store: wasmstint.runtime.ModuleAllocator,
    imports: *Imports,
    script_dir: std.fs.Dir,
    rng: *std.Random.Xoshiro256,
) void {
    state.* = .{
        .module_arena = ArenaAllocator.init(std.heap.page_allocator),
        .module_lookup = .empty,
        .current_module = null,
        .interpreter_allocator = interpreter_allocator,
        .interpreter = wasmstint.Interpreter.init(interpreter_allocator, .{}) catch
            @panic("oom"),
        .starting_fuel = starting_fuel,
        .store = store,
        .imports = imports,
        .script_dir = script_dir,
        .rng = rng,
    };
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
        .assert_return => |*assert_return| try state.processAssertReturn(
            assert_return,
            output,
            scratch,
        ),
        inline else => |_, bad_tag| return failFmt(output, "TODO: handle command '{t}'", .{bad_tag}),
    }
}

fn processModuleCommand(
    state: *State,
    command: *const Parser.Command,
    output: Output,
    scratch: *ArenaAllocator,
) Error!void {
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

    const fmt_filename = std.unicode.fmtUtf8(module.filename);
    const module_binary = wasmstint.FileContent.readFileZ(
        state.script_dir,
        module.filename,
    ) catch |e| switch (e) {
        error.OutOfMemory => @panic("oom"),
        else => |io_err| return failFmt(
            output,
            "I/O error while reading file \"{f}\": {t}",
            .{ fmt_filename, io_err },
        ),
    };
    // errdefer module_binary.deinit();

    var parsed_module = state.module_arena.allocator().create(wasmstint.Module) catch
        @panic("oom");
    {
        var wasm: []const u8 = module_binary.contents;
        parsed_module.* = wasmstint.Module.parse(
            state.module_arena.allocator(),
            &wasm,
            scratch,
            state.rng.random(),
            .{ .realloc_contents = true },
        ) catch |e| return switch (e) {
            error.OutOfMemory => @panic("oom"),
            error.InvalidWasm => failFmt(output, "failed to validate module {f}", .{fmt_filename}),
            else => failFmt(output, "module parse error: {t}", .{e}),
        };
    }
    _ = scratch.reset(.retain_capacity);

    // `assert_invalid` commands mean lazy validation won't work
    const validation_finished = parsed_module.finishCodeValidation(
        state.module_arena.allocator(),
        scratch,
    ) catch |e| switch (e) {
        error.OutOfMemory => @panic("oom"),
        else => return failFmt(output, "module code validation error: {t}", .{e}),
    };

    _ = scratch.reset(.retain_capacity);

    std.debug.assert(validation_finished);

    var import_error: wasmstint.runtime.ImportProvider.FailedRequest = undefined;
    var module_alloc = wasmstint.runtime.ModuleAlloc.allocate(
        parsed_module,
        state.imports.provider(),
        state.module_arena.allocator(),
        state.store,
        &import_error,
    ) catch |e| switch (e) {
        error.OutOfMemory => @panic("oom"),
        error.ImportFailure => return failFmt(output, "{f}", .{import_error}),
    };

    var fuel = state.starting_fuel;
    state.interpreter.reset();
    _ = state.interpreter.state.awaiting_host.instantiateModule(
        state.module_arena.allocator(),
        &module_alloc,
        &fuel,
    ) catch @panic("oom");

    _ = try state.expectResultValues(&fuel, &Parser.Command.Expected.Vec{}, output, scratch);

    const module_inst = module_alloc.expectInstantiated();
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

fn failCallStackExhausted(state: *const State, output: Output) Error {
    return failFmt(
        output,
        "call stack exhausted after {} frames",
        .{state.interpreter.call_stack.items.len},
    );
}

fn failInterpreterTrap(
    trap_code: Interpreter.Trap.Code,
    output: Output,
) Error {
    return failFmt(output, "unexpected trap {t}", .{trap_code});
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

fn checkResultIntegerMatches(
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
            ", but got 0x{[actual_u]X:0>[width]} " ++
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

fn checkResultValueMatches(
    actual: *const Interpreter.TaggedValue,
    expected: *const Parser.Command.Expected,
    index: usize,
    output: Output,
) Error!void {
    switch (expected.*) {
        .i32 => |expected_i| try checkResultIntegerMatches(
            expected_i,
            try expectTypedValue(actual, .i32, index, output),
            index,
            output,
        ),
        .i64 => |expected_i| try checkResultIntegerMatches(
            expected_i,
            try expectTypedValue(actual, .i64, index, output),
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
        else => return failFmt(output, "TODO: check {t}", .{expected.*}),
    }
}

fn expectResultValues(
    state: *State,
    fuel: *Interpreter.Fuel,
    expected: *const Parser.Command.Expected.Vec,
    output: Output,
    scratch: *ArenaAllocator,
) Error![]const Interpreter.TaggedValue {
    state.runToCompletion(fuel, output);
    switch (state.interpreter.state) {
        .awaiting_validation => unreachable,
        .call_stack_exhaustion => return state.failCallStackExhausted(output),
        .trapped => |trap| return failInterpreterTrap(trap.code, output),
        .interrupted => |interrupt| return failInterpreterInterrupted(interrupt.cause, output),
        .awaiting_host => std.debug.assert(state.interpreter.call_stack.items.len == 0),
    }

    const actual_results: []const Interpreter.TaggedValue = state.interpreter.state
        .awaiting_host.copyValues(scratch) catch @panic("oom");

    if (expected.len != actual_results.len) return failFmt(
        output,
        "expected {} results, but got {}",
        .{ expected.len, actual_results.len },
    );

    for (0.., actual_results) |i, *actual_val| {
        const expected_val: *const Parser.Command.Expected = expected.at(i);
        try checkResultValueMatches(actual_val, expected_val, i, output);
    }

    return actual_results;
}

fn runToCompletion(state: *State, fuel: *Interpreter.Fuel, output: Output) void {
    for (0..1234) |_| {
        switch (state.interpreter.state) {
            .awaiting_host => |*host| if (state.interpreter.call_stack.items.len == 0) {
                return;
            } else {
                const callee = host.currentHostFunction().?;
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
                        host.valuesTyped(struct { i32 }) catch unreachable,
                    ),
                    .print_i64 => output.print(
                        "{}",
                        host.valuesTyped(struct { i64 }) catch unreachable,
                    ),
                    .print_f32 => output.print(
                        "{}",
                        host.valuesTyped(struct { f32 }) catch unreachable,
                    ),
                    .print_f64 => output.print(
                        "{}",
                        host.valuesTyped(struct { f64 }) catch unreachable,
                    ),
                    .print_i32_f32 => output.print(
                        "{}, {}",
                        host.valuesTyped(struct { i32, f32 }) catch unreachable,
                    ),
                    .print_f64_f64 => output.print(
                        "{}, {}",
                        host.valuesTyped(struct { f64, f64 }) catch unreachable,
                    ),
                }
                output.writeAll(")\n");

                _ = host.returnFromHostTyped({}, fuel) catch unreachable;
            },
            .awaiting_validation => unreachable,
            .call_stack_exhaustion => |*oof| {
                _ = oof.resumeExecution(state.interpreter_allocator, fuel) catch
                    return;
            },
            .interrupted => |*interrupt| {
                switch (interrupt.cause) {
                    .out_of_fuel => return,
                    .memory_grow => |grow| {
                        _ = grow; // TODO: Should ModuleAllocator API handle resizing?
                        // const new_cap = @min(
                        //     @max(
                        //         grow.delta + grow.memory.size,
                        //         grow.memory.capacity *| 2,
                        //     ),
                        //     grow.memory.limit,
                        // );

                        // const remapped = state.store.arena.allocator().remap(
                        //     grow.memory.base[0..grow.memory.capacity],
                        //     new_cap,
                        // );

                        // if (remapped) |new_buf| {
                        //     _ = grow.resize(new_buf);
                        // } else resize_failed: {
                        //     _ = grow.resize(
                        //         state.store.arena.allocator().alignedAlloc(
                        //             u8,
                        //             wasmstint.runtime.MemInst.buffer_align,
                        //             new_cap,
                        //         ) catch break :resize_failed,
                        //     );
                        // }
                    },
                    .table_grow => |grow| {
                        _ = grow; // TODO: Should ModuleAllocator API handle resizing?
                        // const table = grow.table.table;
                        // const new_cap = @min(
                        //     @max(grow.delta + table.len, table.capacity *| 2),
                        //     table.limit,
                        // ) * table.stride.toBytes();

                        // const remapped = state.store.arena.allocator().remap(
                        //     table.base.ptr[0 .. table.capacity * table.stride.toBytes()],
                        //     new_cap,
                        // );

                        // if (remapped) |new_buf| {
                        //     _ = grow.resize(new_buf);
                        // } else resize_failed: {
                        //     _ = grow.resize(
                        //         state.store.arena.allocator().alignedAlloc(
                        //             u8,
                        //             wasmstint.runtime.TableInst.buffer_align,
                        //             new_cap,
                        //         ) catch break :resize_failed,
                        //     );
                        // }
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

const Action = union(enum) {
    invoke,
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

            _ = state.interpreter.state.awaiting_host.beginCall(
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
            };
            _ = scratch.reset(.retain_capacity);

            return .invoke;
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

fn processAssertReturn(
    state: *State,
    command: *const Parser.Command.AssertReturn,
    output: Output,
    scratch: *ArenaAllocator,
) Error!void {
    var fuel = state.starting_fuel;
    const action = try state.processActionCommand(&command.action, output, &fuel, scratch);
    switch (action) {
        .invoke => {
            const results = try state.expectResultValues(
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
                        std.fmt.Alt(
                            []const Interpreter.TaggedValue,
                            Interpreter.TaggedValue.formatSlice,
                        ){ .data = results },
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

            try checkResultValueMatches(&actual_value, command.expected.at(0), 0, output);

            output.print(
                "get \"{s}\" yielded {f}\n",
                .{ command.action.field, actual_value },
            );
        },
    }
}

const std = @import("std");
const builtin = @import("builtin");
const ArenaAllocator = std.heap.ArenaAllocator;
const wasmstint = @import("wasmstint");
const ModuleInst = wasmstint.runtime.ModuleInst;
const Interpreter = wasmstint.Interpreter;
const Parser = @import("Parser.zig");
const Imports = @import("Imports.zig");
