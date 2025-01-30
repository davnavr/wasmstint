//! Represents a single thread of WebAssembly computation.
//!
//! Based on <https://doi.org/10.48550/arXiv.2205.01183>.

const std = @import("std");
const Allocator = std.mem.Allocator;
const runtime = @import("runtime.zig");
const Module = @import("Module.zig");
const opcodes = @import("opcodes.zig");

const FuncRef = runtime.FuncAddr.Nullable;

const Value = extern union {
    i32: i32,
    f32: f32,
    i64: i64,
    f64: f64,
    externref: runtime.ExternAddr,
    funcref: FuncRef,
};

pub const TaggedValue = union(enum) {
    i32: i32,
    f32: f32,
    i64: i64,
    f64: f64,
    externref: runtime.ExternAddr,
    funcref: *const FuncRef,

    comptime {
        std.debug.assert(@sizeOf(TaggedValue) == 16);
    }
};

const ValueTag = std.meta.Tag(TaggedValue);

const Ip = Module.Code.Ip;
const Eip = *const Module.Code.End;
const Stp = [*]const Module.Code.SideTableEntry;

pub const StackFrame = extern struct {
    function: runtime.FuncAddr,
    instructions: Instructions,
    branch_table: Stp,
    /// The total space taken by parameters, local variables, and values in the interpreter's
    /// `value_stack`.
    values_count: u16,
    /// The number of return values this function has.
    result_count: u16,
    /// The index into the `value_stack` at which local variables begin.
    ///
    /// The length of the value stack to restore when returning from this function is equal to .
    values_base: u32,
};

const ValStack = std.ArrayListUnmanaged(Value);

value_stack: ValStack,
call_stack: std.ArrayListUnmanaged(StackFrame),
state: State = .{ .awaiting_host = &[0]Module.ValType{} },

const Interpreter = @This();

pub const Fuel = extern struct {
    remaining: u64,
};

pub const InitOptions = struct {
    /// The initial size, in bytes, of the value stack.
    value_stack_capacity: u32 = @sizeOf(Value) * 512,
    /// The initial capacity, in numbers of stack frames, of the call stack.
    call_stack_capacity: u32 = 64,
};

pub fn init(alloca: Allocator, options: InitOptions) Allocator.Error!Interpreter {
    return .{
        .value_stack = try std.ArrayListUnmanaged(Value).initCapacity(
            alloca,
            options.value_stack_capacity / @sizeOf(Value),
        ),
        .call_stack = try std.ArrayListUnmanaged(StackFrame).initCapacity(
            alloca,
            options.call_stack_capacity,
        ),
    };
}

/// Describes the kind of trap that occurred.
///
/// Hosts can specify their own codes in the negative range.
pub const TrapCode = enum(i32) {
    unreachable_code_reached = 0,
    /// The function did not contain valid WebAssembly.
    ///
    /// See <https://webassembly.github.io/spec/core/appendix/implementation.html#validation> for more
    /// information.
    lazy_validation_failed,
    integer_division_by_zero,
    _,

    pub fn initHost(code: u31) TrapCode {
        return @enumFromInt(-@as(i31, code) - 1);
    }

    pub fn host(code: TrapCode) ?u31 {
        return if (code < 0) @intCast(-(@intFromEnum(code) + 1)) else null;
    }
};

pub const InterruptionCause = union(enum) {
    /// Indicates that the current function needs to allocate space for their local variables and value stack.
    validation_finished,
    out_of_fuel,
    /// A call instruction required pushing a new stack frame, which required a reallocation of the `call_stack`.
    call_stack_exhaustion,
};

pub const State = union(enum) {
    /// Either WASM code is waiting to be interpreted, or WASM code is awaiting the results of
    /// calling a host function.
    ///
    /// Also indicates the types of the values at the top of the value stack, which are the results of the most
    /// recently called function.
    awaiting_host: []const Module.ValType,
    /// The current function is awaiting the results of lazy validation, with arguments already written to a buffer.
    awaiting_lazy_validation,
    /// Execution of WASM bytecode was interrupted due to one of the following:
    ///
    /// The host can stop using the interpreter further, resume execution with more fuel by calling
    /// `.resumeExecution()`, or reuse the interpreter for a new computation after calling `.reset()`.
    interrupted: InterruptionCause,
    // memory_grow,
    /// The computation was aborted due to a *trap*. The call stack of the interpreter can be
    /// inspected to determine where and when the trap occurred.
    trapped: TrapCode,
    // unhandled_exception: Exception,
};

pub const Error = error{
    InvalidInterpreterState,
} || Allocator.Error;

fn allocateValueStackSpace(interp: *Interpreter, alloca: Allocator, code: *const Module.Code) Allocator.Error!u16 {
    const total = std.math.add(u16, code.state.local_values, code.state.max_values) catch return error.OutOfMemory;
    try interp.value_stack.ensureUnusedCapacity(alloca, total);
    // In WebAssembly, locals are set to zero on entrance to a function.
    interp.value_stack.appendNTimes(undefined, std.mem.zeroes(Value), code.state.local_values) catch unreachable;
    return total;
}

inline fn currentFrame(interp: *Interpreter) *StackFrame {
    return &interp.call_stack.items[interp.call_stack.items.len - 1];
}

/// Resumes execution of WASM bytecode after being `interrupted`.
pub fn resumeExecution(interp: *Interpreter, alloca: Allocator, fuel: *Fuel) Error!void {
    const interruption: InterruptionCause = switch (interp.state) {
        .interrupted => |cause| cause,
        else => return error.InvalidInterpreterState,
    };

    // const saved_value_stack_len = interp.value_stack.items.len;
    // errdefer interp.value_stack.items.len = saved_value_stack_len;

    const current_frame = interp.currentFrame();
    switch (interruption) {
        .validation_finished => {
            // TODO: How to handle too large stack frame? Introduce new stack_exhausted state?
            const code: *const Module.Code = current_frame.function.expanded().wasm.code();

            switch (code.state.flag.load(.acquire)) {
                .init, .validating => unreachable,
                // TODO: Only have a single `.finished` flag.
                .successful, .failed => {},
            }

            if (code.state.@"error") {
                @branchHint(.cold);
                interp.state = .{ .trapped = TrapCode.lazy_validation_failed };
                return;
            }

            try interp.allocateValueStackSpace(alloca, code);
            current_frame.instructions = Instructions.init(code.state.instructions, code.state.instructions_end);
            current_frame.branch_table = code.state.side_table_ptr;
        },
        .out_of_fuel => {},
    }

    errdefer comptime unreachable;

    interp.enterMainLoop(fuel);
}

//pub fn waitForLazyValidation(Timeout)

/// After validation, execution of the function can continue by calling `.resumeExecution()`.
///
/// Returns `true` if validation already succeeded or failed, or `false` if validation is occurring
/// in another thread.
pub fn finishLazyValidation(
    interp: *Interpreter,
    code_allocator: Allocator,
    scratch: *std.heap.ArenaAllocator,
) Error!bool {
    if (interp.state != .awaiting_lazy_validation)
        return error.InvalidInterpreterState;

    const current_function = interp.currentFrame().function.expanded().wasm;
    const module = current_function.module.module;
    const code = current_function.code.code(module).?;
    const validated = code.state.validate(
        code_allocator,
        module,
        module.funcTypeIdx(current_function.code),
        code.contents,
        scratch,
    ) catch |e| {
        @branchHint(.cold);

        // TODO: Should now unused arguments be popped from the stack?

        // Trap occurs even if OOM error is reported, since currently `state.flag` is set to `.failed` if OOM occurs
        // during validation.
        interp.state = .{ .trapped = TrapCode.lazy_validation_failed };

        return switch (e) {
            error.OutOfMemory => |oom| return oom,
            else => true,
        };
    };

    if (validated) {
        if (code.state.@"error") |_| {
            unreachable; // TODO: Same code path as in catch handler that sets .state = .trapped;
        } else {
            interp.state = .{ .interrupted = InterruptionCause.validation_finished };
        }
    }

    return validated;
}

pub fn beginCall(
    interp: *Interpreter,
    alloca: Allocator,
    callee: runtime.FuncAddr,
    arguments: []const TaggedValue,
    fuel: *Fuel,
) (error{ArgumentTypeOrCountMismatch} || Error)!void {
    if (interp.state != .awaiting_host) return Error.InvalidInterpreterState;

    const signature = callee.signature();
    if (arguments.len != signature.param_count) {
        return error.ArgumentTypeOrCountMismatch;
    }

    const saved_call_stack_len = interp.call_stack.items.len;
    try interp.call_stack.ensureUnusedCapacity(alloca, 1);
    errdefer interp.call_stack.items.len = saved_call_stack_len;

    const saved_value_stack_len = interp.value_stack.items.len;
    try interp.value_stack.ensureUnusedCapacity(alloca, signature.param_count);
    errdefer interp.value_stack.items.len = saved_value_stack_len;

    const values_base = std.math.cast(u32, interp.value_stack.items.len) orelse return Error.OutOfMemory;

    for (arguments, signature.parameters()) |arg, param_type| {
        interp.value_stack.appendAssumeCapacity(
            value: switch (@as(std.meta.Tag(TaggedValue), arg)) {
                .funcref => {
                    if (param_type != .funcref)
                        return error.ArgumentTypeOrCountMismatch;

                    break :value Value{ .funcref = arg.funcref.* };
                },
                inline else => |tag| {
                    if (param_type != @field(Module.ValType, @tagName(tag)))
                        return error.ArgumentTypeOrCountMismatch;

                    break :value @unionInit(
                        Value,
                        @tagName(tag),
                        @field(arg, @tagName(tag)),
                    );
                },
            },
        );
    }

    switch (callee.expanded()) {
        .wasm => |wasm| {
            const code: *const Module.Code = wasm.code();

            switch (code.state.flag.load(.acquire)) {
                .init, .validating => {
                    interp.state = .awaiting_lazy_validation;
                    return;
                },
                // TODO: Only have a single `.finished` flag.
                .successful, .failed => {},
            }

            if (code.state.@"error") |_| {
                @branchHint(.cold);
                interp.state = .{ .trapped = TrapCode.lazy_validation_failed };
                return;
            }

            const total_values = try interp.allocateValueStackSpace(alloca, code);

            errdefer comptime unreachable;

            interp.call_stack.append(
                undefined,
                StackFrame{
                    .function = callee,
                    .instructions = Instructions.init(code.state.instructions, code.state.instructions_end),
                    .branch_table = code.state.side_table_ptr,
                    .values_base = values_base,
                    .values_count = total_values,
                    .result_count = signature.result_count,
                },
            ) catch unreachable;

            interp.enterMainLoop(fuel);
        },
        .host => {
            errdefer comptime unreachable;

            interp.call_stack.append(
                undefined,
                StackFrame{
                    .function = callee,
                    .instructions = undefined,
                    .branch_table = undefined,
                    .values_base = values_base,
                    .values_count = signature.param_count,
                    .result_count = signature.result_count,
                },
            ) catch unreachable;
        },
    }
}

const OpcodeHandler = *const fn (
    i: *Instructions,
    s: *Stp,
    loc: u32,
    vals: *ValStack,
    fuel: *Fuel,
    int: *Interpreter,
) void;

const Instructions = extern struct {
    p: Ip,
    /// The "*end* instruction pointer" which denotes an implicit return from the function.
    ep: Eip,

    fn init(ip: Ip, eip: Eip) Instructions {
        return .{ .p = ip, .ep = eip };
    }

    pub fn readByte(i: *Instructions) Module.NoEofError!u8 {
        if (@intFromPtr(i.p) <= @intFromPtr(i.ep)) {
            const b = i.p[0];
            i.p += 1;
            return b;
        } else return error.EndOfStream;
    }

    inline fn readUleb128(reader: *Instructions, comptime T: type) error{ Overflow, EndOfStream }!T {
        return std.leb.readUleb128(T, reader);
    }

    inline fn readIleb128(reader: *Instructions, comptime T: type) error{ Overflow, EndOfStream }!T {
        return std.leb.readIleb128(T, reader);
    }

    inline fn nextOpcodeHandler(reader: *Instructions, fuel: *Fuel, interp: *Interpreter) ?OpcodeHandler {
        if (fuel.remaining == 0) {
            interp.state = .{ .interrupted = .out_of_fuel };
            return null;
        } else {
            fuel.remaining -= 1;
            return byte_dispatch_table[reader.readByte() catch unreachable];
        }
    }
};

/// Moves return values to their appropriate place in the value stack.
///
/// Execution of the handlers for the `end` and `return` instructions ends up here.
fn returnFromWasm(interp: *Interpreter, values_base: u32) void {
    const popped = interp.currentFrame();
    interp.call_stack.items.len -= 1;

    const new_value_stack_len = values_base + popped.result_count;
    std.mem.copyForwards(
        Value,
        interp.value_stack.items[values_base..new_value_stack_len],
        interp.value_stack.items[interp.value_stack.items.len - popped.result_count ..],
    );
    interp.value_stack.items.len = new_value_stack_len;

    return_to_host: {
        if (interp.call_stack.items.len == 0) break :return_to_host;

        const current_frame = interp.currentFrame();
        switch (current_frame.function.expanded()) {
            .wasm => |wasm| {
                _ = wasm;
            },
            .host => break :return_to_host,
        }

        unreachable; // TODO: wasm to wasm calls are not yet implemented (might need to do the tail call stuff again)
        // - could also just return a bool indicating if execution should continue.

        // TODO: Fixup IP, STP, and interp.value_stack.items.len = values_base for new top of call stack.

        // return;
    }

    const signature = popped.function.signature();
    std.debug.assert(signature.result_count == popped.result_count);
    interp.state = .{ .awaiting_host = signature.results() };
}

const opcode_handlers = struct {
    fn panicInvalidInstruction(i: *Instructions, s: *Stp, loc: u32, vals: *ValStack, fuel: *Fuel, int: *Interpreter) void {
        _ = s;
        _ = loc;
        _ = vals;
        _ = fuel;
        _ = int;
        const bad_opcode: u8 = (i.p - 1)[0];
        const opcode_name = name: {
            const tag = std.meta.intToEnum(opcodes.ByteOpcode, bad_opcode) catch break :name "unknown";
            break :name @tagName(tag);
        };

        std.debug.panic("invalid instruction {X:0.2} ({s})", .{ bad_opcode, opcode_name });
    }

    const invalid: OpcodeHandler = switch (@import("builtin").mode) {
        .Debug, .ReleaseSafe => panicInvalidInstruction,
        .ReleaseFast, .ReleaseSmall => undefined,
    };

    fn end(i: *Instructions, s: *Stp, loc: u32, vals: *ValStack, fuel: *Fuel, int: *Interpreter) void {
        if (@intFromPtr(i.p - 1) == @intFromPtr(i.ep)) {
            int.returnFromWasm(loc);
        } else if (i.nextOpcodeHandler(fuel, int)) |next| {
            @call(.always_tail, next, .{ i, s, loc, vals, fuel, int });
        }
    }

    fn @"local.get"(i: *Instructions, s: *Stp, loc: u32, vals: *ValStack, fuel: *Fuel, int: *Interpreter) void {
        const n = i.readUleb128(u32) catch unreachable;
        const value = vals.items[loc..][n];
        vals.appendAssumeCapacity(value);

        if (i.nextOpcodeHandler(fuel, int)) |next| {
            @call(.always_tail, next, .{ i, s, loc, vals, fuel, int });
        }
    }

    fn @"local.set"(i: *Instructions, s: *Stp, loc: u32, vals: *ValStack, fuel: *Fuel, int: *Interpreter) void {
        const n = i.readUleb128(u32) catch unreachable;
        const value = vals.pop();
        vals.items[loc..][n] = value;

        if (i.nextOpcodeHandler(fuel, int)) |next| {
            @call(.always_tail, next, .{ i, s, loc, vals, fuel, int });
        }
    }

    fn @"local.tee"(i: *Instructions, s: *Stp, loc: u32, vals: *ValStack, fuel: *Fuel, int: *Interpreter) void {
        const n = i.readUleb128(u32) catch unreachable;
        vals.items[loc..][n] = vals.items[vals.items.len - 1];

        if (i.nextOpcodeHandler(fuel, int)) |next| {
            @call(.always_tail, next, .{ i, s, loc, vals, fuel, int });
        }
    }

    fn @"i32.const"(i: *Instructions, s: *Stp, loc: u32, vals: *ValStack, fuel: *Fuel, int: *Interpreter) void {
        const n = i.readIleb128(i32) catch unreachable;
        vals.appendAssumeCapacity(.{ .i32 = n });

        if (i.nextOpcodeHandler(fuel, int)) |next| {
            @call(.always_tail, next, .{ i, s, loc, vals, fuel, int });
        }
    }

    fn @"i32.add"(i: *Instructions, s: *Stp, loc: u32, vals: *ValStack, fuel: *Fuel, int: *Interpreter) void {
        const c_2 = vals.pop().i32;
        const c_1 = vals.pop().i32;
        vals.appendAssumeCapacity(.{ .i32 = c_1 +% c_2 });

        if (i.nextOpcodeHandler(fuel, int)) |next| {
            @call(.always_tail, next, .{ i, s, loc, vals, fuel, int });
        }
    }

    fn @"i32.sub"(i: *Instructions, s: *Stp, loc: u32, vals: *ValStack, fuel: *Fuel, int: *Interpreter) void {
        const c_2 = vals.pop().i32;
        const c_1 = vals.pop().i32;
        vals.appendAssumeCapacity(.{ .i32 = c_1 -% c_2 });

        if (i.nextOpcodeHandler(fuel, int)) |next| {
            @call(.always_tail, next, .{ i, s, loc, vals, fuel, int });
        }
    }

    fn @"i32.mul"(i: *Instructions, s: *Stp, loc: u32, vals: *ValStack, fuel: *Fuel, int: *Interpreter) void {
        const c_2 = vals.pop().i32;
        const c_1 = vals.pop().i32;
        vals.appendAssumeCapacity(.{ .i32 = c_1 *% c_2 });

        if (i.nextOpcodeHandler(fuel, int)) |next| {
            @call(.always_tail, next, .{ i, s, loc, vals, fuel, int });
        }
    }

    //std.math.divTrunc
};

const byte_dispatch_table: [256]OpcodeHandler = handlers: {
    var table = [_]OpcodeHandler{opcode_handlers.invalid} ** 256;
    for (@typeInfo(opcodes.ByteOpcode).@"enum".fields) |op| {
        if (@hasDecl(opcode_handlers, op.name)) {
            table[op.value] = @as(OpcodeHandler, @field(opcode_handlers, op.name));
        }
    }

    break :handlers table;
};

fn enterMainLoop(interp: *Interpreter, fuel: *Fuel) void {
    std.debug.assert(interp.state == .awaiting_host);

    if (fuel.remaining == 0) {
        interp.state = .{ .interrupted = .out_of_fuel };
        return;
    }

    var starting_frame = interp.currentFrame();
    std.debug.assert(starting_frame.function.expanded() == .wasm);

    const handler = starting_frame.instructions.nextOpcodeHandler(
        fuel,
        interp,
    ).?;

    _ = handler(
        &starting_frame.instructions,
        &starting_frame.branch_table,
        starting_frame.values_base,
        &interp.value_stack,
        fuel,
        interp,
    );
    starting_frame = undefined;
}

// /// Return from the currently executing host function to the calling function, typically WASM code.
// pub fn returnFromHost(inter: *Interpreter, results: []TaggedValue, fuel: *Fuel)

// TODO: Don't want extra branch in code that handles function return? How to handle module instantiation?
// - custom frame kind, so there is WASM, Host, and Instantiation, when latter is popped, it updates flag
// - add note saying it is not thread safe, host responsible when calling instantiate()

/// Discards the current computation.
pub fn reset(interp: *Interpreter) void {
    interp.value_stack.clearRetainingCapacity();
    interp.call_stack.clearRetainingCapacity();
    interp.state = .{ .awaiting_host = &[0]Module.ValType{} };
}

pub fn deinit(interp: *Interpreter, alloca: Allocator) void {
    interp.value_stack.deinit(alloca);
    interp.call_stack.deinit(alloca);
    interp.* = undefined;
}
