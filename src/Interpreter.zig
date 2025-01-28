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
    host_ref: runtime.ExternAddr,
    func_ref: FuncRef,
};

const Ip = Module.Code.Ip;
const Eip = *const Module.Code.End;
const Stp = [*]const Module.Code.SideTableEntry;

pub const StackFrame = extern struct {
    function: runtime.FuncAddr,
    ip: Ip,
    /// The "*end* instruction pointer".
    eip: Eip,
    stp: Stp,
    /// The total space taken by local variables and values in the interpreter's `value_stack`.
    values_sizes: u32,
    /// The index into the `value_stack` at which local variables begin.
    values_base: u32,
};

const ValStack = std.ArrayListUnmanaged(Value);

value_stack: ValStack,
call_stack: std.ArrayListUnmanaged(StackFrame),
state: State = .awaiting_host,

const Interpreter = @This();

pub const Fuel = extern struct {
    remaining: u64,
};

pub const TaggedValue = union(enum) {
    i32: i32,
    f32: f32,
    i64: i64,
    f64: f64,
    host_ref: runtime.ExternAddr,
    func_ref: *const FuncRef,
};

pub const InitOptions = struct {
    value_stack_capacity: usize = @sizeOf(Value) * 2048,
    call_stack_capacity: usize = 64,
};

pub fn init(alloca: Allocator, options: InitOptions) Allocator.Error!Interpreter {
    return .{
        .value_stack = try std.ArrayListUnmanaged(Value).initCapacity(
            alloca,
            options.value_stack_capacity,
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
    awaiting_host,
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

fn allocateValueStackSpace(interp: *Interpreter, alloca: Allocator, locals: u32, total: u32) Allocator.Error!void {
    std.debug.assert(locals <= total);
    try interp.value_stack.ensureUnusedCapacity(alloca, total);
    interp.value_stack.appendNTimes(undefined, std.mem.zeroes(Value), locals) catch unreachable;
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
            if (code.state.@"error") {
                interp.state = .{ .trapped = TrapCode.lazy_validation_failed };
                return;
            }

            const sizes = code.state.info.sizes;
            try interp.allocateValueStackSpace(alloca, sizes.local_values, sizes.max_values);
            current_frame.ip = code.state.instructions;
            current_frame.eip = code.state.instructions_end;
            current_frame.stp = code.state.side_table_ptr;
        },
        .out_of_fuel => {},
    }

    errdefer comptime unreachable;

    // TODO: Go back into the interpreter.
    // enterMainLoop
    _ = fuel;
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
) Error!void {
    if (interp.state != .awaiting_host) return Error.InvalidInterpreterState;

    const arg_len = std.math.cast(u32, arguments.len) orelse return Error.OutOfMemory;

    const saved_call_stack_len = interp.call_stack.items.len;
    try interp.call_stack.ensureUnusedCapacity(alloca, 1);
    errdefer interp.call_stack.items.len = saved_call_stack_len;

    const saved_value_stack_len = interp.value_stack.items.len;
    try interp.value_stack.ensureUnusedCapacity(alloca, arg_len);
    errdefer interp.value_stack.items.len = saved_value_stack_len;

    for (arguments) |arg| {
        interp.value_stack.appendAssumeCapacity(
            switch (@as(std.meta.Tag(TaggedValue), arg)) {
                .func_ref => Value{ .func_ref = arg.func_ref.* },
                inline else => |tag| @unionInit(
                    Value,
                    @tagName(tag),
                    @field(arg, @tagName(tag)),
                ),
            },
        );
    }

    switch (callee.expanded()) {
        .wasm => |wasm| {
            const code: *const Module.Code = wasm.code();
            if (code.state.@"error") |_| {
                interp.state = .{ .trapped = TrapCode.lazy_validation_failed };
                return;
            }

            const sizes = code.state.info.sizes;
            try interp.allocateValueStackSpace(alloca, sizes.local_values, sizes.max_values);

            interp.call_stack.append(
                undefined,
                StackFrame{
                    .function = callee,
                    .ip = code.state.instructions,
                    .eip = code.state.instructions_end,
                    .stp = code.state.side_table_ptr,
                    .values_base = std.math.cast(u32, interp.value_stack.items.len) orelse
                        return Error.OutOfMemory,
                    .values_sizes = sizes.local_values + sizes.max_values,
                },
            ) catch unreachable;

            errdefer comptime unreachable;

            // enterMainLoop
            _ = fuel;
        },
        .host => {
            const values_base = std.math.cast(u32, interp.value_stack.items.len) orelse return Error.OutOfMemory;

            errdefer comptime unreachable;

            interp.call_stack.append(
                undefined,
                StackFrame{
                    .function = callee,
                    .ip = undefined,
                    .eip = undefined,
                    .stp = undefined,
                    .values_base = values_base,
                    .values_sizes = arg_len,
                },
            ) catch unreachable;

            interp.state = .awaiting_host;
        },
    }
}

const OpcodeResult = packed struct(std.meta.Int(.unsigned, @bitSizeOf([2]*anyopaque))) {
    ip: Ip,
    stp: Stp,
};

const OpcodeHandler = *const fn (
    ip: Ip,
    vals: *ValStack,
    fuel: *Fuel,
    values_base: u32,
    stp: Stp,
    eip: Eip,
    interp: *Interpreter,
) OpcodeResult;

const IpReader = struct {
    ip: Ip,
    eip: Eip,

    fn init(ip: Ip, eip: Eip) IpReader {
        return .{ .ip = ip, .eip = eip };
    }

    pub fn readByte(reader: *IpReader) Module.NoEofError!u8 {
        if (@intFromPtr(reader.ip) <= @intFromPtr(reader.eip)) {
            const b = reader.ip[0];
            reader.ip += 1;
            return b;
        } else return error.EndOfStream;
    }

    inline fn readUleb128(reader: *IpReader, comptime T: type) error{ Overflow, EndOfStream }!T {
        return std.leb.readUleb128(T, reader);
    }

    inline fn readIleb128(reader: *IpReader, comptime T: type) error{ Overflow, EndOfStream }!T {
        return std.leb.readIleb128(T, reader);
    }

    inline fn nextOpcodeHandler(reader: *IpReader, fuel: *Fuel, interp: *Interpreter) ?OpcodeHandler {
        if (fuel.remaining == 0) {
            interp.state = .{ .interrupted = .out_of_fuel };
            const current_frame = interp.currentFrame();
            current_frame.ip = reader.ip;
            current_frame.stp = reader.stp;
            return null;
        } else {
            fuel.remaining -= 1;
            return byte_dispatch_table[reader.readByte() catch unreachable];
        }
    }
};

const opcode_handlers = struct {
    fn unspecifiedPanic(ip: Ip, vals: *ValStack, fuel: *Fuel, values_base: u32, stp: Stp, eip: Eip, interp: *Interpreter) OpcodeResult {
        _ = vals;
        _ = fuel;
        _ = values_base;
        _ = stp;
        _ = eip;
        _ = interp;
        std.debug.panic("unimplemented handler for instruction {X:0.2}", .{(ip - 1)[0]});
    }

    const unspecified: OpcodeHandler = switch (@import("builtin").mode) {
        .Debug, .ReleaseSafe => unspecifiedPanic,
        .ReleaseFast, .ReleaseSmall => undefined,
    };

    fn end(ip: Ip, vals: *ValStack, fuel: *Fuel, values_base: u32, stp: Stp, eip: Eip, interp: *Interpreter) OpcodeResult {
        if (@intFromPtr(ip) == @intFromPtr(eip)) {
            // TODO: Handle function return in a common routine!
            unreachable;
        } else {
            var reader = IpReader.init(ip, eip);
            if (reader.nextOpcodeHandler(fuel, interp)) |next| {
                @call(.always_tail, next, .{ reader.ip, vals, fuel, values_base, stp, eip, interp });
            }
        }
    }

    fn @"i32.const"(ip: Ip, vals: *ValStack, fuel: *Fuel, values_base: u32, stp: Stp, eip: Eip, interp: *Interpreter) OpcodeResult {
        var reader = IpReader.init(ip, eip);
        const i = reader.readIleb128(i32) catch unreachable;
        vals.appendAssumeCapacity(Value{ .i32 = i });

        if (reader.nextOpcodeHandler(fuel, interp)) |next| {
            @call(.always_tail, next, .{ reader.ip, vals, fuel, values_base, stp, eip, interp });
        }
    }

    fn @"i32.add"(ip: Ip, vals: *ValStack, fuel: *Fuel, values_base: u32, stp: Stp, eip: Eip, interp: *Interpreter) OpcodeResult {
        var reader = IpReader.init(ip, eip);
        const c_2 = vals.pop().i32;
        const c_1 = vals.pop().i32;
        vals.appendAssumeCapacity(c_1 +% c_2);

        if (reader.nextOpcodeHandler(fuel, interp)) |next| {
            @call(.always_tail, next, .{ reader.ip, vals, fuel, values_base, stp, eip, interp });
        }
    }

    fn @"i32.sub"(ip: Ip, vals: *ValStack, fuel: *Fuel, values_base: u32, stp: Stp, eip: Eip, interp: *Interpreter) OpcodeResult {
        var reader = IpReader.init(ip, eip);
        const c_2 = vals.pop().i32;
        const c_1 = vals.pop().i32;
        vals.appendAssumeCapacity(c_1 -% c_2);

        if (reader.nextOpcodeHandler(fuel, interp)) |next| {
            @call(.always_tail, next, .{ reader.ip, vals, fuel, values_base, stp, eip, interp });
        }
    }

    fn @"i32.mul"(ip: Ip, vals: *ValStack, fuel: *Fuel, values_base: u32, stp: Stp, eip: Eip, interp: *Interpreter) OpcodeResult {
        var reader = IpReader.init(ip, eip);
        const c_2 = vals.pop().i32;
        const c_1 = vals.pop().i32;
        vals.appendAssumeCapacity(c_1 *% c_2);

        if (reader.nextOpcodeHandler(fuel, interp)) |next| {
            @call(.always_tail, next, .{ reader.ip, vals, fuel, values_base, stp, eip, interp });
        }
    }

    //std.math.divTrunc
};

const byte_dispatch_table: [256]OpcodeHandler = handlers: {
    var table = [_]OpcodeHandler{opcode_handlers.unspecified} ** 256;
    for (@typeInfo(opcodes.ByteOpcode).@"enum".fields) |op| {
        if (@hasDecl(opcode_handlers, op.name)) {
            table[op.value] = @as(OpcodeHandler, @field(opcode_handlers, op.name));
        }
    }

    break :handlers table;
};

fn enterMainLoop(interp: *Interpreter, fuel: *Fuel) void {
    if (fuel.remaining == 0) {
        interp.state = .{ .interrupted = .out_of_fuel };
        return;
    }

    const starting_frame = interp.currentFrame();
    std.debug.assert(starting_frame.function.expanded() == .wasm);

    var reader = IpReader.init(starting_frame.ip, starting_frame.eip);
    const handler = reader.nextOpcodeHandler(fuel, &interp.state).?;

    _ = handler(
        reader.ip,
        &interp.value_stack,
        fuel,
        starting_frame.values_base,
        starting_frame.stp,
        starting_frame.eip,
        interp,
    );
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
    interp.state = .awaiting_host;
}

pub fn deinit(interp: *Interpreter, alloca: Allocator) void {
    interp.value_stack.deinit(alloca);
    interp.call_stack.deinit(alloca);
    interp.* = undefined;
}
