const std = @import("std");
const Allocator = std.mem.Allocator;
const runtime = @import("runtime.zig");

const FuncRef = runtime.FuncAddr.Nullable;

const Value = packed union {
    i32: i32,
    f32: f32,
    i64: i64,
    f64: f64,
    host_ref: runtime.ExternAddr,
    func_ref: FuncRef,
};

pub const StackFrame = extern struct {
    function: runtime.FuncAddr,
    values: u32,
    // Maybe reuse space for ip and stuff for host data when function is host?
};

value_stack: std.ArrayListUnmanaged(Value),
call_stack: std.ArrayListUnmanaged(StackFrame),
state: State,

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
        .value_stack = std.ArrayListUnmanaged(Value).initCapacity(
            alloca,
            options.value_stack_capacity,
        ),
        .call_stack = std.ArrayListUnmanaged(StackFrame).initCapacity(
            alloca,
            options.call_stack_capacity,
        ),
        .state = .executing,
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

pub const State = union(enum) {
    /// Either WASM code is waiting to be interpreted, or WASM code is awaiting the results of
    /// calling a host function.
    executing,
    /// Execution of WASM bytecode was interrupted after running out of fuel.
    ///
    /// The host can stop using the interpreter further and handle this error condition,
    /// resume execution with more fuel by calling `.resume()`, or reuse the interpreter for a
    /// future computation by calling `.reset()`.
    out_of_fuel,
    // memory_grow,
    /// The computation was aborted due to a *trap*. The call stack of the interpreter can be
    /// inspected to determine where and when the trap occurred.
    trapped: TrapCode,
    // unhandled_exception: Exception,
};

pub const Error = error{
    InvalidInterpreterState,
} || Allocator.Error;

// /// Resumes execution of WASM bytecode after an `out_of_fuel` condition.
// pub fn resume(interp: *Interpreter, alloc: Allocator, fuel: *Fuel) Error!void

pub fn beginCall(
    interp: *Interpreter,
    alloca: Allocator,
    callee: runtime.FuncAddr,
    arguments: []TaggedValue,
    fuel: *Fuel,
) Error!void {
    if (interp.state != .executing) return error.InvalidInterpreterState;

    const saved_value_stack_len = interp.value_stack.items.len;
    try interp.value_stack.ensureUnusedCapacity(alloca, arguments.len);
    errdefer interp.value_stack.items.len = saved_value_stack_len;

    for (arguments) |arg| {
        interp.value_stack.appendAssumeCapacity(
            switch (arg) {
                .func_ref => |func_ref| Value{ .func_ref = func_ref.* },
                inline else => |src| @unionInit(Value, @tagName(src), src),
            },
        );
    }

    _ = callee;
    _ = fuel;
    // TODO: Since validation is required, maybe have top most stack info stored in State, allowing a new State.awaiting_validation case
    // - or maybe always allocate a stack frame, but make StackFrame an union(enum)
    // TODO: Allocate stack frame (use known stack space calculated by code validator for WASM, nothing if host)
}

// /// Return from the currently executing host function to the calling function, typically WASM code.
// pub fn returnFromHost(inter: *Interpreter, results: []TaggedValue, fuel: *Fuel)

// TODO: Don't want extra branch in code that handles function return? How to handle module instantiation?
// - custom frame kind, so there is WASM, Host, and Instantiation, when latter is popped, it updates flag
// - add note saying it is not thread safe, host responsible when calling instantiate()

// TODO: should this error out if a computation is in progress?
pub fn reset(interp: *Interpreter) void {
    interp.value_stack.clearRetainingCapacity();
    interp.call_stack.clearRetainingCapacity();
}

pub fn deinit(interp: *Interpreter, alloca: Allocator) void {
    interp.value_stack.deinit(alloca);
    interp.call_stack.deinit(alloca);
    interp.* = undefined;
}
