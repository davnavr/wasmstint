//! Represents a single thread of WebAssembly computation.
//!
//! Based on <https://doi.org/10.48550/arXiv.2205.01183>.

const std = @import("std");
const builtin = @import("builtin");
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
    instantiate_flag: *bool,
};

const ValStack = std.ArrayListUnmanaged(Value);

value_stack: ValStack,
call_stack: std.ArrayListUnmanaged(StackFrame),
state: State = .{ .awaiting_host = &[0]Module.ValType{} },
dummy_instantiate_flag: bool = true,

const Interpreter = @This();

pub const Fuel = extern struct {
    remaining: u64,
};

pub const InitOptions = struct {
    /// The initial size, in bytes, of the value stack.
    value_stack_capacity: u32 = @sizeOf(Value) * 512,
    /// The initial capacity, in numbers of stack frames, of the call stack.
    call_stack_capacity: u32 = 32,
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
    lazy_validation_failed, // TODO: rename to lazy_validation_failure
    integer_division_by_zero,
    integer_overflow,
    invalid_conversion_to_integer,
    memory_access_out_of_bounds,
    table_access_out_of_bounds,
    indirect_call_to_null,
    indirect_call_signature_mismatch,
    _,

    pub fn initHost(code: u31) TrapCode {
        return @enumFromInt(-@as(i31, code) - 1);
    }

    pub fn host(code: TrapCode) ?u31 {
        return if (code < 0) @intCast(-(@intFromEnum(code) + 1)) else null;
    }

    fn initIntegerOverflow(e: error{Overflow}) TrapCode {
        return switch (e) {
            error.Overflow => .integer_overflow,
        };
    }

    fn initIntegerDivisionByZero(e: error{DivisionByZero}) TrapCode {
        return switch (e) {
            error.DivisionByZero => .integer_division_by_zero,
        };
    }

    fn initSignedIntegerDivision(e: error{ Overflow, DivisionByZero }) TrapCode {
        return switch (e) {
            error.Overflow => .integer_overflow,
            error.DivisionByZero => .integer_division_by_zero,
        };
    }

    fn initTrunc(e: error{ Overflow, NotANumber }) TrapCode {
        return switch (e) {
            error.Overflow => .integer_overflow,
            error.NotANumber => .invalid_conversion_to_integer,
        };
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

pub const Error = error{InvalidInterpreterState} || Allocator.Error;

pub fn copyResultValues(interp: *const Interpreter, arena: *std.heap.ArenaAllocator) Error![]TaggedValue {
    const types: []const Module.ValType = switch (interp.state) {
        .awaiting_host => |s| s,
        else => return error.InvalidInterpreterState,
    };

    const dst = try arena.allocator().alloc(TaggedValue, types.len);
    for (dst, types, interp.value_stack.items[interp.value_stack.items.len - types.len ..]) |*tagged, result_type, *result| {
        tagged.* = switch (result_type) {
            .v128 => unreachable, // Not implemented
            .funcref => func: {
                const dup = try arena.allocator().create(FuncRef);
                dup.* = result.funcref;
                break :func TaggedValue{ .funcref = dup };
            },
            inline else => |tag| @unionInit(
                TaggedValue,
                @tagName(tag),
                @field(result, @tagName(tag)),
            ),
        };
    }

    return dst;
}

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

    const entry_point = try interp.setupStackFrame(
        alloca,
        callee,
        values_base,
        signature,
        &interp.dummy_instantiate_flag,
    );

    switch (entry_point) {
        .wasm => interp.enterMainLoop(fuel),
        .host, .complete => {},
    }
}

pub fn instantiateModule(
    interp: *Interpreter,
    alloca: Allocator,
    module_inst: *runtime.ModuleInst,
    fuel: *Fuel,
) Error!void {
    const entry_point = try interp.setupStackFrame(
        alloca,
        module_inst.funcAddr(
            module_inst.module.inner.start.get() orelse {
                module_inst.instantiated = true;
                return;
            },
        ),
        std.math.cast(u32, interp.value_stack.items.len) orelse return Error.OutOfMemory,
        &Module.FuncType.empty,
        &module_inst.instantiated,
    );

    switch (entry_point) {
        .wasm => interp.enterMainLoop(fuel),
        .host, .complete => {},
    }
}

/// Pushes a new frame onto the call stack, with function arguments expected to already be on the stack.
///
/// Asserts that there is already enough space on the call stack.
fn setupStackFrame(
    interp: *Interpreter,
    alloca: Allocator,
    callee: runtime.FuncAddr,
    values_base: u32,
    signature: *const Module.FuncType,
    instantiate_flag: *bool,
) Allocator.Error!enum { host, wasm, complete } {
    std.debug.assert(interp.value_stack.items[values_base..].len >= signature.param_count);
    switch (callee.expanded()) {
        .wasm => |wasm| {
            const code: *const Module.Code = wasm.code();

            switch (code.state.flag.load(.acquire)) {
                .init, .validating => {
                    interp.state = .awaiting_lazy_validation;
                    return .complete;
                },
                // TODO: Only have a single `.finished` flag.
                .successful, .failed => {},
            }

            if (code.state.@"error") |_| {
                @branchHint(.cold);
                interp.state = .{ .trapped = TrapCode.lazy_validation_failed };
                return .complete;
            }

            const total_values = try interp.allocateValueStackSpace(alloca, code);

            try interp.call_stack.append(
                alloca,
                StackFrame{
                    .function = callee,
                    .instructions = Instructions.init(code.state.instructions, code.state.instructions_end),
                    .branch_table = code.state.side_table_ptr,
                    .values_base = values_base,
                    .values_count = total_values,
                    .result_count = signature.result_count,
                    .instantiate_flag = instantiate_flag,
                },
            );
            return .wasm;
        },
        .host => {
            try interp.call_stack.append(
                alloca,
                StackFrame{
                    .function = callee,
                    .instructions = undefined,
                    .branch_table = undefined,
                    .values_base = values_base,
                    .values_count = signature.param_count,
                    .result_count = signature.result_count,
                    .instantiate_flag = instantiate_flag,
                },
            );
            return .host;
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

    fn readByteArray(i: *Instructions, comptime n: usize) Module.NoEofError!*const [n]u8 {
        if (@intFromPtr(i.p) + (n - 1) <= @intFromPtr(i.ep)) {
            const result = i.p[0..n];
            i.p += n;
            return result;
        } else return error.EndOfStream;
    }

    pub inline fn readByte(i: *Instructions) Module.NoEofError!u8 {
        return (try i.readByteArray(1))[0];
    }

    inline fn readUleb128(reader: *Instructions, comptime T: type) error{ Overflow, EndOfStream }!T {
        return std.leb.readUleb128(T, reader);
    }

    inline fn nextIdx(reader: *Instructions, comptime I: type) I {
        return @enumFromInt(reader.readUleb128(@typeInfo(I).@"enum".tag_type) catch unreachable);
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

            // const saved_ip = @intFromPtr(reader.p) -
            //     @intFromPtr(interp.currentFrame().function.expanded().wasm.module.module.wasm.ptr);

            const next_opcode = reader.readByte() catch unreachable;

            // std.debug.print(
            //     "TRACE[{X:0>6}]: {s}\n",
            //     .{ saved_ip, @tagName(@as(opcodes.ByteOpcode, @enumFromInt(next_opcode))) },
            // );

            return byte_dispatch_table[next_opcode];
        }
    }

    inline fn skipBlockType(reader: *Instructions) void {
        _ = std.leb.readIleb128(i33, reader) catch unreachable;
    }
};

/// Moves return values to their appropriate place in the value stack.
///
/// Execution of the handlers for the `end` (only when it is last opcode of a function)
/// and `return` instructions ends up here.
///
/// To ensure the interpreter cannot overflow the stack, opcode handlers must call this function
/// via `@call` with either `.always_tail` or `always_inline`.
fn returnFromWasm(i: *Instructions, s: *Stp, loc: u32, vals: *ValStack, fuel: *Fuel, int: *Interpreter) void {
    _ = i;
    _ = s;

    const popped = int.currentFrame();
    std.debug.assert(popped.function.expanded() == .wasm);
    int.call_stack.items.len -= 1;
    popped.instantiate_flag.* = true;

    const new_value_stack_len = loc + popped.result_count;
    std.mem.copyForwards(
        Value,
        int.value_stack.items[loc..new_value_stack_len],
        int.value_stack.items[int.value_stack.items.len - popped.result_count ..],
    );
    int.value_stack.items.len = new_value_stack_len;

    return_to_host: {
        if (int.call_stack.items.len == 0) break :return_to_host;

        const caller_frame = int.currentFrame();
        switch (caller_frame.function.expanded()) {
            .wasm => if (caller_frame.instructions.nextOpcodeHandler(fuel, int)) |next| {
                @call(
                    .always_tail,
                    next,
                    .{ &caller_frame.instructions, &caller_frame.branch_table, caller_frame.values_base, vals, fuel, int },
                );
            } else return,
            .host => break :return_to_host,
        }

        comptime unreachable;
    }

    const signature = popped.function.signature();
    std.debug.assert(signature.result_count == popped.result_count);
    int.state = .{ .awaiting_host = signature.results() };
}

/// Continues execution of WASM code up to calling the `target_function`, with arguments expected
/// to be on top of the value stack.
///
/// To ensure the interpreter cannot overflow the stack, opcode handlers must ensure this function is
/// called inline.
inline fn invokeWithinWasm(
    target_function: runtime.FuncAddr,
    loc: u32,
    vals: *ValStack,
    fuel: *Fuel,
    int: *Interpreter,
) void {
    const signature = target_function.signature();

    // Overlap trick to avoid copying arguments.
    const values_base = @as(u32, @intCast(vals.items.len)) - signature.param_count;

    const entry_point = int.setupStackFrame(
        no_allocation.allocator,
        target_function,
        values_base,
        signature,
        &int.dummy_instantiate_flag,
    ) catch |e| switch (e) {
        error.OutOfMemory => {
            // Could set ip back to before the call instruction to allow trying again.
            // std.debug.print("call stack depth: {}\n", .{int.call_stack.items.len});
            int.state = .{ .interrupted = .call_stack_exhaustion };
            return;
        },
    };

    switch (entry_point) {
        .wasm => {
            std.debug.assert(loc <= values_base);

            const new_frame = int.currentFrame();
            if (new_frame.instructions.nextOpcodeHandler(fuel, int)) |next| {
                @call(
                    .always_tail,
                    next,
                    .{ &new_frame.instructions, &new_frame.branch_table, values_base, vals, fuel, int },
                );
            }
        },
        .host => {
            int.state = State{ .awaiting_host = signature.parameters() };
        },
        .complete => {},
    }
}

const MemArg = struct {
    mem: *const runtime.MemInst,
    offset: u32,

    // TODO: Should opcode handlers take extra ModuleInst parameter?
    fn read(i: *Instructions, interp: *Interpreter) MemArg {
        _ = i.readUleb128(u32) catch unreachable; // align
        return .{
            .offset = i.readUleb128(u32) catch unreachable,
            .mem = interp.currentFrame().function.expanded().wasm.module.memAddr(.default),
        };
    }
};

fn linearMemoryAccessors(comptime access_size: u5) type {
    return struct {
        comptime {
            std.debug.assert(0 < access_size);
            std.debug.assert(std.math.isPowerOfTwo(access_size));
            std.debug.assert(builtin.cpu.arch.endian() == .little);
        }

        const Bytes = [access_size]u8;

        fn performLoad(i: *Instructions, vals: *ValStack, interp: *Interpreter) ?*const Bytes {
            const mem_arg = MemArg.read(i, interp);
            const base_addr: u32 = @bitCast(vals.pop().i32);
            // std.debug.print(" > load of size {} @ 0x{X} + {} into memory size={}\n", .{ access_size, base_addr, mem_arg.offset, mem_arg.mem.size });
            const effective_addr = std.math.add(u32, base_addr, mem_arg.offset) catch return null;
            const end_addr = std.math.add(u32, effective_addr, access_size - 1) catch return null;
            if (mem_arg.mem.size <= end_addr) return null;
            return mem_arg.mem.bytes()[effective_addr..][0..access_size];
        }

        fn performStore(
            i: *Instructions,
            vals: *ValStack,
            interp: *Interpreter,
            value: Bytes,
        ) error{OutOfBounds}!void {
            const mem_arg = MemArg.read(i, interp);
            const base_addr: u32 = @bitCast(vals.pop().i32);
            const effective_addr = std.math.add(u32, base_addr, mem_arg.offset) catch
                return error.OutOfBounds;
            const end_addr = std.math.add(u32, effective_addr, access_size - 1) catch
                return error.OutOfBounds;
            if (mem_arg.mem.size <= end_addr)
                return error.OutOfBounds;

            mem_arg.mem.bytes()[effective_addr..][0..access_size].* = value;
        }
    };
}

fn linearMemoryHandlers(comptime field_name: []const u8) type {
    return struct {
        comptime {
            std.debug.assert(builtin.cpu.arch.endian() == .little);
        }

        const T = @FieldType(Value, field_name);
        const accessors = linearMemoryAccessors(@sizeOf(T));

        fn load(i: *Instructions, s: *Stp, loc: u32, vals: *ValStack, fuel: *Fuel, int: *Interpreter) void {
            const bytes = accessors.performLoad(i, vals, int) orelse {
                int.state = .{ .trapped = .memory_access_out_of_bounds };
                return;
            };

            vals.appendAssumeCapacity(@unionInit(Value, field_name, @bitCast(bytes.*)));

            std.debug.assert(loc <= vals.items.len);
            if (i.nextOpcodeHandler(fuel, int)) |next| {
                @call(.always_tail, next, .{ i, s, loc, vals, fuel, int });
            }
        }

        fn store(i: *Instructions, s: *Stp, loc: u32, vals: *ValStack, fuel: *Fuel, int: *Interpreter) void {
            const c: accessors.Bytes = @bitCast(@field(vals.pop(), field_name));
            accessors.performStore(i, vals, int, c) catch |e| {
                comptime std.debug.assert(@TypeOf(e) == error{OutOfBounds});
                int.state = .{ .trapped = .memory_access_out_of_bounds };
                return;
            };

            std.debug.assert(loc <= vals.items.len);
            if (i.nextOpcodeHandler(fuel, int)) |next| {
                @call(.always_tail, next, .{ i, s, loc, vals, fuel, int });
            }
        }
    };
}

fn extendingLinearMemoryLoad(comptime field_name: []const u8, comptime S: type) type {
    return struct {
        const T = @FieldType(Value, field_name);

        comptime {
            std.debug.assert(@bitSizeOf(S) < @bitSizeOf(T));
        }

        fn handler(i: *Instructions, s: *Stp, loc: u32, vals: *ValStack, fuel: *Fuel, int: *Interpreter) void {
            const bytes = linearMemoryAccessors(@sizeOf(S)).performLoad(i, vals, int) orelse {
                int.state = .{ .trapped = .memory_access_out_of_bounds };
                return;
            };

            vals.appendAssumeCapacity(
                @unionInit(
                    Value,
                    field_name,
                    @as(S, @bitCast(bytes.*)),
                ),
            );

            std.debug.assert(loc <= vals.items.len);
            if (i.nextOpcodeHandler(fuel, int)) |next| {
                @call(.always_tail, next, .{ i, s, loc, vals, fuel, int });
            }
        }
    };
}

fn narrowingLinearMemoryStore(comptime field_name: []const u8, comptime size: u6) type {
    return struct {
        const T = @FieldType(Value, field_name);
        const S = std.meta.Int(.signed, size);

        comptime {
            std.debug.assert(@bitSizeOf(S) < @bitSizeOf(T));
        }

        fn handler(i: *Instructions, s: *Stp, loc: u32, vals: *ValStack, fuel: *Fuel, int: *Interpreter) void {
            const narrowed: S = @truncate(@field(vals.pop(), field_name));
            linearMemoryAccessors(size / 8).performStore(i, vals, int, @bitCast(narrowed)) catch |e| {
                comptime std.debug.assert(@TypeOf(e) == error{OutOfBounds});
                int.state = .{ .trapped = .memory_access_out_of_bounds };
                return;
            };

            std.debug.assert(loc <= vals.items.len);
            if (i.nextOpcodeHandler(fuel, int)) |next| {
                @call(.always_tail, next, .{ i, s, loc, vals, fuel, int });
            }
        }
    };
}

fn defineBinOp(comptime value_field: []const u8, comptime op: anytype, comptime trap: anytype) type {
    return struct {
        fn handler(i: *Instructions, s: *Stp, loc: u32, vals: *ValStack, fuel: *Fuel, int: *Interpreter) void {
            const c_2 = @field(vals.pop(), value_field);
            const c_1 = @field(vals.pop(), value_field);
            const result = @call(.always_inline, op, .{ c_1, c_2 }) catch |e| {
                int.state = .{ .trapped = @call(.always_inline, trap, .{e}) };
                return;
            };

            vals.appendAssumeCapacity(@unionInit(Value, value_field, result));

            std.debug.assert(loc <= vals.items.len);
            if (i.nextOpcodeHandler(fuel, int)) |next| {
                @call(.always_tail, next, .{ i, s, loc, vals, fuel, int });
            }
        }
    };
}

fn defineUnOp(comptime value_field: []const u8, comptime op: anytype) type {
    return struct {
        fn handler(i: *Instructions, s: *Stp, loc: u32, vals: *ValStack, fuel: *Fuel, int: *Interpreter) void {
            const c_1 = @field(vals.pop(), value_field);
            const result = @call(.always_inline, op, .{c_1});
            vals.appendAssumeCapacity(@unionInit(Value, value_field, result));

            std.debug.assert(loc <= vals.items.len);
            if (i.nextOpcodeHandler(fuel, int)) |next| {
                @call(.always_tail, next, .{ i, s, loc, vals, fuel, int });
            }
        }
    };
}

fn defineTestOp(comptime value_field: []const u8, comptime op: anytype) type {
    return struct {
        fn handler(i: *Instructions, s: *Stp, loc: u32, vals: *ValStack, fuel: *Fuel, int: *Interpreter) void {
            const c_1 = @field(vals.pop(), value_field);
            const result = @call(.always_inline, op, .{c_1});
            vals.appendAssumeCapacity(Value{ .i32 = @intFromBool(result) });

            std.debug.assert(loc <= vals.items.len);
            if (i.nextOpcodeHandler(fuel, int)) |next| {
                @call(.always_tail, next, .{ i, s, loc, vals, fuel, int });
            }
        }
    };
}

fn defineRelOp(comptime value_field: []const u8, comptime op: anytype) type {
    return struct {
        fn handler(i: *Instructions, s: *Stp, loc: u32, vals: *ValStack, fuel: *Fuel, int: *Interpreter) void {
            const c_2 = @field(vals.pop(), value_field);
            const c_1 = @field(vals.pop(), value_field);
            const result = @call(.always_inline, op, .{ c_1, c_2 });
            vals.appendAssumeCapacity(Value{ .i32 = @intFromBool(result) });

            std.debug.assert(loc <= vals.items.len);
            if (i.nextOpcodeHandler(fuel, int)) |next| {
                @call(.always_tail, next, .{ i, s, loc, vals, fuel, int });
            }
        }
    };
}

fn defineConvOp(
    comptime src_field: []const u8,
    comptime dst_field: []const u8,
    comptime op: anytype,
    comptime trap: anytype,
) type {
    return struct {
        fn handler(i: *Instructions, s: *Stp, loc: u32, vals: *ValStack, fuel: *Fuel, int: *Interpreter) void {
            const t_1 = @field(vals.pop(), src_field);
            const result = @call(.always_inline, op, .{t_1}) catch |e| {
                int.state = .{ .trapped = @call(.always_inline, trap, .{e}) };
                return;
            };

            vals.appendAssumeCapacity(@unionInit(Value, dst_field, result));

            std.debug.assert(loc <= vals.items.len);
            if (i.nextOpcodeHandler(fuel, int)) |next| {
                @call(.always_tail, next, .{ i, s, loc, vals, fuel, int });
            }
        }
    };
}

fn trapIntegerOverflow(e: error{Overflow}) TrapCode {
    return switch (e) {
        error.Overflow => .integer_overflow,
    };
}

fn trapSignedIntegerDivision(e: error{ Overflow, DivisionByZero }) TrapCode {
    return switch (e) {
        error.Overflow => .integer_overflow,
        error.DivisionByZero => .integer_division_by_zero,
    };
}

fn integerOpcodeHandlers(comptime Signed: type) type {
    return struct {
        const Unsigned = std.meta.Int(.unsigned, @typeInfo(Signed).int.bits);
        const value_field = @typeName(Signed);

        const operators = struct {
            fn eqz(i: Signed) bool {
                return i == 0;
            }

            fn eq(i_1: Signed, i_2: Signed) bool {
                // std.debug.print(" > (" ++ @typeName(Signed) ++ ".eq) {0} (0x{0X}) == {1} (0x{1X})?\n", .{ i_1, i_2 });
                return i_1 == i_2;
            }

            fn ne(i_1: Signed, i_2: Signed) bool {
                return i_1 != i_2;
            }

            fn lt_s(i_1: Signed, i_2: Signed) bool {
                return i_1 < i_2;
            }

            fn lt_u(i_1: Signed, i_2: Signed) bool {
                return @as(Unsigned, @bitCast(i_1)) < @as(Unsigned, @bitCast(i_2));
            }

            fn gt_s(i_1: Signed, i_2: Signed) bool {
                return i_1 > i_2;
            }

            fn gt_u(i_1: Signed, i_2: Signed) bool {
                // std.debug.print(" > (" ++ @typeName(Signed) ++ ".gt_u) {[0]X} (0x{[0]X}) > {[1]} ([{1}X])\n", .{ i_1, i_2 });
                return @as(Unsigned, @bitCast(i_1)) > @as(Unsigned, @bitCast(i_2));
            }

            fn le_s(i_1: Signed, i_2: Signed) bool {
                return i_1 <= i_2;
            }

            fn le_u(i_1: Signed, i_2: Signed) bool {
                return @as(Unsigned, @bitCast(i_1)) <= @as(Unsigned, @bitCast(i_2));
            }

            fn ge_s(i_1: Signed, i_2: Signed) bool {
                return i_1 >= i_2;
            }

            fn ge_u(i_1: Signed, i_2: Signed) bool {
                return @as(Unsigned, @bitCast(i_1)) >= @as(Unsigned, @bitCast(i_2));
            }

            fn clz(i: Signed) Signed {
                return @bitCast(@as(Unsigned, @clz(i)));
            }

            fn ctz(i: Signed) Signed {
                return @bitCast(@as(Unsigned, @ctz(i)));
            }

            fn popcnt(i: Signed) Signed {
                return @bitCast(@as(Unsigned, @popCount(i)));
            }

            fn add(i_1: Signed, i_2: Signed) !Signed {
                // std.debug.print(" > (" ++ @typeName(Signed) ++ ".add) {0} (0x{0X}) + {1} (0x{1X})\n", .{ i_1, i_2 });
                return i_1 +% i_2;
            }

            fn sub(i_1: Signed, i_2: Signed) !Signed {
                // std.debug.print(" > (" ++ @typeName(Signed) ++ ".sub) {0} (0x{0X}) - {1} (0x{1X})\n", .{ i_1, i_2 });
                return i_1 -% i_2;
            }

            fn mul(i_1: Signed, i_2: Signed) !Signed {
                // std.debug.print(" > (" ++ @typeName(Signed) ++ ".mul) {0} (0x{0X}) * {1} (0x{1X})\n", .{ i_1, i_2 });
                return i_1 *% i_2;
            }

            fn div_s(j_1: Signed, j_2: Signed) error{ Overflow, DivisionByZero }!Signed {
                return std.math.divTrunc(Signed, j_1, j_2);
            }

            fn div_u(i_1: Signed, i_2: Signed) error{DivisionByZero}!Signed {
                return @bitCast(try std.math.divTrunc(Unsigned, @bitCast(i_1), @bitCast(i_2)));
            }

            fn rem_s(j_1: Signed, j_2: Signed) error{DivisionByZero}!Signed {
                return if (j_2 == 0)
                    error.DivisionByZero
                else if (j_1 == std.math.minInt(Signed) and j_2 == -1)
                    0
                else
                    j_1 - (j_2 * @divTrunc(j_1, j_2));
            }

            fn rem_u(i_1: Signed, i_2: Signed) error{DivisionByZero}!Signed {
                return @bitCast(try std.math.rem(Unsigned, @bitCast(i_1), @bitCast(i_2)));
            }

            fn @"and"(i_1: Signed, i_2: Signed) !Signed {
                return i_1 & i_2;
            }

            fn @"or"(i_1: Signed, i_2: Signed) !Signed {
                return i_1 | i_2;
            }

            fn xor(i_1: Signed, i_2: Signed) !Signed {
                return i_1 ^ i_2;
            }

            /// *k*
            inline fn bitShiftAmt(i_2: Signed) std.math.Log2Int(Signed) {
                return @intCast(@mod(i_2, @bitSizeOf(Signed)));
            }

            fn shl(i_1: Signed, i_2: Signed) !Signed {
                return i_1 << bitShiftAmt(i_2);
            }

            fn shr_s(i_1: Signed, i_2: Signed) !Signed {
                // Currently assumes Zig sign-extends when shifting right.
                return i_1 >> bitShiftAmt(i_2);
            }

            fn shr_u(i_1: Signed, i_2: Signed) !Signed {
                return @bitCast(@as(Unsigned, @bitCast(i_1)) >> bitShiftAmt(i_2));
            }

            fn rotl(i_1: Signed, i_2: Signed) !Signed {
                // Zig's function here handles the `bitShiftAmt()`/`@mod()`
                return @bitCast(std.math.rotl(Unsigned, @bitCast(i_1), i_2));
            }

            fn rotr(i_1: Signed, i_2: Signed) !Signed {
                // Zig's function here handles the `bitShiftAmt()`/`@mod()`
                return @bitCast(std.math.rotr(Unsigned, @bitCast(i_1), i_2));
            }

            fn trunc_s(z: anytype) !Signed {
                if (std.math.isNan(z)) return error.NotANumber;

                const tr = @trunc(z);
                return if (tr < std.math.minInt(Signed) or std.math.maxInt(Signed) < tr)
                    error.Overflow
                else
                    @intFromFloat(tr);
            }

            fn trunc_u(z: anytype) !Signed {
                if (std.math.isNan(z)) return error.NotANumber;

                const tr = @trunc(z);
                return if (tr < -0.0 or std.math.maxInt(Unsigned) < tr)
                    error.Overflow
                else
                    @bitCast(@as(Unsigned, @intFromFloat(tr)));
            }

            fn trunc_sat_s(z: anytype) !Signed {
                return std.math.lossyCast(Signed, z);
            }

            fn trunc_sat_u(z: anytype) !Signed {
                return @bitCast(std.math.lossyCast(Unsigned, z));
            }
        };

        fn @"const"(i: *Instructions, s: *Stp, loc: u32, vals: *ValStack, fuel: *Fuel, int: *Interpreter) void {
            const n = i.readIleb128(Signed) catch unreachable;
            vals.appendAssumeCapacity(@unionInit(Value, value_field, n));
            // std.debug.print(" > (" ++ @typeName(Signed) ++ ".const) {[0]} (0x{[0]X})\n", .{n});

            if (i.nextOpcodeHandler(fuel, int)) |next| {
                @call(.always_tail, next, .{ i, s, loc, vals, fuel, int });
            }
        }

        const eqz = defineTestOp(value_field, operators.eqz).handler;
        const eq = defineRelOp(value_field, operators.eq).handler;
        const ne = defineRelOp(value_field, operators.ne).handler;
        const lt_s = defineRelOp(value_field, operators.lt_s).handler;
        const lt_u = defineRelOp(value_field, operators.lt_u).handler;
        const gt_s = defineRelOp(value_field, operators.gt_s).handler;
        const gt_u = defineRelOp(value_field, operators.gt_u).handler;
        const le_s = defineRelOp(value_field, operators.le_s).handler;
        const le_u = defineRelOp(value_field, operators.le_u).handler;
        const ge_s = defineRelOp(value_field, operators.ge_s).handler;
        const ge_u = defineRelOp(value_field, operators.ge_u).handler;

        const clz = defineUnOp(value_field, operators.clz).handler;
        const ctz = defineUnOp(value_field, operators.ctz).handler;
        const popcnt = defineUnOp(value_field, operators.popcnt).handler;
        const add = defineBinOp(value_field, operators.add, undefined).handler;
        const sub = defineBinOp(value_field, operators.sub, undefined).handler;
        const mul = defineBinOp(value_field, operators.mul, undefined).handler;
        const div_s = defineBinOp(value_field, operators.div_s, TrapCode.initSignedIntegerDivision).handler;
        const div_u = defineBinOp(value_field, operators.div_u, TrapCode.initIntegerDivisionByZero).handler;
        const rem_s = defineBinOp(value_field, operators.rem_s, TrapCode.initIntegerDivisionByZero).handler;
        const rem_u = defineBinOp(value_field, operators.rem_u, TrapCode.initIntegerDivisionByZero).handler;
        const @"and" = defineBinOp(value_field, operators.@"and", undefined).handler;
        const @"or" = defineBinOp(value_field, operators.@"or", undefined).handler;
        const xor = defineBinOp(value_field, operators.xor, undefined).handler;
        const shl = defineBinOp(value_field, operators.shl, undefined).handler;
        const shr_s = defineBinOp(value_field, operators.shr_s, undefined).handler;
        const shr_u = defineBinOp(value_field, operators.shr_u, undefined).handler;
        const rotl = defineBinOp(value_field, operators.rotl, undefined).handler;
        const rotr = defineBinOp(value_field, operators.rotr, undefined).handler;

        const trunc_f32_s = defineConvOp("f32", value_field, operators.trunc_s, TrapCode.initTrunc).handler;
        const trunc_f32_u = defineConvOp("f32", value_field, operators.trunc_u, TrapCode.initTrunc).handler;
        const trunc_f64_s = defineConvOp("f64", value_field, operators.trunc_s, TrapCode.initTrunc).handler;
        const trunc_f64_u = defineConvOp("f64", value_field, operators.trunc_u, TrapCode.initTrunc).handler;

        const trunc_sat_f32_s = defineConvOp("f32", value_field, operators.trunc_sat_s, TrapCode.initTrunc).handler;
        const trunc_sat_f32_u = defineConvOp("f32", value_field, operators.trunc_sat_u, TrapCode.initTrunc).handler;
        const trunc_sat_f64_s = defineConvOp("f64", value_field, operators.trunc_sat_s, TrapCode.initTrunc).handler;
        const trunc_sat_f64_u = defineConvOp("f64", value_field, operators.trunc_sat_u, TrapCode.initTrunc).handler;
    };
}

const i32_opcode_handlers = integerOpcodeHandlers(i32);
const i64_opcode_handlers = integerOpcodeHandlers(i64);

fn floatOpcodeHandlers(comptime F: type) type {
    return struct {
        const value_field = @typeName(F);

        const operators = struct {
            fn convert_s(i: anytype) !F {
                comptime std.debug.assert(@typeInfo(@TypeOf(i)).int.signedness == .signed);
                return @floatFromInt(i);
            }

            fn convert_u(i: anytype) !F {
                comptime std.debug.assert(@typeInfo(@TypeOf(i)).int.signedness == .signed);
                const Unsigned = std.meta.Int(.unsigned, @typeInfo(@TypeOf(i)).int.bits);
                return @floatFromInt(@as(Unsigned, @bitCast(i)));
            }
        };

        fn @"const"(i: *Instructions, s: *Stp, loc: u32, vals: *ValStack, fuel: *Fuel, int: *Interpreter) void {
            const z = std.mem.readInt(
                std.meta.Int(.unsigned, @bitSizeOf(F)),
                i.readByteArray(@sizeOf(F)) catch unreachable,
                .little,
            );

            vals.appendAssumeCapacity(@unionInit(Value, value_field, @bitCast(z)));

            if (i.nextOpcodeHandler(fuel, int)) |next| {
                @call(.always_tail, next, .{ i, s, loc, vals, fuel, int });
            }
        }

        const convert_i32_s = defineConvOp("i32", value_field, operators.convert_s, undefined).handler;
        const convert_i32_u = defineConvOp("i32", value_field, operators.convert_u, undefined).handler;
        const convert_i64_s = defineConvOp("i64", value_field, operators.convert_s, undefined).handler;
        const convert_i64_u = defineConvOp("i64", value_field, operators.convert_u, undefined).handler;
    };
}

const f32_opcode_handlers = floatOpcodeHandlers(f32);
const f64_opcode_handlers = floatOpcodeHandlers(f64);

fn dispatchTableLength(comptime Opcode: type) comptime_int {
    var maximum = 0;
    for (@typeInfo(Opcode).@"enum".fields) |op| {
        maximum = @max(maximum, op.value);
    }
    return maximum + 1;
}

fn dispatchTable(comptime Opcode: type, comptime invalid: OpcodeHandler) [dispatchTableLength(Opcode)]OpcodeHandler {
    var table = [_]OpcodeHandler{invalid} ** dispatchTableLength(Opcode);
    for (@typeInfo(Opcode).@"enum".fields) |op| {
        if (@hasDecl(opcode_handlers, op.name)) {
            table[op.value] = @as(OpcodeHandler, @field(opcode_handlers, op.name));
        }
    }

    return table;
}

fn prefixDispatchTable(comptime prefix: opcodes.ByteOpcode, comptime Opcode: type) type {
    return struct {
        fn panicInvalidInstruction(i: *Instructions, s: *Stp, loc: u32, vals: *ValStack, fuel: *Fuel, int: *Interpreter) void {
            _ = s;
            _ = loc;
            _ = vals;
            _ = fuel;
            _ = int;
            std.debug.panic(
                "invalid instruction 0x{X:0>2} ... 0x{X:0>2}",
                .{ @intFromEnum(prefix), (i.p - 1)[0] },
            );
        }

        const invalid: OpcodeHandler = switch (builtin.mode) {
            .Debug, .ReleaseSafe => panicInvalidInstruction,
            .ReleaseFast, .ReleaseSmall => undefined,
        };

        const entries = dispatchTable(Opcode, invalid);

        pub fn handler(i: *Instructions, s: *Stp, loc: u32, vals: *ValStack, fuel: *Fuel, int: *Interpreter) void {
            const n = i.nextIdx(Opcode);
            const next = entries[@intFromEnum(n)];
            @call(.always_tail, next, .{ i, s, loc, vals, fuel, int });
        }
    };
}

const fc_prefixed_dispatch = prefixDispatchTable(.@"0xFC", opcodes.FCPrefixOpcode);

const no_allocation = struct {
    const vtable = Allocator.VTable{
        .alloc = noAlloc,
        .resize = Allocator.noResize,
        .free = neverFree,
    };

    fn noAlloc(_: *anyopaque, _: usize, _: u8, _: usize) ?[*]u8 {
        @branchHint(.cold);
        return null;
    }

    fn noResize(_: *anyopaque, _: []u8, _: u8, _: usize, _: usize) bool {
        @branchHint(.cold);
        return false;
    }

    fn neverFree(_: *anyopaque, _: []u8, _: u8, _: usize) void {
        unreachable;
    }

    const allocator = Allocator{ .ptr = undefined, .vtable = &vtable };
};

fn addPtrWithOffset(ptr: anytype, offset: isize) @TypeOf(ptr) {
    const sum = if (offset < 0) ptr - @abs(offset) else ptr + @as(usize, @intCast(offset));
    // std.debug.print(" > {*} + {} = {*}\n", .{ ptr, offset, sum });
    return sum;
}

inline fn takeBranch(
    interp: *Interpreter,
    base_ip: Ip,
    i: *Instructions,
    s: *Stp,
    vals: *ValStack,
    branch: u32,
) void {
    const code = interp.currentFrame().function.expanded().wasm.code();
    const wasm_base_ptr = @intFromPtr(interp.currentFrame().function.expanded().wasm.module.module.wasm.ptr);

    const side_table_end = @intFromPtr(code.state.side_table_ptr + code.state.side_table_len);
    std.debug.assert(@intFromPtr(s.* + branch) < side_table_end);
    const target: *const Module.Code.SideTableEntry = &s.*[branch];

    const origin_ip = code.state.instructions + target.origin;
    if (builtin.mode == .Debug and @intFromPtr(base_ip) != @intFromPtr(origin_ip)) {
        std.debug.panic(
            "expected this branch to originate from {X:0>6}, but got {X:0>6}",
            .{ @intFromPtr(origin_ip) - wasm_base_ptr, @intFromPtr(base_ip) - wasm_base_ptr },
        );
    }

    // std.debug.print(
    //     " ? TGT BRANCH #{} (current is #{}): delta_ip={}, delta_stp={}\n",
    //     .{
    //         (@intFromPtr(target) - @intFromPtr(code.state.side_table_ptr)) / @sizeOf(Module.Code.SideTableEntry),
    //         (@intFromPtr(s.*) - @intFromPtr(code.state.side_table_ptr)) / @sizeOf(Module.Code.SideTableEntry),
    //         target.delta_ip.done,
    //         target.delta_stp,
    //     },
    // );

    i.p = addPtrWithOffset(base_ip, target.delta_ip.done);
    std.debug.assert(@intFromPtr(code.state.instructions) <= @intFromPtr(i.p));
    std.debug.assert(@intFromPtr(i.p) <= @intFromPtr(i.ep));

    // std.debug.print(
    //     " ? NEXT[{X:0>6}]: 0x{X} ({s})\n",
    //     .{
    //         @intFromPtr(i.p) - wasm_base_ptr,
    //         i.p[0],
    //         @tagName(@as(opcodes.ByteOpcode, @enumFromInt(i.p[0]))),
    //     },
    // );

    s.* = addPtrWithOffset(s.* + branch, target.delta_stp);
    std.debug.assert(@intFromPtr(code.state.side_table_ptr) <= @intFromPtr(s.*));
    std.debug.assert(@intFromPtr(s.*) <= side_table_end);

    // std.debug.print(
    //     " ? STP=#{}\n",
    //     .{(@intFromPtr(s.*) - @intFromPtr(code.state.side_table_ptr)) / @sizeOf(Module.Code.SideTableEntry)},
    // );

    const vals_base = vals.items.len;
    const src = vals.items[vals_base - target.copy_count ..];
    if (target.copy_count > target.pop_count) {
        vals.appendNTimesAssumeCapacity(undefined, target.copy_count - target.pop_count);
    }

    const dest = vals.items[vals_base - target.pop_count ..];
    std.mem.copyBackwards(Value, dest[0..target.copy_count], src);
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

        std.debug.panic("invalid instruction 0x{X:0>2} ({s})", .{ bad_opcode, opcode_name });
    }

    const invalid: OpcodeHandler = switch (builtin.mode) {
        .Debug, .ReleaseSafe => panicInvalidInstruction,
        .ReleaseFast, .ReleaseSmall => undefined,
    };

    pub fn @"unreachable"(i: *Instructions, s: *Stp, loc: u32, vals: *ValStack, fuel: *Fuel, int: *Interpreter) void {
        _ = i;
        _ = s;
        _ = loc;
        _ = vals;
        _ = fuel;
        int.state = .{ .trapped = .unreachable_code_reached };
    }

    pub fn nop(i: *Instructions, s: *Stp, loc: u32, vals: *ValStack, fuel: *Fuel, int: *Interpreter) void {
        if (i.nextOpcodeHandler(fuel, int)) |next| {
            @call(.always_tail, next, .{ i, s, loc, vals, fuel, int });
        }
    }

    pub fn block(i: *Instructions, s: *Stp, loc: u32, vals: *ValStack, fuel: *Fuel, int: *Interpreter) void {
        i.skipBlockType();
        if (i.nextOpcodeHandler(fuel, int)) |next| {
            @call(.always_tail, next, .{ i, s, loc, vals, fuel, int });
        }
    }

    pub const loop = block;

    pub fn @"if"(i: *Instructions, s: *Stp, loc: u32, vals: *ValStack, fuel: *Fuel, int: *Interpreter) void {
        const c = vals.pop().i32;
        std.debug.assert(loc <= vals.items.len);
        // std.debug.print(" > (if) {}?\n", .{c != 0});
        if (c == 0) {
            // No need to read LEB128 block type.
            int.takeBranch(i.p - 1, i, s, vals, 0);
        } else {
            i.skipBlockType();
            s.* += 1;
        }

        if (i.nextOpcodeHandler(fuel, int)) |next| {
            @call(.always_tail, next, .{ i, s, loc, vals, fuel, int });
        }
    }

    pub fn @"else"(i: *Instructions, s: *Stp, loc: u32, vals: *ValStack, fuel: *Fuel, int: *Interpreter) void {
        int.takeBranch(i.p - 1, i, s, vals, 0);

        if (i.nextOpcodeHandler(fuel, int)) |next| {
            @call(.always_tail, next, .{ i, s, loc, vals, fuel, int });
        }
    }

    pub fn end(i: *Instructions, s: *Stp, loc: u32, vals: *ValStack, fuel: *Fuel, int: *Interpreter) void {
        if (@intFromPtr(i.p - 1) == @intFromPtr(i.ep)) {
            @call(.always_tail, returnFromWasm, .{ i, s, loc, vals, fuel, int });
        } else if (i.nextOpcodeHandler(fuel, int)) |next| {
            @call(.always_tail, next, .{ i, s, loc, vals, fuel, int });
        }
    }

    pub fn br(i: *Instructions, s: *Stp, loc: u32, vals: *ValStack, fuel: *Fuel, int: *Interpreter) void {
        // No need to read LEB128 branch target
        int.takeBranch(i.p - 1, i, s, vals, 0);
        if (i.nextOpcodeHandler(fuel, int)) |next| {
            @call(.always_tail, next, .{ i, s, loc, vals, fuel, int });
        }
    }

    pub fn br_if(i: *Instructions, s: *Stp, loc: u32, vals: *ValStack, fuel: *Fuel, int: *Interpreter) void {
        const c = vals.pop().i32;
        // std.debug.print(" > (br_if) {}?\n", .{c != 0});
        if (c != 0) {
            // No need to read LEB128 branch target
            int.takeBranch(i.p - 1, i, s, vals, 0);
        } else {
            _ = i.readUleb128(u32) catch unreachable;
            s.* += 1;
        }

        std.debug.assert(loc <= vals.items.len);
        if (i.nextOpcodeHandler(fuel, int)) |next| {
            @call(.always_tail, next, .{ i, s, loc, vals, fuel, int });
        }
    }

    pub fn br_table(i: *Instructions, s: *Stp, loc: u32, vals: *ValStack, fuel: *Fuel, int: *Interpreter) void {
        const base_ip = i.p - 1;
        const label_count = i.readUleb128(u32) catch unreachable;

        // No need to read LEB128 labels

        const n: u32 = @bitCast(vals.pop().i32);

        // std.debug.print(" > br_table [{}]\n", .{n});

        int.takeBranch(base_ip, i, s, vals, @min(n, label_count));

        std.debug.assert(loc <= vals.items.len);
        if (i.nextOpcodeHandler(fuel, int)) |next| {
            @call(.always_tail, next, .{ i, s, loc, vals, fuel, int });
        }
    }

    fn @"return"(i: *Instructions, s: *Stp, loc: u32, vals: *ValStack, fuel: *Fuel, int: *Interpreter) void {
        @call(.always_tail, returnFromWasm, .{ i, s, loc, vals, fuel, int });
    }

    pub fn call(i: *Instructions, s: *Stp, loc: u32, vals: *ValStack, fuel: *Fuel, int: *Interpreter) void {
        _ = s;
        const func_idx = i.nextIdx(Module.FuncIdx);
        const callee = int.currentFrame().function.expanded().wasm.module.funcAddr(func_idx);
        invokeWithinWasm(callee, loc, vals, fuel, int);
    }

    pub fn call_indirect(i: *Instructions, s: *Stp, loc: u32, vals: *ValStack, fuel: *Fuel, int: *Interpreter) void {
        _ = s;
        const current_module = int.currentFrame().function.expanded().wasm.module;

        const expected_signature = i.nextIdx(Module.TypeIdx).funcType(current_module.module);
        const table_idx = i.nextIdx(Module.TableIdx);

        const elem_index: u32 = @bitCast(vals.pop().i32);

        const table_addr = current_module.tableAddr(table_idx);
        std.debug.assert(table_addr.elem_type == .funcref);
        const table = table_addr.table;

        if (table.len <= elem_index) {
            int.state = .{ .trapped = .table_access_out_of_bounds };
            return;
        }

        const callee = table.base.func_ref[0..table.len][elem_index].funcInst() orelse {
            int.state = .{ .trapped = .indirect_call_to_null };
            return;
        };

        if (!expected_signature.matches(callee.signature())) {
            int.state = .{ .trapped = .indirect_call_signature_mismatch };
            return;
        }

        invokeWithinWasm(callee, loc, vals, fuel, int);
    }

    pub fn drop(i: *Instructions, s: *Stp, loc: u32, vals: *ValStack, fuel: *Fuel, int: *Interpreter) void {
        _ = vals.pop();

        std.debug.assert(loc <= vals.items.len);
        if (i.nextOpcodeHandler(fuel, int)) |next| {
            @call(.always_tail, next, .{ i, s, loc, vals, fuel, int });
        }
    }

    pub fn select(i: *Instructions, s: *Stp, loc: u32, vals: *ValStack, fuel: *Fuel, int: *Interpreter) void {
        const c = vals.pop().i32;
        if (c == 0) {
            vals.items[vals.items.len - 2] = vals.items[vals.items.len - 1];
        }

        _ = vals.pop();

        std.debug.assert(loc <= vals.items.len);
        if (i.nextOpcodeHandler(fuel, int)) |next| {
            @call(.always_tail, next, .{ i, s, loc, vals, fuel, int });
        }
    }

    // select t

    pub fn @"local.get"(i: *Instructions, s: *Stp, loc: u32, vals: *ValStack, fuel: *Fuel, int: *Interpreter) void {
        const n = i.readUleb128(u32) catch unreachable;
        const value = vals.items[loc..][n];
        vals.appendAssumeCapacity(value);

        // std.debug.print(" > (local.get {}) (i64.const {})\n", .{ n, value.i64 });

        if (i.nextOpcodeHandler(fuel, int)) |next| {
            @call(.always_tail, next, .{ i, s, loc, vals, fuel, int });
        }
    }

    pub fn @"local.set"(i: *Instructions, s: *Stp, loc: u32, vals: *ValStack, fuel: *Fuel, int: *Interpreter) void {
        const n = i.readUleb128(u32) catch unreachable;
        const value = vals.pop();
        vals.items[loc..][n] = value;

        std.debug.assert(loc <= vals.items.len);
        if (i.nextOpcodeHandler(fuel, int)) |next| {
            @call(.always_tail, next, .{ i, s, loc, vals, fuel, int });
        }
    }

    pub fn @"local.tee"(i: *Instructions, s: *Stp, loc: u32, vals: *ValStack, fuel: *Fuel, int: *Interpreter) void {
        const n = i.readUleb128(u32) catch unreachable;
        vals.items[loc..][n] = vals.items[vals.items.len - 1];

        std.debug.assert(loc <= vals.items.len);
        if (i.nextOpcodeHandler(fuel, int)) |next| {
            @call(.always_tail, next, .{ i, s, loc, vals, fuel, int });
        }
    }

    // global.get/set

    // table.get/set

    pub const @"i32.load" = linearMemoryHandlers("i32").load;
    pub const @"i64.load" = linearMemoryHandlers("i64").load;
    pub const @"f32.load" = linearMemoryHandlers("f32").load;
    pub const @"f64.load" = linearMemoryHandlers("f64").load;
    pub const @"i32.load8_s" = extendingLinearMemoryLoad("i32", i8).handler;
    pub const @"i32.load8_u" = extendingLinearMemoryLoad("i32", u8).handler;
    pub const @"i32.load16_s" = extendingLinearMemoryLoad("i32", i16).handler;
    pub const @"i32.load16_u" = extendingLinearMemoryLoad("i32", u16).handler;
    pub const @"i64.load8_s" = extendingLinearMemoryLoad("i64", i8).handler;
    pub const @"i64.load8_u" = extendingLinearMemoryLoad("i64", u8).handler;
    pub const @"i64.load16_s" = extendingLinearMemoryLoad("i64", i16).handler;
    pub const @"i64.load16_u" = extendingLinearMemoryLoad("i64", u16).handler;
    pub const @"i64.load32_s" = extendingLinearMemoryLoad("i64", i32).handler;
    pub const @"i64.load32_u" = extendingLinearMemoryLoad("i64", u32).handler;
    pub const @"i32.store" = linearMemoryHandlers("i32").store;
    pub const @"i64.store" = linearMemoryHandlers("i64").store;
    pub const @"f32.store" = linearMemoryHandlers("f32").store;
    pub const @"f64.store" = linearMemoryHandlers("f64").store;
    pub const @"i32.store8" = narrowingLinearMemoryStore("i32", 8).handler;
    pub const @"i32.store16" = narrowingLinearMemoryStore("i32", 16).handler;
    pub const @"i64.store8" = narrowingLinearMemoryStore("i64", 8).handler;
    pub const @"i64.store16" = narrowingLinearMemoryStore("i64", 16).handler;
    pub const @"i64.store32" = narrowingLinearMemoryStore("i64", 32).handler;

    pub const @"i32.const" = i32_opcode_handlers.@"const";
    pub const @"i64.const" = i64_opcode_handlers.@"const";
    pub const @"f32.const" = f32_opcode_handlers.@"const";
    pub const @"f64.const" = f64_opcode_handlers.@"const";

    pub const @"i32.eqz" = i32_opcode_handlers.eqz;
    pub const @"i32.eq" = i32_opcode_handlers.eq;
    pub const @"i32.ne" = i32_opcode_handlers.ne;
    pub const @"i32.lt_s" = i32_opcode_handlers.lt_s;
    pub const @"i32.lt_u" = i32_opcode_handlers.lt_u;
    pub const @"i32.gt_s" = i32_opcode_handlers.gt_s;
    pub const @"i32.gt_u" = i32_opcode_handlers.gt_u;
    pub const @"i32.le_s" = i32_opcode_handlers.le_s;
    pub const @"i32.le_u" = i32_opcode_handlers.le_u;
    pub const @"i32.ge_s" = i32_opcode_handlers.ge_s;
    pub const @"i32.ge_u" = i32_opcode_handlers.ge_u;

    pub const @"i64.eqz" = i64_opcode_handlers.eqz;
    pub const @"i64.eq" = i64_opcode_handlers.eq;
    pub const @"i64.ne" = i64_opcode_handlers.ne;
    pub const @"i64.lt_s" = i64_opcode_handlers.lt_s;
    pub const @"i64.lt_u" = i64_opcode_handlers.lt_u;
    pub const @"i64.gt_s" = i64_opcode_handlers.gt_s;
    pub const @"i64.gt_u" = i64_opcode_handlers.gt_u;
    pub const @"i64.le_s" = i64_opcode_handlers.le_s;
    pub const @"i64.le_u" = i64_opcode_handlers.le_u;
    pub const @"i64.ge_s" = i64_opcode_handlers.ge_s;
    pub const @"i64.ge_u" = i64_opcode_handlers.ge_u;

    pub const @"i32.clz" = i32_opcode_handlers.clz;
    pub const @"i32.ctz" = i32_opcode_handlers.ctz;
    pub const @"i32.popcnt" = i32_opcode_handlers.popcnt;
    pub const @"i32.add" = i32_opcode_handlers.add;
    pub const @"i32.sub" = i32_opcode_handlers.sub;
    pub const @"i32.mul" = i32_opcode_handlers.mul;
    pub const @"i32.div_s" = i32_opcode_handlers.div_s;
    pub const @"i32.div_u" = i32_opcode_handlers.div_u;
    pub const @"i32.rem_s" = i32_opcode_handlers.rem_s;
    pub const @"i32.rem_u" = i32_opcode_handlers.rem_u;
    pub const @"i32.and" = i32_opcode_handlers.@"and";
    pub const @"i32.or" = i32_opcode_handlers.@"or";
    pub const @"i32.xor" = i32_opcode_handlers.xor;
    pub const @"i32.shl" = i32_opcode_handlers.shl;
    pub const @"i32.shr_s" = i32_opcode_handlers.shr_s;
    pub const @"i32.shr_u" = i32_opcode_handlers.shr_u;
    pub const @"i32.rotl" = i32_opcode_handlers.rotl;
    pub const @"i32.rotr" = i32_opcode_handlers.rotr;

    pub const @"i64.clz" = i64_opcode_handlers.clz;
    pub const @"i64.ctz" = i64_opcode_handlers.ctz;
    pub const @"i64.popcnt" = i64_opcode_handlers.popcnt;
    pub const @"i64.add" = i64_opcode_handlers.add;
    pub const @"i64.sub" = i64_opcode_handlers.sub;
    pub const @"i64.mul" = i64_opcode_handlers.mul;
    pub const @"i64.div_s" = i64_opcode_handlers.div_s;
    pub const @"i64.div_u" = i64_opcode_handlers.div_u;
    pub const @"i64.rem_s" = i64_opcode_handlers.rem_s;
    pub const @"i64.rem_u" = i64_opcode_handlers.rem_u;
    pub const @"i64.and" = i64_opcode_handlers.@"and";
    pub const @"i64.or" = i64_opcode_handlers.@"or";
    pub const @"i64.xor" = i64_opcode_handlers.xor;
    pub const @"i64.shl" = i64_opcode_handlers.shl;
    pub const @"i64.shr_s" = i64_opcode_handlers.shr_s;
    pub const @"i64.shr_u" = i64_opcode_handlers.shr_u;
    pub const @"i64.rotl" = i64_opcode_handlers.rotl;
    pub const @"i64.rotr" = i64_opcode_handlers.rotr;

    const conv_ops = struct {
        fn @"i32.wrap_i64"(i: i64) !i32 {
            return @truncate(i);
        }

        fn @"i64.extend_i32_s"(i: i32) !i64 {
            return i;
        }

        fn @"i64.extend_i32_u"(i: i32) !i64 {
            return @bitCast(@as(u64, @as(u32, @bitCast(i))));
        }

        fn @"f32.demote_f64"(z: f64) !f32 {
            return @floatCast(z);
        }

        fn @"f64.promote_f32"(z: f32) !f64 {
            return z;
        }
    };

    fn reinterpretOp(comptime Dst: type) type {
        return struct {
            fn op(src: anytype) !Dst {
                return @bitCast(src);
            }
        };
    }

    pub const @"i32.wrap_i64" = defineConvOp("i64", "i32", conv_ops.@"i32.wrap_i64", undefined).handler;
    pub const @"i32.trunc_f32_s" = i32_opcode_handlers.trunc_f32_s;
    pub const @"i32.trunc_f32_u" = i32_opcode_handlers.trunc_f32_u;
    pub const @"i32.trunc_f64_s" = i32_opcode_handlers.trunc_f64_s;
    pub const @"i32.trunc_f64_u" = i32_opcode_handlers.trunc_f64_u;
    pub const @"i64.extend_i32_s" = defineConvOp("i32", "i64", conv_ops.@"i64.extend_i32_s", undefined).handler;
    pub const @"i64.extend_i32_u" = defineConvOp("i32", "i64", conv_ops.@"i64.extend_i32_u", undefined).handler;
    pub const @"i64.trunc_f32_s" = i64_opcode_handlers.trunc_f32_s;
    pub const @"i64.trunc_f32_u" = i64_opcode_handlers.trunc_f32_u;
    pub const @"i64.trunc_f64_s" = i64_opcode_handlers.trunc_f64_s;
    pub const @"i64.trunc_f64_u" = i64_opcode_handlers.trunc_f64_u;
    pub const @"f32.convert_i32_s" = f32_opcode_handlers.convert_i32_s;
    pub const @"f32.convert_i32_u" = f32_opcode_handlers.convert_i32_u;
    pub const @"f32.convert_i64_s" = f32_opcode_handlers.convert_i64_s;
    pub const @"f32.convert_i64_u" = f32_opcode_handlers.convert_i64_u;
    pub const @"f32.demote_f64" = defineConvOp("f64", "f32", conv_ops.@"f32.demote_f64", undefined).handler;
    pub const @"f64.convert_i32_s" = f64_opcode_handlers.convert_i32_s;
    pub const @"f64.convert_i32_u" = f64_opcode_handlers.convert_i32_u;
    pub const @"f64.convert_i64_s" = f64_opcode_handlers.convert_i64_s;
    pub const @"f64.convert_i64_u" = f64_opcode_handlers.convert_i64_u;
    pub const @"f64.promote_f32" = defineConvOp("f32", "f64", conv_ops.@"f64.promote_f32", undefined).handler;
    pub const @"i32.reinterpret_f32" = defineConvOp("f32", "i32", reinterpretOp(i32).op, undefined).handler;
    pub const @"i64.reinterpret_f64" = defineConvOp("f64", "i64", reinterpretOp(i64).op, undefined).handler;
    pub const @"f32.reinterpret_i32" = defineConvOp("i32", "f32", reinterpretOp(f32).op, undefined).handler;
    pub const @"f64.reinterpret_i64" = defineConvOp("i64", "f64", reinterpretOp(f64).op, undefined).handler;

    fn intSignExtend(comptime I: type, comptime M: type) type {
        std.debug.assert(@bitSizeOf(M) < @bitSizeOf(I));
        return struct {
            fn op(i: I) I {
                const j: I = @mod(i, @as(I, 1 << @bitSizeOf(M)));
                return @as(M, @truncate(j));
            }
        };
    }

    pub const @"i32.extend8_s" = defineUnOp("i32", intSignExtend(i32, i8).op).handler;
    pub const @"i32.extend16_s" = defineUnOp("i32", intSignExtend(i32, i16).op).handler;
    pub const @"i64.extend8_s" = defineUnOp("i64", intSignExtend(i64, i8).op).handler;
    pub const @"i64.extend16_s" = defineUnOp("i64", intSignExtend(i64, i16).op).handler;
    pub const @"i64.extend32_s" = defineUnOp("i64", intSignExtend(i64, i32).op).handler;

    pub const @"0xFC" = fc_prefixed_dispatch.handler;
    pub const @"i32.trunc_sat_f32_s" = i32_opcode_handlers.trunc_sat_f32_s;
    pub const @"i32.trunc_sat_f32_u" = i32_opcode_handlers.trunc_sat_f32_u;
    pub const @"i32.trunc_sat_f64_s" = i32_opcode_handlers.trunc_sat_f64_s;
    pub const @"i32.trunc_sat_f64_u" = i32_opcode_handlers.trunc_sat_f64_u;
    pub const @"i64.trunc_sat_f32_s" = i64_opcode_handlers.trunc_sat_f32_s;
    pub const @"i64.trunc_sat_f32_u" = i64_opcode_handlers.trunc_sat_f32_u;
    pub const @"i64.trunc_sat_f64_s" = i64_opcode_handlers.trunc_sat_f64_s;
    pub const @"i64.trunc_sat_f64_u" = i64_opcode_handlers.trunc_sat_f64_u;
};

/// If the handler is not appearing in this table, make sure it is public first.
const byte_dispatch_table = dispatchTable(opcodes.ByteOpcode, opcode_handlers.invalid);

/// Given a WASM function at the top of the call stack, resumes execution.
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
