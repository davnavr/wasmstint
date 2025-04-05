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

const ExternRef = extern struct {
    addr: runtime.ExternAddr,
    padding: enum(usize) {
        zero = 0,
    } = .zero,
};

const Value = extern union {
    i32: i32,
    f32: f32,
    i64: i64,
    f64: f64,
    externref: ExternRef,
    funcref: FuncRef,

    comptime {
        std.debug.assert(@sizeOf(Value) == switch (@sizeOf(*anyopaque)) {
            4 => 8, // 16 if support for  v128 is added
            8 => 16,
            else => unreachable,
        });
    }
};

pub const TaggedValue = union(enum) {
    i32: i32,
    f32: f32,
    i64: i64,
    f64: f64,
    externref: runtime.ExternAddr,
    funcref: FuncRef,

    comptime {
        std.debug.assert(@sizeOf(TaggedValue) == switch (@sizeOf(*anyopaque)) {
            4 => 12,
            8 => 24,
            else => unreachable,
        });
    }

    pub fn value_type(tagged: *const TaggedValue) Module.ValType {
        return switch (@as(std.meta.Tag(TaggedValue), tagged.*)) {
            inline else => |tag| @field(Module.ValType, @tagName(tag)),
        };
    }

    fn untagged(tagged: *const TaggedValue) Value {
        return switch (@as(std.meta.Tag(TaggedValue), tagged.*)) {
            .externref => .{ .externref = .{ .addr = tagged.externref } },
            inline else => |tag| @unionInit(
                Value,
                @tagName(tag),
                @field(tagged, @tagName(tag)),
            ),
        };
    }

    pub fn initInferred(value: anytype) TaggedValue {
        const T = @TypeOf(value);

        if (@typeInfo(T) == .pointer) {
            if (@typeInfo(T).pointer.size != .one)
                @compileError("unsupported value pointer type " ++ @typeName(T));

            return initInferred(value.*);
        }

        return switch (T) {
            i32, u32 => .{ .i32 = @bitCast(value) },
            i64, u64 => .{ .i64 = @bitCast(value) },
            f32 => .{ .f32 = value },
            f64 => .{ .f64 = value },
            runtime.ExternAddr => .{ .externref = value },
            FuncRef => .{ .funcref = value },
            runtime.FuncAddr => .{ .funcref = @bitCast(value) },
            else => switch (@typeInfo(T)) {
                .int => @compileError("unsupported integer value type " ++ @typeName(T)),
                .float => @compileError("unsupported float value type " ++ @typeName(T)),
                else => @compileError("unrecognized value type" ++ @typeName(T)),
            },
        };
    }

    pub fn format(
        value: *const TaggedValue,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        try writer.writeByte('(');
        switch (value.*) {
            inline .i32, .i64 => |i| {
                try writer.writeAll(@tagName(value.*));
                try writer.writeAll(".const ");
                try std.fmt.formatIntValue(i, fmt, options, writer);
            },
            inline .f32, .f64 => |z| {
                try writer.writeAll(@tagName(value.*));
                try writer.writeAll(".const ");
                if (fmt.len == 0) {
                    if (std.math.isPositiveZero(z) or
                        std.math.isNegativeZero(z) or
                        std.math.isInf(z))
                    {
                        try writer.print("{}", .{z});
                    } else {
                        try writer.print("{} (;{};)", .{
                            z,
                            @as(
                                std.meta.Int(.unsigned, @bitSizeOf(@TypeOf(z))),
                                @bitCast(z),
                            ),
                        });
                    }
                } else {
                    try std.fmt.formatFloatValue(z.*, fmt, options, writer);
                }
            },
            inline .funcref, .externref => |*ref| {
                try ref.format(fmt, options, writer);
            },
        }
        try writer.writeByte(')');
    }

    fn formatSlice(
        values: []const TaggedValue,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        if (values.len == 1) {
            try values[0].format(fmt, options, writer);
        } else {
            for (0.., values) |i, val| {
                if (i > 0) {
                    try writer.writeByte(' ');
                }

                try val.format(fmt, options, writer);
            }
        }
    }

    pub fn sliceFormatter(values: []const TaggedValue) std.fmt.Formatter(formatSlice) {
        return std.fmt.Formatter(formatSlice){ .data = values };
    }
};

const Ip = Module.Code.Ip;
const Eip = *const Module.Code.End;
const Stp = [*]const Module.Code.SideTableEntry;

pub const StackFrame = extern struct {
    function: runtime.FuncAddr,
    /// These fields must only be used in WASM functions.
    wasm: extern struct {
        instructions: Instructions,
        branch_table: Stp,
    },
    /// The total space taken by parameters, local variables, and values in the interpreter's
    /// `value_stack`.
    ///
    /// When a host function is called, this is set to the number of parameters.
    values_count: u16,
    /// The number of return values this function has.
    result_count: u16,
    /// The index into the `value_stack` at which local variables (specifically its parameters)
    /// begin.
    ///
    /// The length of the value stack to restore when returning from this function is equal to this
    /// value.
    values_base: u32,
    instantiate_flag: *bool,

    // TODO: What if call stack was an "unrolled linked list" or something like std.SegmentedList?
    // - to ensure quick access to top, store ptr to current top of call stack
    // - allows allocator to reuse space instead of having a big block that needs resizing

    /// Asserts that the current `frame` is of a WASM function.
    fn currentModule(frame: *const StackFrame) runtime.ModuleInst {
        return frame.function.expanded().wasm.module;
    }
};

const ValStack = std.ArrayListUnmanaged(Value);

/// For every WASM stack frame, calculates a hash of the value stack and the called function.
///
/// This is used to detect bugs in debug mode where the value stacks of functions are incorrectly
/// modified.
const HashStack = struct {
    const enabled = builtin.mode == .Debug;

    const Hashes = std.SegmentedList(u64, 4);

    inner: if (enabled)
        Hashes
    else
        void,

    fn init(alloca: Allocator, capacity: usize) Allocator.Error!HashStack {
        if (enabled) {
            var entries = Hashes{};
            if (Hashes.prealloc_count < capacity)
                try entries.setCapacity(alloca, capacity);

            return .{ .inner = entries };
        } else return .{ .inner = {} };
    }

    fn clearRetainingCapacity(stack: *HashStack) void {
        if (enabled)
            stack.inner.clearRetainingCapacity();
    }

    fn prevHash(stack: *const HashStack) u64 {
        return if (stack.inner.len == 0)
            0
        else
            stack.inner.at(stack.inner.len - 1).*;
    }

    fn hash(
        prev_hash: u64,
        frame: *const StackFrame,
        values: []const Value,
        values_end: u32,
    ) u64 {
        var hasher = std.hash.XxHash64.init(prev_hash);
        std.debug.assert(frame.function.expanded() == .wasm);

        // Note that padding bytes might get inadvertently hashed, but since those values shouldn't
        // be modified anyway, it should be fine.
        hasher.update(std.mem.asBytes(frame));
        hasher.update(std.mem.sliceAsBytes(values[frame.values_base..values_end]));

        return hasher.final();
    }

    /// Pushes a hash onto the stack for a WASM function that is no longer on the top of the call stack.
    ///
    /// Note that the values should exclude the top values used as function parameters.
    fn push(
        stack: *HashStack,
        alloca: Allocator,
        frame: *const StackFrame,
        values: []const Value,
        values_end: u32,
    ) Allocator.Error!void {
        if (!enabled) return;

        const prev_hash = stack.prevHash();
        const new_hash = try stack.inner.addOne(alloca);
        errdefer comptime unreachable;
        new_hash.* = hash(prev_hash, frame, values, values_end);
    }

    /// Asserts that the WASM function that is now the top of the call stack did not have
    /// its value stack and local variables modified.
    fn pop(
        stack: *HashStack,
        frame: *const StackFrame,
        values: []const Value,
        values_end: u32,
    ) void {
        if (!enabled) return;

        const expected_hash: u64 = stack.inner.pop().?;
        const actual_hash: u64 = hash(stack.prevHash(), frame, values, values_end);
        if (expected_hash != actual_hash) {
            std.debug.panic(
                "bad function hash: expected 0x{X:0>16}, got 0x{X:0>16}",
                .{
                    expected_hash,
                    actual_hash,
                },
            );
        }
    }
};

value_stack: ValStack,
call_stack: std.ArrayListUnmanaged(StackFrame),
hash_stack: HashStack,
state: State = State.initial,
dummy_instantiate_flag: bool = false,

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
        .hash_stack = try HashStack.init(alloca, options.call_stack_capacity),
    };
}

pub const Trap = struct {
    /// Describes the kind of trap that occurred.
    ///
    /// Hosts can specify their own codes in the negative range.
    pub const Code = enum(i32) {
        unreachable_code_reached = 0,
        /// The function did not contain valid WebAssembly.
        ///
        /// See <https://webassembly.github.io/spec/core/appendix/implementation.html#validation> for more
        /// information.
        lazy_validation_failure = 1,
        integer_division_by_zero = 2,
        integer_overflow = 3,
        invalid_conversion_to_integer = 4,
        memory_access_out_of_bounds = 5,
        table_access_out_of_bounds = 6,
        indirect_call_to_null = 7,
        indirect_call_signature_mismatch = 8,
        _,

        pub fn initHost(code: u31) Code {
            return @enumFromInt(-@as(i31, code) - 1);
        }

        pub fn host(code: Code) ?u31 {
            return if (code < 0) @intCast(-(@intFromEnum(code) + 1)) else null;
        }
    };

    code: Code,
    information: Information,

    pub const Information = union {
        indirect_call_to_null: struct {
            index: usize,
        },
        lazy_validation_failure: struct {
            function: Module.FuncIdx,
        },
    };

    fn InformationType(comptime code: Code) type {
        return if (@hasField(Information, @tagName(code)))
            @FieldType(Information, @tagName(code))
        else
            void;
    }

    fn init(comptime code: Code, information: InformationType(code)) Trap {
        return Trap{
            .code = code,
            .information = if (@hasField(Information, @tagName(code)))
                @unionInit(Information, @tagName(code), information)
            else
                undefined,
        };
    }

    fn initIntegerOverflow(e: error{Overflow}) Trap {
        return switch (e) {
            error.Overflow => Trap.init(.integer_overflow, {}),
        };
    }

    fn initIntegerDivisionByZero(e: error{DivisionByZero}) Trap {
        return switch (e) {
            error.DivisionByZero => Trap.init(.integer_division_by_zero, {}),
        };
    }

    fn initSignedIntegerDivision(e: error{ Overflow, DivisionByZero }) Trap {
        return switch (e) {
            error.Overflow => Trap.init(.integer_overflow, {}),
            error.DivisionByZero => Trap.init(.integer_division_by_zero, {}),
        };
    }

    fn initTrunc(e: error{ Overflow, NotANumber }) Trap {
        return switch (e) {
            error.Overflow => Trap.init(.integer_overflow, {}),
            error.NotANumber => Trap.init(.invalid_conversion_to_integer, {}),
        };
    }

    fn initHostCode(code: u31) Trap {
        return .{
            .code = @enumFromInt(-@as(i32, code) - 1),
            .information = undefined,
        };
    }

    fn toHostCode(trap: *const Trap) ?u31 {
        const code: i32 = @intFromEnum(trap.code);
        return if (code < 0) @intCast(-(code + 1)) else null;
    }
};

pub const InterruptionCause = union(enum) {
    out_of_fuel,
    memory_grow: MemoryGrow,
    table_grow: TableGrow,

    pub const MemoryGrow = struct {
        memory: *runtime.MemInst,
        /// The amount to increase the size of the memory by, in bytes.
        delta: usize,

        /// Returns the old memory buffer, or `null` if the same base address was passed.
        ///
        /// Asserts that the size of the memory's buffer does not exceed its `limit`.
        pub fn resize(
            grow: *const MemoryGrow,
            new: []align(runtime.MemInst.buffer_align) u8,
        ) ?[]align(runtime.MemInst.buffer_align) u8 {
            std.debug.assert(new.len <= grow.memory.limit);
            std.debug.assert(new.len % runtime.MemInst.buffer_align == 0);
            std.debug.assert(grow.memory.capacity <= new.len);

            const prev_mem = if (@intFromPtr(grow.memory.base) != @intFromPtr(new.ptr)) moved: {
                @memcpy(new[0..grow.memory.size], grow.memory.bytes());
                const old_mem = grow.memory.base[0..grow.memory.capacity];
                grow.memory.base = new.ptr;
                break :moved old_mem;
            } else null;

            @memset(grow.memory.base[grow.memory.size..new.len], 0);

            grow.memory.capacity = @max(grow.memory.capacity, new.len);
            return prev_mem;
        }
    };

    pub const TableGrow = struct {
        table: runtime.TableAddr,
        elem: Value,
        /// The amount to increase the size of the table by, in elements.
        delta: u32,

        /// Returns the old table buffer, or `null` if the same base address was passed.
        ///
        /// Asserts that the size of the table's buffer does not exceed its `limit`.
        pub fn resize(
            grow: *const TableGrow,
            new: []align(runtime.TableInst.buffer_align) u8,
        ) ?[]align(runtime.TableInst.buffer_align) u8 {
            const table = grow.table.table;
            const stride = table.stride.toBytes();
            const new_len: u32 = @intCast(@divExact(new.len, stride));
            std.debug.assert(new_len <= table.limit);
            std.debug.assert(table.capacity <= new_len);

            const prev_table = if (@intFromPtr(table.base.ptr) != @intFromPtr(new.ptr)) moved: {
                @memcpy(new[0 .. table.len * stride], table.bytes());
                const old_mem = table.base.ptr[0 .. @as(usize, table.capacity) * stride];
                table.base.ptr = new.ptr;
                break :moved old_mem;
            } else null;

            table.capacity = @max(table.capacity, new_len);
            table.fillWithinCapacity(
                std.mem.asBytes(&grow.elem)[0..stride],
                table.len,
                table.capacity,
            );

            return prev_table;
        }
    };
};

pub const State = union(enum) {
    awaiting_host: AwaitingHost,
    awaiting_validation: AwaitingValidation,
    call_stack_exhaustion: CallStackExhaustion,
    interrupted: Interrupted,
    /// The computation was aborted due to a *trap*. The call stack of the interpreter can be
    /// inspected to determine where and when the trap occurred.
    ///
    /// Note that in the case of a *trap* occurring during module *instantation* (before the
    /// *start* function is invoked), no stack frame will be recorded.
    trapped: Trap,
    // unhandled_exception: Exception,

    fn stateInterpreterPtr(
        self: anytype,
    ) (if (@typeInfo(@TypeOf(self)).pointer.is_const) *const Interpreter else *Interpreter) {
        const Self = @typeInfo(@TypeOf(self)).pointer.child;
        const state: *State = state: inline for (@typeInfo(State).@"union".fields) |field| {
            if (field.type == Self) {
                break :state @fieldParentPtr(field.name, @constCast(self));
            }
        } else @compileError(@typeName(Self) ++ " is not a State struct");

        return @fieldParentPtr("state", state);
    }

    /// Either WASM code is ready to be interpreted, or WASM code is awaiting the results of
    /// calling a host function.
    pub const AwaitingHost = struct {
        /// The types of the values at the top of the value stack, which are the results of the most
        /// recently called function or the parameters passed to a host function.
        types: []const Module.ValType,

        const interpreter = State.stateInterpreterPtr;

        pub fn copyValues(
            self: *const AwaitingHost,
            arena: *std.heap.ArenaAllocator,
        ) Allocator.Error![]TaggedValue {
            const types = self.types;
            const dst = try arena.allocator().alloc(TaggedValue, types.len);
            const interp = self.interpreter();
            for (
                dst,
                types,
                interp.value_stack.items[interp.value_stack.items.len - types.len ..],
            ) |*tagged, result_type, *result| {
                tagged.* = switch (result_type) {
                    .v128 => unreachable, // Not implemented
                    .externref => TaggedValue{ .externref = result.externref.addr },
                    inline else => |tag| @unionInit(
                        TaggedValue,
                        @tagName(tag),
                        @field(result, @tagName(tag)),
                    ),
                };
            }

            return dst;
        }

        pub fn valuesTyped(
            self: *const AwaitingHost,
            comptime T: type,
        ) error{ValueTypeOrCountMismatch}!T {
            const result_fields = tuple: {
                switch (@typeInfo(T)) {
                    .@"struct" => |s| if (s.is_tuple) break :tuple s.fields,
                    else => {},
                }

                @compileError("expect tuple, got " ++ @typeName(T));
            };

            const interp: *const Interpreter = self.interpreter();
            const types = self.types;
            var results: T = undefined;
            inline for (
                0..result_fields.len,
                result_fields,
                types,
                interp.value_stack.items[interp.value_stack.items.len - types.len ..],
            ) |i, *field, ty, *src| {
                results[i] = val: switch (field.type) {
                    i32, u32 => {
                        if (ty != .i32) return error.ValueTypeOrCountMismatch;
                        break :val src.i32;
                    },
                    i64, u64 => {
                        if (ty != .i64) return error.ValueTypeOrCountMismatch;
                        break :val src.i64;
                    },
                    f32 => {
                        if (ty != .f32) return error.ValueTypeOrCountMismatch;
                        break :val src.f32;
                    },
                    f64 => {
                        if (ty != .f64) return error.ValueTypeOrCountMismatch;
                        break :val src.f64;
                    },
                    runtime.ExternAddr => {
                        if (ty != .externref) return error.ValueTypeOrCountMismatch;
                        break :val src.externref.addr;
                    },
                    FuncRef => {
                        if (ty != .funcref) return error.ValueTypeOrCountMismatch;
                        break :val src.funcref;
                    },
                    else => @compileError("unsupported result type " ++ @typeName(field.type)),
                };
            }

            return results;
        }

        /// Begins the process of calling a function, allocating stack space.
        ///
        /// For a host function, this returns back to the caller, while a WASM function
        /// will enter the interpreter loop, returning when a `Trap` occurs or when `Interrupted`.
        ///
        /// Returns an error if `alloca` could not reserve enough space to execute the function.
        pub fn beginCall(
            self: *AwaitingHost,
            alloca: Allocator,
            callee: runtime.FuncAddr,
            arguments: []const TaggedValue,
            fuel: *Fuel,
        ) (error{ValueTypeOrCountMismatch} || Allocator.Error)!*State {
            const interp: *Interpreter = self.interpreter();
            const signature = callee.signature();
            if (arguments.len != signature.param_count) {
                return error.ValueTypeOrCountMismatch;
            }

            const saved_call_stack_len = interp.call_stack.items.len;
            try interp.call_stack.ensureUnusedCapacity(alloca, 1);
            errdefer interp.call_stack.items.len = saved_call_stack_len;

            const values_base: u32 = @intCast(interp.value_stack.items.len);
            const new_values_len = std.math.add(u32, values_base, signature.param_count) catch
                return error.OutOfMemory;

            try interp.value_stack.ensureTotalCapacity(alloca, new_values_len);
            errdefer interp.value_stack.items.len = values_base;

            try interp.call_stack.ensureUnusedCapacity(alloca, 1);

            for (arguments, signature.parameters()) |*arg, param_type| {
                if (param_type != arg.value_type())
                    return error.ValueTypeOrCountMismatch;

                interp.value_stack.appendAssumeCapacity(arg.untagged());
            }

            const setup = try interp.setupStackFrame(
                alloca,
                callee,
                values_base,
                signature,
                &interp.dummy_instantiate_flag,
            );

            errdefer comptime unreachable;

            switch (setup) {
                .wasm_validate => interp.state = .{ .awaiting_validation = .{} },
                .wasm_ready => interp.enterMainLoop(fuel),
                .host_ready => self.types = signature.parameters(),
            }

            return &interp.state;
        }

        /// Instantiates a module, beginning the process of invoking its start function (if it
        /// exists) as if passed to `.beginCall()`.
        pub fn instantiateModule(
            self: *AwaitingHost,
            alloca: Allocator,
            module: *runtime.ModuleAlloc,
            fuel: *Fuel,
        ) Allocator.Error!*State {
            const interp: *Interpreter = self.interpreter();
            const maybe_start = moduleInstantiationSetup(module) catch |e| {
                interp.state = .{
                    .trapped = switch (e) {
                        error.MemoryAccessOutOfBounds => Trap.init(
                            .memory_access_out_of_bounds,
                            {},
                        ),
                        error.TableAccessOutOfBounds => Trap.init(
                            .table_access_out_of_bounds,
                            {},
                        ),
                    },
                };
                return &interp.state;
            };

            if (maybe_start.funcInst()) |start| {
                std.debug.assert(!module.instantiated);
                std.debug.assert(start.signature().param_count == 0);
                std.debug.assert(start.signature().result_count == 0);

                const setup = try interp.setupStackFrame(
                    alloca,
                    start,
                    @intCast(interp.value_stack.items.len),
                    &Module.FuncType.empty,
                    &module.instantiated,
                );

                errdefer comptime unreachable;

                switch (setup) {
                    .wasm_validate => interp.state = .{ .awaiting_validation = .{} },
                    .wasm_ready => interp.enterMainLoop(fuel),
                    .host_ready => self.types = &[0]Module.ValType{},
                }

                return &interp.state;
            } else {
                std.debug.assert(module.instantiated);
                return &interp.state;
            }
        }

        pub fn currentHostFunction(
            self: *const AwaitingHost,
        ) ?*const runtime.FuncAddr.Expanded.Host {
            const interp: *const Interpreter = self.interpreter();
            if (interp.call_stack.items.len == 0)
                return null;

            return &interp.call_stack.items[interp.call_stack.items.len - 1]
                .function.expanded().host;
        }

        /// Return from the currently executing host function to the calling function, typically
        /// WASM code whose interpretation will continue with the given `fuel` amount.
        pub fn returnFromHost(
            self: *AwaitingHost,
            results: []const TaggedValue,
            fuel: *Fuel,
        ) error{ValueTypeOrCountMismatch}!*State {
            const interp: *Interpreter = self.interpreter();
            const popped = interp.currentFrame();
            const signature = popped.function.signature();

            if (results.len != signature.result_count)
                return error.ValueTypeOrCountMismatch;

            interp.call_stack.items.len -= 1;
            errdefer interp.call_stack.items.len += 1;

            const saved_value_stack_len = interp.value_stack.items.len;
            errdefer interp.value_stack.items.len = saved_value_stack_len;

            const results_dst = interp.value_stack
                .items[popped.values_base .. popped.values_base + popped.result_count];

            for (
                results,
                signature.results(),
                results_dst,
            ) |*src, result_type, *dst| {
                if (result_type != src.value_type())
                    return error.ValueTypeOrCountMismatch;

                dst.* = src.untagged();
            }

            interp.value_stack.items.len = popped.values_base + popped.result_count;

            errdefer comptime unreachable;

            popped.instantiate_flag.* = true;

            if (interp.call_stack.items.len > 0) {
                const current = interp.currentFrame();
                switch (current.function.expanded()) {
                    .wasm => {
                        interp.hash_stack.pop(
                            current,
                            interp.value_stack.items,
                            popped.values_base,
                        );
                        interp.enterMainLoop(fuel);
                    },
                    .host => self.types = signature.results(),
                }
            } else {
                self.types = signature.results();
            }

            return &interp.state;
        }

        pub fn returnFromHostTyped(
            self: *AwaitingHost,
            results: anytype,
            fuel: *Fuel,
        ) error{ValueTypeOrCountMismatch}!*State {
            if (@TypeOf(results) == void) {
                return self.returnFromHost(&[0]TaggedValue{}, fuel);
            }

            const results_len = len: {
                switch (@typeInfo(@TypeOf(results))) {
                    .@"struct" => |s| if (s.is_tuple) break :len s.fields.len,
                    else => {},
                }

                @compileError("expect result tuple, got " ++ @typeName(@TypeOf(results)));
            };

            var result_array: [results_len]TaggedValue = undefined;
            inline for (&result_array, results) |*dst, src| {
                dst.* = TaggedValue.initInferred(src);
            }

            return self.returnFromHost(&result_array, fuel);
        }

        pub fn trapWithHostCode(self: *AwaitingHost, code: u31) *State {
            const interp: *Interpreter = self.interpreter();
            interp.state = .{ .trapped = Trap.initHostCode(code) };
            return &interp.state;
        }
    };

    /// Indicates that a function to call needs to be validated, and once successful, allocate
    /// space for their local variables and value stack.
    pub const AwaitingValidation = struct {
        padding: enum(usize) { padding = 0 } = .padding,

        const interpreter = State.stateInterpreterPtr;

        // pub fn waitForLazyValidation(Timeout)

        pub fn validate(
            self: *AwaitingValidation,
            code_allocator: Allocator,
            scratch: *std.heap.ArenaAllocator,
            alloca: Allocator,
            fuel: *Fuel,
        ) *State {
            const interp: *Interpreter = self.interpreter();
            const current_frame = interp.currentFrame();

            const callee = current_frame.function;
            const function = callee.expanded().wasm;
            const code = function.code();
            const finished = code.validate(
                code_allocator,
                function.module.header().module,
                scratch,
            ) catch {
                interp.state = .{
                    .trapped = Trap.init(
                        .lazy_validation_failure,
                        .{ .function = function.idx },
                    ),
                };

                return &interp.state;
            };

            if (finished) {
                current_frame.wasm = .{
                    .instructions = Instructions.init(
                        code.inner.instructions_start,
                        code.inner.instructions_end,
                    ),
                    .branch_table = code.inner.side_table_ptr,
                };

                _ = interp.allocateValueStackSpace(alloca, &code.inner) catch {
                    interp.state = .{
                        .call_stack_exhaustion = .{
                            .callee = callee,
                            .values_base = @intCast(interp.value_stack.items.len),
                            .signature = callee.signature(),
                        },
                    };

                    return &interp.state;
                };

                interp.state = .{ .awaiting_host = .{ .types = &.{} } };
                interp.enterMainLoop(fuel);
            }

            return &interp.state;
        }
    };

    /// A call instruction required pushing a new stack frame, which required a reallocation of the
    /// `call_stack`.
    ///
    /// In this state, the IP of the current frame refers to the instruction after the call
    /// instruction, which will be executed next.
    pub const CallStackExhaustion = struct {
        // Parameters passed to `setupStackFrame`.
        callee: runtime.FuncAddr,
        values_base: u32,
        signature: *const Module.FuncType,

        const interpreter = State.stateInterpreterPtr;

        pub fn resumeExecution(
            self: *CallStackExhaustion,
            alloca: Allocator,
            fuel: *Fuel,
        ) Allocator.Error!*State {
            const args = self.*;
            const interp: *Interpreter = self.interpreter();
            const setup = try interp.setupStackFrame(
                alloca,
                args.callee,
                args.values_base,
                args.signature,
                &interp.dummy_instantiate_flag,
            );

            switch (setup) {
                .wasm_validate => interp.state = .{ .awaiting_validation = .{} },
                .wasm_ready => interp.enterMainLoop(fuel),
                .host_ready => interp.state = .{
                    .awaiting_host = .{
                        .types = args.signature.parameters(),
                    },
                },
            }

            return &interp.state;
        }
    };

    /// Execution of WASM bytecode was interrupted.
    ///
    /// The host can stop using the interpreter further, resume execution with more fuel by calling
    /// `.resumeExecution()`, or reuse the interpreter for a new computation after calling `.reset()`.
    ///
    /// In this state, the IP of the current frame refers to the instruction to execute next after
    /// the interrupt is handled.
    pub const Interrupted = struct {
        cause: InterruptionCause,

        const interpreter = State.stateInterpreterPtr;

        /// Resumes execution of WASM bytecode after being `interrupted`.
        ///
        /// Returns an error if an attempt to grow the call stack with `alloca` fails, in which case
        /// `resumeExecution` is allowed to be called again.
        pub fn resumeExecution(
            self: *Interrupted,
            fuel: *Fuel,
        ) *State {
            const cause = self.cause;
            const interp: *Interpreter = self.interpreter();
            switch (cause) {
                .out_of_fuel => {},
                .memory_grow => |grow| interp.value_stack.appendAssumeCapacity(Value{
                    .i32 = result: {
                        const old_len = grow.memory.size;
                        const new_len = std.math.add(
                            usize,
                            old_len,
                            grow.delta,
                        ) catch break :result -1;

                        if (@min(grow.memory.limit, grow.memory.capacity) < new_len)
                            break :result -1;

                        grow.memory.size = new_len;
                        break :result @bitCast(
                            @as(
                                u32,
                                @intCast(old_len / runtime.MemInst.page_size),
                            ),
                        );
                    },
                }),
                .table_grow => |grow| interp.value_stack.appendAssumeCapacity(Value{
                    .i32 = result: {
                        const table = grow.table.table;
                        const old_len = table.len;
                        const new_len = std.math.add(
                            u32,
                            old_len,
                            grow.delta,
                        ) catch break :result -1;

                        if (@min(table.limit, table.capacity) < new_len)
                            break :result -1;

                        table.len = new_len;
                        break :result @bitCast(old_len);
                    },
                }),
            }

            interp.enterMainLoop(fuel);
            return &interp.state;
        }
    };

    pub const initial = State{
        .awaiting_host = .{ .types = &[0]Module.ValType{} },
    };
};

/// Performs the steps of module instantiation up to but excluding the invocation of the *start*
/// function, which is returned.
fn moduleInstantiationSetup(
    module: *runtime.ModuleAlloc,
) (runtime.MemInst.OobError || runtime.TableInst.OobError)!FuncRef {
    const module_inst = module.requiring_instantiation.header();
    const wasm = module_inst.module;
    const global_types = wasm.globalTypes()[wasm.inner.global_import_count..];
    for (
        wasm.inner.global_exprs[0..global_types.len],
        module_inst.definedGlobalValues(),
        global_types,
    ) |*init_expr, global_value, *global_type| {
        switch (init_expr.*) {
            .i32_or_f32 => |n32| {
                std.debug.assert(global_type.val_type == .i32 or global_type.val_type == .f32);
                @as(*u32, @ptrCast(@alignCast(global_value))).* = n32;
            },
            .i64_or_f64 => |n64| {
                std.debug.assert(global_type.val_type == .i64 or global_type.val_type == .f64);
                @as(*u64, @ptrCast(@alignCast(global_value))).* = n64.get(wasm.arena_data);
            },
            .@"ref.null" => |ref_type| {
                std.debug.assert(ref_type == global_type.val_type);
                switch (ref_type) {
                    .funcref => {
                        @as(*runtime.FuncAddr.Nullable, @ptrCast(@alignCast(global_value))).* = .null;
                    },
                    .externref => {
                        @as(*runtime.ExternAddr, @ptrCast(@alignCast(global_value))).* = .null;
                    },
                    else => unreachable,
                }
            },
            .@"ref.func" => |func_idx| {
                @as(*runtime.FuncAddr.Nullable, @ptrCast(@alignCast(global_value))).* =
                    @bitCast(@as(runtime.FuncAddr, module_inst.funcAddr(func_idx)));
            },
            .@"global.get" => |src_global| {
                const src_addr = module_inst.globalAddr(src_global);
                std.debug.assert(src_addr.global_type.val_type == global_type.val_type);

                const src: *const anyopaque = module_inst.globalAddr(src_global).value;
                switch (global_type.val_type) {
                    .i32, .f32 => {
                        @as(*u32, @ptrCast(@alignCast(global_value))).* =
                            @as(*const u32, @ptrCast(@alignCast(src))).*;
                    },
                    .i64, .f64 => {
                        @as(*u64, @ptrCast(@alignCast(global_value))).* =
                            @as(*const u64, @ptrCast(@alignCast(src))).*;
                    },
                    .funcref => {
                        @as(*runtime.FuncAddr.Nullable, @ptrCast(@alignCast(global_value))).* =
                            @as(*const runtime.FuncAddr.Nullable, @ptrCast(@alignCast(src))).*;
                    },
                    .externref => {
                        @as(*runtime.ExternAddr, @ptrCast(@alignCast(global_value))).* =
                            @as(*const runtime.ExternAddr, @ptrCast(@alignCast(src))).*;
                    },
                    .v128 => unreachable,
                }
            },
        }
    }

    for (wasm.inner.active_elems[0..wasm.inner.active_elems_count]) |*active_elem| {
        const offset: u32 = offset: switch (active_elem.header.offset_tag) {
            .@"i32.const" => active_elem.offset.@"i32.const",
            .@"global.get" => {
                const global = module_inst.globalAddr(active_elem.offset.@"global.get");
                std.debug.assert(global.global_type.val_type == .i32);
                break :offset @as(*const u32, @ptrCast(@alignCast(global.value))).*;
            },
        };

        try runtime.TableInst.init(
            active_elem.header.table,
            module.requiring_instantiation,
            active_elem.header.elements,
            null,
            0,
            offset,
        );

        module_inst.elemSegmentDropFlag(active_elem.header.elements).drop();
    }

    for (wasm.inner.active_datas[0..wasm.inner.active_datas_count]) |*active_data| {
        const mem = module_inst.memAddr(active_data.header.memory);

        const offset: u32 = switch (active_data.header.offset_tag) {
            .@"i32.const" => active_data.offset.@"i32.const",
            .@"global.get" => get: {
                const global = module_inst.globalAddr(active_data.offset.@"global.get");
                std.debug.assert(global.global_type.val_type == .i32);
                break :get @as(*const u32, @ptrCast(@alignCast(global.value))).*;
            },
        };

        const src: []const u8 = module_inst.dataSegment(active_data.data);
        try mem.init(src, @intCast(src.len), 0, offset);

        module_inst.dataSegmentDropFlag(active_data.data).drop();
    }

    errdefer comptime unreachable;

    if (wasm.inner.start.get()) |start_idx|
        return @bitCast(module_inst.funcAddr(start_idx))
    else {
        module.instantiated = true;
        return .null;
    }
}

/// Reserves space for the value stack and local variables (that aren't parameters).
fn allocateValueStackSpace(
    interp: *Interpreter,
    alloca: Allocator,
    code: *const Module.Code.Inner,
) Allocator.Error!u16 {
    const total = std.math.add(
        u16,
        code.local_values,
        code.max_values,
    ) catch return error.OutOfMemory;

    try interp.value_stack.ensureUnusedCapacity(alloca, total);

    // In WebAssembly, locals are set to zero on entrance to a function.
    interp.value_stack.appendNTimes(
        undefined,
        std.mem.zeroes(Value),
        code.local_values,
    ) catch unreachable;

    const value_stack_base = interp.value_stack.items.len;
    @memset(interp.value_stack.items[value_stack_base..], undefined);

    // std.debug.print(
    //     "allocated {} entries: {} locals, {} for value stack (base height = {})\n",
    //     .{ total, code.local_values, code.max_values, value_stack_base },
    // );

    return total;
}

fn currentFrame(interp: *Interpreter) *StackFrame {
    return &interp.call_stack.items[interp.call_stack.items.len - 1];
}

const SetupStackFrame = enum {
    wasm_ready,
    host_ready,
    wasm_validate,
};

/// Pushes a new frame onto the call stack, with function arguments expected to already be on the
/// value stack.
fn setupStackFrame(
    interp: *Interpreter,
    alloca: Allocator,
    callee: runtime.FuncAddr,
    values_base: u32,
    signature: *const Module.FuncType,
    instantiate_flag: *bool,
) Allocator.Error!SetupStackFrame {
    std.debug.assert(interp.value_stack.items[values_base..].len >= signature.param_count);

    const saved_hash_stack_len = if (HashStack.enabled) interp.hash_stack.inner.len;

    if (interp.call_stack.items.len > 0 and
        interp.currentFrame().function.expanded() == .wasm)
    {
        try interp.hash_stack.push(
            alloca,
            interp.currentFrame(),
            interp.value_stack.items,
            values_base,
        );
    }

    errdefer if (HashStack.enabled) {
        interp.hash_stack.inner.len = saved_hash_stack_len;
    };

    switch (callee.expanded()) {
        .wasm => |wasm| {
            const code: *const Module.Code = wasm.code();

            const validated = code.isValidationFinished();
            const code_inner = if (validated) &code.inner else &Module.Code.validation_failed;

            const total_values = try interp.allocateValueStackSpace(alloca, code_inner);

            try interp.call_stack.append(
                alloca,
                StackFrame{
                    .function = callee,
                    .wasm = .{
                        .instructions = Instructions.init(
                            code_inner.instructions_start,
                            code_inner.instructions_end,
                        ),
                        .branch_table = code_inner.side_table_ptr,
                    },
                    .values_base = values_base,
                    .values_count = total_values,
                    .result_count = signature.result_count,
                    .instantiate_flag = instantiate_flag,
                },
            );

            return if (validated) .wasm_ready else .wasm_validate;
        },
        .host => {
            try interp.call_stack.append(
                alloca,
                StackFrame{
                    .function = callee,
                    .wasm = undefined,
                    .values_base = values_base,
                    .values_count = signature.param_count,
                    .result_count = signature.result_count,
                    .instantiate_flag = instantiate_flag,
                },
            );
            return .host_ready;
        },
    }
}

const OpcodeHandler = fn (
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

    inline fn readUleb128(
        reader: *Instructions,
        comptime T: type,
    ) error{ Overflow, EndOfStream }!T {
        return std.leb.readUleb128(T, reader);
    }

    inline fn nextIdx(reader: *Instructions, comptime I: type) I {
        const IdxInt = @typeInfo(I).@"enum".tag_type;
        return switch (I) {
            // spec w/o multi-memory allows only parsing single byte for memory indices
            Module.MemIdx => @enumFromInt(reader.readUleb128(IdxInt) catch unreachable),
            else => @enumFromInt(@as(
                IdxInt,
                @intCast(reader.readUleb128(u32) catch unreachable),
            )),
        };
    }

    inline fn readIleb128(
        reader: *Instructions,
        comptime T: type,
    ) error{ Overflow, EndOfStream }!T {
        return std.leb.readIleb128(T, reader);
    }

    inline fn nextOpcodeHandler(
        reader: *Instructions,
        fuel: *Fuel,
        interp: *Interpreter,
    ) ?*const OpcodeHandler {
        if (fuel.remaining == 0) {
            interp.state = .{ .interrupted = .{ .cause = .out_of_fuel } };
            return null;
        } else {
            fuel.remaining -= 1;

            const next_opcode = reader.readByte() catch unreachable;

            // std.debug.print(
            //     "TRACE[{X:0>6}]: {s}\n",
            //     .{
            //         @intFromPtr(reader.p) - 1 -
            //             @intFromPtr(interp.currentFrame().function.expanded().wasm.module.header().module.wasm.ptr),
            //         @tagName(@as(opcodes.ByteOpcode, @enumFromInt(next_opcode))),
            //     },
            // );

            return byte_dispatch_table[next_opcode];
        }
    }

    inline fn skipValType(reader: *Instructions) void {
        const b = reader.readByte() catch unreachable;
        _ = @as(Module.ValType, @enumFromInt(b));
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
fn returnFromWasm(
    i: *Instructions,
    s: *Stp,
    loc: u32,
    vals: *ValStack,
    fuel: *Fuel,
    int: *Interpreter,
) void {
    _ = i;
    _ = s;

    const popped = int.currentFrame();
    std.debug.assert(popped.function.expanded() == .wasm);
    std.debug.assert(popped.values_base == loc);

    int.call_stack.items.len -= 1;
    popped.instantiate_flag.* = true;

    if (int.call_stack.items.len > 0 and int.currentFrame().function.expanded() == .wasm) {
        int.hash_stack.pop(
            int.currentFrame(),
            vals.items,
            loc,
        );
    }

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
            .wasm => if (caller_frame.wasm.instructions.nextOpcodeHandler(fuel, int)) |next| {
                @call(
                    .always_tail,
                    next,
                    .{
                        &caller_frame.wasm.instructions,
                        &caller_frame.wasm.branch_table,
                        caller_frame.values_base,
                        vals,
                        fuel,
                        int,
                    },
                );
            } else return,
            .host => break :return_to_host,
        }

        comptime unreachable;
    }

    const signature = popped.function.signature();
    std.debug.assert(signature.result_count == popped.result_count);
    int.state = .{ .awaiting_host = .{ .types = signature.results() } };
}

/// Continues execution of WASM code up to calling the `target_function`, with arguments expected
/// to be on top of the value stack.
///
/// To ensure the interpreter cannot overflow the stack, opcode handlers must ensure this function is
/// called inline.
///
/// If enough stack space is not available, then the interpreter is interrupted and the IP is set to
/// `call_ip`, which is a pointer to the call instruction to restart.
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

    const setup = int.setupStackFrame(
        no_allocation.allocator,
        target_function,
        values_base,
        signature,
        &int.dummy_instantiate_flag,
    ) catch |e| switch (e) {
        error.OutOfMemory => {
            int.state = .{
                .call_stack_exhaustion = .{
                    .callee = target_function,
                    .values_base = values_base,
                    .signature = signature,
                },
            };
            return;
        },
    };

    switch (setup) {
        .wasm_ready => {
            std.debug.assert(loc <= values_base);

            const new_frame = int.currentFrame();
            if (new_frame.wasm.instructions.nextOpcodeHandler(fuel, int)) |next| {
                @call(
                    .always_tail,
                    next,
                    .{
                        &new_frame.wasm.instructions,
                        &new_frame.wasm.branch_table,
                        values_base,
                        vals,
                        fuel,
                        int,
                    },
                );
            }
        },
        .host_ready => int.state = .{
            .awaiting_host = .{ .types = signature.parameters() },
        },
        .wasm_validate => int.state = .{ .awaiting_validation = .{} },
    }
}

const MemArg = struct {
    mem: *const runtime.MemInst,
    offset: u32,

    // TODO: Should opcode handlers take extra ModuleInst parameter?
    fn read(i: *Instructions, interp: *Interpreter) MemArg {
        _ = i.readUleb128(u3) catch unreachable; // align, maximum is 16 bytes (1 << 4)
        return .{
            .offset = i.readUleb128(u32) catch unreachable,
            .mem = interp.currentFrame().function.expanded().wasm
                .module.header().memAddr(.default),
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
            const base_addr: u32 = @bitCast(vals.pop().?.i32);
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
            const base_addr: u32 = @bitCast(vals.pop().?.i32);
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

        fn load(
            i: *Instructions,
            s: *Stp,
            loc: u32,
            vals: *ValStack,
            fuel: *Fuel,
            int: *Interpreter,
        ) void {
            const bytes = accessors.performLoad(i, vals, int) orelse {
                int.state = .{
                    .trapped = Trap.init(.memory_access_out_of_bounds, {}),
                };
                return;
            };

            vals.appendAssumeCapacity(
                @unionInit(
                    Value,
                    field_name,
                    @bitCast(bytes.*),
                ),
            );

            std.debug.assert(loc <= vals.items.len);
            if (i.nextOpcodeHandler(fuel, int)) |next| {
                @call(.always_tail, next, .{ i, s, loc, vals, fuel, int });
            }
        }

        fn store(
            i: *Instructions,
            s: *Stp,
            loc: u32,
            vals: *ValStack,
            fuel: *Fuel,
            int: *Interpreter,
        ) void {
            const c: accessors.Bytes = @bitCast(@field(vals.pop().?, field_name));
            accessors.performStore(i, vals, int, c) catch |e| {
                comptime std.debug.assert(@TypeOf(e) == error{OutOfBounds});
                int.state = .{ .trapped = Trap.init(.memory_access_out_of_bounds, {}) };
                return;
            };

            std.debug.assert(loc <= vals.items.len);
            if (i.nextOpcodeHandler(fuel, int)) |next| {
                @call(.always_tail, next, .{ i, s, loc, vals, fuel, int });
            }
        }
    };
}

fn extendingLinearMemoryLoad(
    comptime field_name: []const u8,
    comptime S: type,
) OpcodeHandler {
    return struct {
        const T = @FieldType(Value, field_name);

        comptime {
            std.debug.assert(@bitSizeOf(S) < @bitSizeOf(T));
        }

        fn handler(
            i: *Instructions,
            s: *Stp,
            loc: u32,
            vals: *ValStack,
            fuel: *Fuel,
            int: *Interpreter,
        ) void {
            const bytes = linearMemoryAccessors(@sizeOf(S)).performLoad(
                i,
                vals,
                int,
            ) orelse {
                int.state = .{ .trapped = Trap.init(.memory_access_out_of_bounds, {}) };
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
    }.handler;
}

fn narrowingLinearMemoryStore(
    comptime field_name: []const u8,
    comptime size: u6,
) OpcodeHandler {
    return struct {
        const T = @FieldType(Value, field_name);
        const S = std.meta.Int(.signed, size);

        comptime {
            std.debug.assert(@bitSizeOf(S) < @bitSizeOf(T));
        }

        fn handler(
            i: *Instructions,
            s: *Stp,
            loc: u32,
            vals: *ValStack,
            fuel: *Fuel,
            int: *Interpreter,
        ) void {
            const narrowed: S = @truncate(@field(vals.pop().?, field_name));
            linearMemoryAccessors(size / 8).performStore(
                i,
                vals,
                int,
                @bitCast(narrowed),
            ) catch |e| {
                comptime std.debug.assert(@TypeOf(e) == error{OutOfBounds});
                int.state = .{
                    .trapped = Trap.init(.memory_access_out_of_bounds, {}),
                };
                return;
            };

            std.debug.assert(loc <= vals.items.len);
            if (i.nextOpcodeHandler(fuel, int)) |next| {
                @call(.always_tail, next, .{ i, s, loc, vals, fuel, int });
            }
        }
    }.handler;
}

fn defineBinOp(
    comptime value_field: []const u8,
    comptime op: anytype,
    comptime trap: anytype,
) OpcodeHandler {
    return struct {
        fn handler(
            i: *Instructions,
            s: *Stp,
            loc: u32,
            vals: *ValStack,
            fuel: *Fuel,
            int: *Interpreter,
        ) void {
            const c_2 = @field(vals.pop().?, value_field);
            const c_1 = @field(vals.pop().?, value_field);
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
    }.handler;
}

fn defineUnOp(comptime value_field: []const u8, comptime op: anytype) OpcodeHandler {
    return struct {
        fn handler(
            i: *Instructions,
            s: *Stp,
            loc: u32,
            vals: *ValStack,
            fuel: *Fuel,
            int: *Interpreter,
        ) void {
            const c_1 = @field(vals.pop().?, value_field);
            const result = @call(.always_inline, op, .{c_1});
            vals.appendAssumeCapacity(@unionInit(Value, value_field, result));

            std.debug.assert(loc <= vals.items.len);
            if (i.nextOpcodeHandler(fuel, int)) |next| {
                @call(.always_tail, next, .{ i, s, loc, vals, fuel, int });
            }
        }
    }.handler;
}

fn defineTestOp(comptime value_field: []const u8, comptime op: anytype) OpcodeHandler {
    return struct {
        fn handler(
            i: *Instructions,
            s: *Stp,
            loc: u32,
            vals: *ValStack,
            fuel: *Fuel,
            int: *Interpreter,
        ) void {
            const c_1 = @field(vals.pop().?, value_field);
            const result = @call(.always_inline, op, .{c_1});
            vals.appendAssumeCapacity(Value{ .i32 = @intFromBool(result) });

            std.debug.assert(loc <= vals.items.len);
            if (i.nextOpcodeHandler(fuel, int)) |next| {
                @call(.always_tail, next, .{ i, s, loc, vals, fuel, int });
            }
        }
    }.handler;
}

fn defineRelOp(comptime value_field: []const u8, comptime op: anytype) OpcodeHandler {
    return struct {
        fn handler(
            i: *Instructions,
            s: *Stp,
            loc: u32,
            vals: *ValStack,
            fuel: *Fuel,
            int: *Interpreter,
        ) void {
            const c_2 = @field(vals.pop().?, value_field);
            const c_1 = @field(vals.pop().?, value_field);
            const result = @call(.always_inline, op, .{ c_1, c_2 });
            vals.appendAssumeCapacity(Value{ .i32 = @intFromBool(result) });

            std.debug.assert(loc <= vals.items.len);
            if (i.nextOpcodeHandler(fuel, int)) |next| {
                @call(.always_tail, next, .{ i, s, loc, vals, fuel, int });
            }
        }
    }.handler;
}

fn defineConvOp(
    comptime src_field: []const u8,
    comptime dst_field: []const u8,
    comptime op: anytype,
    comptime trap: anytype,
) OpcodeHandler {
    return struct {
        fn handler(
            i: *Instructions,
            s: *Stp,
            loc: u32,
            vals: *ValStack,
            fuel: *Fuel,
            int: *Interpreter,
        ) void {
            const t_1 = @field(vals.pop().?, src_field);
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
    }.handler;
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

            /// https://webassembly.github.io/spec/core/exec/numerics.html#op-trunc-s
            fn trunc_s(z: anytype) !Signed {
                if (std.math.isNan(z)) return error.NotANumber;

                // std.debug.print(
                //     "> ({[i]s}.trunc_{[f]s}_s) ({[f]s}.const {[z]d})\n",
                //     .{ .i = @typeName(Signed), .f = @typeName(@TypeOf(z)), .z = z },
                // );

                const tr = @trunc(z);
                return if (tr < std.math.minInt(Signed) or std.math.maxInt(Signed) < tr)
                    error.Overflow
                else
                    std.math.cast(
                        Signed,
                        @as(
                            std.meta.Int(.signed, @typeInfo(Signed).int.bits + 1),
                            @intFromFloat(tr),
                        ),
                    ) orelse error.Overflow;
            }

            fn trunc_u(z: anytype) !Signed {
                if (std.math.isNan(z)) return error.NotANumber;

                const tr = @trunc(z);
                return if (tr < -0.0 or std.math.maxInt(Unsigned) < tr)
                    error.Overflow
                else
                    @bitCast(
                        std.math.cast(
                            Unsigned,
                            @as(
                                std.meta.Int(
                                    .unsigned,
                                    @typeInfo(Signed).int.bits + 1,
                                ),
                                @intFromFloat(tr),
                            ),
                        ) orelse return error.Overflow,
                    );
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

            // std.debug.print(
            //     " > (" ++ @typeName(Signed) ++ ".const) {[0]} (0x{[0]X}) ;; height = {[1]}\n",
            //     .{ n, vals.items.len },
            // );

            if (i.nextOpcodeHandler(fuel, int)) |next| {
                @call(.always_tail, next, .{ i, s, loc, vals, fuel, int });
            }
        }

        const eqz = defineTestOp(value_field, operators.eqz);
        const eq = defineRelOp(value_field, operators.eq);
        const ne = defineRelOp(value_field, operators.ne);
        const lt_s = defineRelOp(value_field, operators.lt_s);
        const lt_u = defineRelOp(value_field, operators.lt_u);
        const gt_s = defineRelOp(value_field, operators.gt_s);
        const gt_u = defineRelOp(value_field, operators.gt_u);
        const le_s = defineRelOp(value_field, operators.le_s);
        const le_u = defineRelOp(value_field, operators.le_u);
        const ge_s = defineRelOp(value_field, operators.ge_s);
        const ge_u = defineRelOp(value_field, operators.ge_u);

        const clz = defineUnOp(value_field, operators.clz);
        const ctz = defineUnOp(value_field, operators.ctz);
        const popcnt = defineUnOp(value_field, operators.popcnt);
        const add = defineBinOp(value_field, operators.add, undefined);
        const sub = defineBinOp(value_field, operators.sub, undefined);
        const mul = defineBinOp(value_field, operators.mul, undefined);
        const div_s = defineBinOp(value_field, operators.div_s, Trap.initSignedIntegerDivision);
        const div_u = defineBinOp(value_field, operators.div_u, Trap.initIntegerDivisionByZero);
        const rem_s = defineBinOp(value_field, operators.rem_s, Trap.initIntegerDivisionByZero);
        const rem_u = defineBinOp(value_field, operators.rem_u, Trap.initIntegerDivisionByZero);
        const @"and" = defineBinOp(value_field, operators.@"and", undefined);
        const @"or" = defineBinOp(value_field, operators.@"or", undefined);
        const xor = defineBinOp(value_field, operators.xor, undefined);
        const shl = defineBinOp(value_field, operators.shl, undefined);
        const shr_s = defineBinOp(value_field, operators.shr_s, undefined);
        const shr_u = defineBinOp(value_field, operators.shr_u, undefined);
        const rotl = defineBinOp(value_field, operators.rotl, undefined);
        const rotr = defineBinOp(value_field, operators.rotr, undefined);

        const trunc_f32_s = defineConvOp("f32", value_field, operators.trunc_s, Trap.initTrunc);
        const trunc_f32_u = defineConvOp("f32", value_field, operators.trunc_u, Trap.initTrunc);
        const trunc_f64_s = defineConvOp("f64", value_field, operators.trunc_s, Trap.initTrunc);
        const trunc_f64_u = defineConvOp("f64", value_field, operators.trunc_u, Trap.initTrunc);

        const trunc_sat_f32_s = defineConvOp("f32", value_field, operators.trunc_sat_s, Trap.initTrunc);
        const trunc_sat_f32_u = defineConvOp("f32", value_field, operators.trunc_sat_u, Trap.initTrunc);
        const trunc_sat_f64_s = defineConvOp("f64", value_field, operators.trunc_sat_s, Trap.initTrunc);
        const trunc_sat_f64_u = defineConvOp("f64", value_field, operators.trunc_sat_u, Trap.initTrunc);
    };
}

const i32_opcode_handlers = integerOpcodeHandlers(i32);
const i64_opcode_handlers = integerOpcodeHandlers(i64);

fn floatOpcodeHandlers(comptime F: type) type {
    return struct {
        const value_field = @typeName(F);
        const Bits = std.meta.Int(.unsigned, @typeInfo(F).float.bits);

        const canonical_nan_bit: Bits = 1 << (std.math.floatMantissaBits(F) - 1);

        const precise_int_limit = 1 << (std.math.floatMantissaBits(F) + 1);

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

            /// https://webassembly.github.io/spec/core/exec/numerics.html#op-feq
            fn eq(z_1: F, z_2: F) bool {
                return z_1 == z_2;
            }

            fn ne(z_1: F, z_2: F) bool {
                return z_1 != z_2;
            }

            fn lt(z_1: F, z_2: F) bool {
                return z_1 < z_2;
            }

            fn gt(z_1: F, z_2: F) bool {
                return z_1 > z_2;
            }

            fn le(z_1: F, z_2: F) bool {
                return z_1 <= z_2;
            }

            fn ge(z_1: F, z_2: F) bool {
                return z_1 >= z_2;
            }

            /// https://webassembly.github.io/spec/core/exec/numerics.html#op-fabs
            fn abs(z: F) F {
                return @abs(z);
            }

            /// https://webassembly.github.io/spec/core/exec/numerics.html#op-fneg
            fn neg(z: F) F {
                // const Int = std.meta.Int(.unsigned, @bitSizeOf(F));
                // return @bitCast(@as(Int, @bitCast(z)) ^ std.math.minInt(Int));
                return -z;
            }

            /// https://webassembly.github.io/spec/core/exec/numerics.html#op-fceil
            fn ceil(z: F) F {
                return @ceil(z);
            }

            /// https://webassembly.github.io/spec/core/exec/numerics.html#op-ffloor
            fn floor(z: F) F {
                return @floor(z);
            }

            /// https://webassembly.github.io/spec/core/exec/numerics.html#op-ftrunc
            fn trunc(z: F) F {
                return if (z <= -0.0) @ceil(z) else @floor(z);
            }

            /// https://webassembly.github.io/spec/core/exec/numerics.html#op-fnearest
            fn nearest(z: F) F {
                // WASM requires rounds-to-nearest-ties-even

                // '@round' compiles to 'llvm.round.*', but what is needed is 'llvm.roundeven.*'
                // See also:
                // - https://github.com/ziglang/zig/issues/767
                // - https://github.com/ziglang/zig/issues/2535

                // Caution, might get error: "Invalid user of intrinsic instruction!"
                // extern fn @"llvm.roundeven.f32"(z: f32) callconv(.c) f32;
                // extern fn @"llvm.roundeven.f64"(z: f64) callconv(.c) f64;

                // Also seems to be available in C23, but that's too new:
                // extern "c" fn roundevenf(arg: f32);
                // extern "c" fn roundevenf(arg: f32);

                if (std.math.isNan(z)) {
                    return @bitCast(@as(Bits, @bitCast(z)) | canonical_nan_bit);
                } else if (std.math.isInf(z) or
                    std.math.isPositiveZero(z) or
                    std.math.isNegativeZero(z))
                {
                    return z;
                } else if (0 < z and z <= 0.5) {
                    return 0.0;
                } else if (-0.5 <= z and z < 0) {
                    return -0.0;
                }

                const left_int = @round(z);
                const right_int = @round(if (std.math.signbit(z)) z + 1.0 else z - 1.0);

                const left_dist = @abs(left_int - z);
                const right_dist = @abs(right_int - z);

                if (left_dist < right_dist) {
                    return left_int;
                } else if (right_dist < left_dist) {
                    return right_dist;
                } else if (-@as(F, precise_int_limit) < z and z < @as(F, precise_int_limit)) {
                    const RoundedInt = std.math.IntFittingRange(-precise_int_limit, precise_int_limit);

                    // Both candidates are the same distance from `z`, so pick the even one
                    const left_i: RoundedInt = @intFromFloat(left_int);
                    const right_i: RoundedInt = @intFromFloat(right_int);
                    std.debug.assert(left_i != right_i);

                    if (@rem(left_i, 2) == 0) {
                        std.debug.assert(@rem(right_i, 2) != 0);
                        return left_int;
                    } else {
                        return right_int;
                    }
                } else {
                    std.debug.assert(left_int == right_int);
                    return left_int;
                }
            }

            /// https://webassembly.github.io/spec/core/exec/numerics.html#op-fsqrt
            fn sqrt(z: F) F {
                return std.math.sqrt(z);
            }

            fn add(z_1: F, z_2: F) !F {
                return z_1 + z_2;
            }

            fn sub(z_1: F, z_2: F) !F {
                return z_1 - z_2;
            }

            fn mul(z_1: F, z_2: F) !F {
                return z_1 * z_2;
            }

            fn div(z_1: F, z_2: F) !F {
                return z_1 / z_2;
            }

            /// https://webassembly.github.io/spec/core/exec/numerics.html#op-fmin
            fn min(z_1: F, z_2: F) !F {
                return if (std.math.isNan(z_1) or std.math.isNan(z_2))
                    z_1 + z_2 // Pick a NaN
                else if ((std.math.isNegativeZero(z_1) and std.math.isPositiveZero(z_2)) or
                    (std.math.isPositiveZero(z_1) and std.math.isNegativeZero(z_2)))
                    -0.0
                else
                    // Zig currently maps `@min` to a call to `llvm.minnum`
                    @min(z_1, z_2);
            }

            /// https://webassembly.github.io/spec/core/exec/numerics.html#op-fmax
            fn max(z_1: F, z_2: F) !F {
                return if (std.math.isNan(z_1) or std.math.isNan(z_2))
                    z_1 + z_2 // Pick a NaN
                else if ((std.math.isNegativeZero(z_1) and std.math.isPositiveZero(z_2)) or
                    (std.math.isPositiveZero(z_1) and std.math.isNegativeZero(z_2)))
                    0.0 // positive zero
                else
                    // Zig currently maps `@max` to a call to `llvm.maxnum`
                    @max(z_1, z_2);
            }

            /// https://webassembly.github.io/spec/core/exec/numerics.html#op-fcopysign
            fn copysign(z_1: F, z_2: F) !F {
                return std.math.copysign(z_1, z_2);
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

        const eq = defineRelOp(value_field, operators.eq);
        const ne = defineRelOp(value_field, operators.ne);
        const lt = defineRelOp(value_field, operators.lt);
        const gt = defineRelOp(value_field, operators.gt);
        const le = defineRelOp(value_field, operators.le);
        const ge = defineRelOp(value_field, operators.ge);

        const abs = defineUnOp(value_field, operators.abs);
        const neg = defineUnOp(value_field, operators.neg);
        const ceil = defineUnOp(value_field, operators.ceil);
        const floor = defineUnOp(value_field, operators.floor);
        const trunc = defineUnOp(value_field, operators.trunc);
        const nearest = defineUnOp(value_field, operators.nearest);
        const sqrt = defineUnOp(value_field, operators.sqrt);
        const add = defineBinOp(value_field, operators.add, undefined);
        const sub = defineBinOp(value_field, operators.sub, undefined);
        const mul = defineBinOp(value_field, operators.mul, undefined);
        const div = defineBinOp(value_field, operators.div, undefined);
        const min = defineBinOp(value_field, operators.min, undefined);
        const max = defineBinOp(value_field, operators.max, undefined);
        const copysign = defineBinOp(value_field, operators.copysign, undefined);

        const convert_i32_s = defineConvOp("i32", value_field, operators.convert_s, undefined);
        const convert_i32_u = defineConvOp("i32", value_field, operators.convert_u, undefined);
        const convert_i64_s = defineConvOp("i64", value_field, operators.convert_s, undefined);
        const convert_i64_u = defineConvOp("i64", value_field, operators.convert_u, undefined);
    };
}

const f32_opcode_handlers = floatOpcodeHandlers(f32);
const f64_opcode_handlers = floatOpcodeHandlers(f64);

fn dispatchTableLength(comptime Opcode: type, comptime length_override: ?usize) comptime_int {
    var maximum = 0;
    for (@typeInfo(Opcode).@"enum".fields) |op| {
        maximum = @max(maximum, op.value);
    }

    const actual_len = maximum + 1;

    if (length_override) |manual_len| {
        std.debug.assert(actual_len <= manual_len);
        return manual_len;
    } else {
        return actual_len;
    }
}

fn dispatchTable(
    comptime Opcode: type,
    comptime invalid: OpcodeHandler,
    comptime length_override: ?usize,
) [dispatchTableLength(Opcode, length_override)]*const OpcodeHandler {
    var table = [_]*const OpcodeHandler{invalid} **
        dispatchTableLength(Opcode, length_override);

    for (@typeInfo(Opcode).@"enum".fields) |op| {
        if (@hasDecl(opcode_handlers, op.name)) {
            table[op.value] = @as(
                *const OpcodeHandler,
                @field(opcode_handlers, op.name),
            );
        }
    }

    return table;
}

fn prefixDispatchTable(comptime prefix: opcodes.ByteOpcode, comptime Opcode: type) type {
    return struct {
        fn panicInvalidInstruction(
            i: *Instructions,
            s: *Stp,
            loc: u32,
            vals: *ValStack,
            fuel: *Fuel,
            int: *Interpreter,
        ) void {
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

        const entries = dispatchTable(Opcode, invalid, null);

        pub fn handler(
            i: *Instructions,
            s: *Stp,
            loc: u32,
            vals: *ValStack,
            fuel: *Fuel,
            int: *Interpreter,
        ) void {
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
        .remap = Allocator.noRemap,
        .free = neverFree,
    };

    fn noAlloc(_: *anyopaque, _: usize, _: std.mem.Alignment, _: usize) ?[*]u8 {
        @branchHint(.cold);
        return null;
    }

    fn noResize(_: *anyopaque, _: []u8, _: std.mem.Alignment, _: usize, _: usize) bool {
        @branchHint(.cold);
        return false;
    }

    fn neverFree(_: *anyopaque, _: []u8, _: std.mem.Alignment, _: usize) void {
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
    const current_frame = interp.currentFrame();
    const code = current_frame.function.expanded().wasm.code();
    const wasm_base_ptr = @intFromPtr(current_frame.function.expanded().wasm
        .module.header().module.wasm.ptr);

    const side_table_end = @intFromPtr(code.inner.side_table_ptr + code.inner.side_table_len);
    std.debug.assert(@intFromPtr(s.* + branch) < side_table_end);
    const target: *const Module.Code.SideTableEntry = &s.*[branch];

    if (builtin.mode == .Debug) {
        const origin_ip = code.inner.instructions_start + target.origin;
        if (@intFromPtr(base_ip) != @intFromPtr(origin_ip)) {
            std.debug.panic(
                "expected this branch to originate from {X:0>6}, but got {X:0>6}",
                .{ @intFromPtr(origin_ip) - wasm_base_ptr, @intFromPtr(base_ip) - wasm_base_ptr },
            );
        }
    }

    // std.debug.print(
    //     " ? TGT BRANCH #{} (current is #{}): delta_ip={}, delta_stp={}, copy={}, pop={}\n",
    //     .{
    //         (@intFromPtr(target) - @intFromPtr(code.inner.side_table_ptr)) / @sizeOf(Module.Code.SideTableEntry),
    //         (@intFromPtr(s.*) - @intFromPtr(code.inner.side_table_ptr)) / @sizeOf(Module.Code.SideTableEntry),
    //         target.delta_ip.done,
    //         target.delta_stp,
    //         target.copy_count,
    //         target.pop_count,
    //     },
    // );

    i.p = addPtrWithOffset(base_ip, target.delta_ip.done);
    std.debug.assert(@intFromPtr(code.inner.instructions_start) <= @intFromPtr(i.p));
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
    std.debug.assert(@intFromPtr(code.inner.side_table_ptr) <= @intFromPtr(s.*));
    std.debug.assert(@intFromPtr(s.*) <= side_table_end);

    // std.debug.print(
    //     " ? STP=#{}\n",
    //     .{(@intFromPtr(s.*) - @intFromPtr(code.inner.side_table_ptr)) / @sizeOf(Module.Code.SideTableEntry)},
    // );

    // std.debug.print(" ? value stack height was {}\n", .{vals.items.len});

    const vals_base = vals.items.len;
    const src: []const Value = vals.items[vals_base - target.copy_count ..];
    const dst_base = vals_base - target.pop_count;

    if (target.pop_count < target.copy_count) {
        vals.appendNTimesAssumeCapacity(undefined, target.copy_count - target.pop_count);
        std.mem.copyForwards(
            Value,
            vals.items[dst_base .. dst_base + target.copy_count],
            src,
        );
    } else if (target.copy_count < target.pop_count) {
        std.mem.copyBackwards(
            Value,
            vals.items[dst_base .. dst_base + target.copy_count],
            src,
        );
        vals.shrinkRetainingCapacity(vals.items.len - target.pop_count + target.copy_count);
    }

    // std.debug.print(" ? value stack height is {}\n", .{vals.items.len});

    std.debug.assert(vals.items.len == vals_base + target.copy_count - target.pop_count);
    std.debug.assert(current_frame.values_base <= vals.items.len);
}

fn functionValidationFailure(
    i: *Instructions,
    s: *Stp,
    loc: u32,
    vals: *ValStack,
    fuel: *Fuel,
    int: *Interpreter,
) void {
    _ = i;
    _ = s;
    _ = loc;
    _ = vals;
    _ = fuel;
    int.state = .{
        .trapped = Trap.init(
            .lazy_validation_failure,
            .{
                .function = int.currentFrame().function.expanded().wasm.idx,
            },
        ),
    };
}

const opcode_handlers = struct {
    fn panicInvalidInstruction(
        i: *Instructions,
        s: *Stp,
        loc: u32,
        vals: *ValStack,
        fuel: *Fuel,
        int: *Interpreter,
    ) void {
        _ = s;
        _ = loc;
        _ = vals;
        _ = fuel;
        _ = int;
        const bad_opcode: u8 = (i.p - 1)[0];
        const opcode_name = name: {
            const tag = std.meta.intToEnum(opcodes.ByteOpcode, bad_opcode) catch
                break :name "unknown";

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
        int.state = .{ .trapped = Trap.init(.unreachable_code_reached, {}) };
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
        const c = vals.pop().?.i32;
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
        const c = vals.pop().?.i32;
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

        const n: u32 = @bitCast(vals.pop().?.i32);

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
        const callee = int.currentFrame().function.expanded().wasm
            .module.header().funcAddr(func_idx);

        invokeWithinWasm(callee, loc, vals, fuel, int);
    }

    pub fn call_indirect(i: *Instructions, s: *Stp, loc: u32, vals: *ValStack, fuel: *Fuel, int: *Interpreter) void {
        _ = s;

        const current_module = int.currentFrame().function.expanded().wasm
            .module.header();

        const expected_signature = i.nextIdx(Module.TypeIdx).funcType(current_module.module);
        const table_idx = i.nextIdx(Module.TableIdx);

        const elem_index: u32 = @bitCast(vals.pop().?.i32);

        const table_addr = current_module.tableAddr(table_idx);
        std.debug.assert(table_addr.elem_type == .funcref);
        const table = table_addr.table;

        if (table.len <= elem_index) {
            int.state = .{ .trapped = Trap.init(.table_access_out_of_bounds, {}) };
            return;
        }

        const callee = table.base.func_ref[0..table.len][elem_index].funcInst() orelse {
            int.state = .{
                .trapped = Trap.init(
                    .indirect_call_to_null,
                    .{ .index = elem_index },
                ),
            };
            return;
        };

        if (!expected_signature.matches(callee.signature())) {
            int.state = .{
                .trapped = Trap.init(.indirect_call_signature_mismatch, {}),
            };
            return;
        }

        invokeWithinWasm(callee, loc, vals, fuel, int);
    }

    pub fn drop(i: *Instructions, s: *Stp, loc: u32, vals: *ValStack, fuel: *Fuel, int: *Interpreter) void {
        _ = vals.pop().?;

        // std.debug.print(" height after drop: {}\n", .{vals.items.len});

        std.debug.assert(loc <= vals.items.len);
        if (i.nextOpcodeHandler(fuel, int)) |next| {
            @call(.always_tail, next, .{ i, s, loc, vals, fuel, int });
        }
    }

    pub fn select(i: *Instructions, s: *Stp, loc: u32, vals: *ValStack, fuel: *Fuel, int: *Interpreter) void {
        const c = vals.pop().?.i32;
        if (c == 0) {
            vals.items[vals.items.len - 2] = vals.items[vals.items.len - 1];
        }

        _ = vals.pop();

        std.debug.assert(loc <= vals.items.len);
        if (i.nextOpcodeHandler(fuel, int)) |next| {
            @call(.always_tail, next, .{ i, s, loc, vals, fuel, int });
        }
    }

    pub fn @"select t"(i: *Instructions, s: *Stp, loc: u32, vals: *ValStack, fuel: *Fuel, int: *Interpreter) void {
        const type_count = i.readUleb128(u32) catch unreachable;
        std.debug.assert(type_count == 1);

        for (0..type_count) |_|
            i.skipValType();

        if (type_count == 1) {
            @call(
                if (builtin.mode == .Debug) .always_tail else .always_inline,
                select,
                .{ i, s, loc, vals, fuel, int },
            );
        } else unreachable;
    }

    pub fn @"local.get"(i: *Instructions, s: *Stp, loc: u32, vals: *ValStack, fuel: *Fuel, int: *Interpreter) void {
        const n: u16 = @intCast(i.readUleb128(u32) catch unreachable);
        const src: *const Value = &vals.items[loc..][n];
        const dst = vals.addOneAssumeCapacity();
        dst.* = src.*;

        // std.debug.print(" > (local.get {}) (i32.const {})\n", .{ n, value.i32 });

        if (i.nextOpcodeHandler(fuel, int)) |next| {
            @call(.always_tail, next, .{ i, s, loc, vals, fuel, int });
        }
    }

    pub fn @"local.set"(i: *Instructions, s: *Stp, loc: u32, vals: *ValStack, fuel: *Fuel, int: *Interpreter) void {
        const n: u16 = @intCast(i.readUleb128(u32) catch unreachable);
        const dst = &vals.items[loc..][n];
        const src: *const Value = &vals.items[vals.items.len - 1];
        dst.* = src.*;
        vals.items.len -= 1;

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

    pub fn @"global.get"(i: *Instructions, s: *Stp, loc: u32, vals: *ValStack, fuel: *Fuel, int: *Interpreter) void {
        const global_idx = i.nextIdx(Module.GlobalIdx);
        const global_addr = int.currentFrame().function.expanded().wasm
            .module.header().globalAddr(global_idx);

        vals.appendAssumeCapacity(switch (global_addr.global_type.val_type) {
            .v128 => unreachable, // TODO
            .externref => .{
                .externref = ExternRef{
                    .addr = @as(
                        *const runtime.ExternAddr,
                        @constCast(@ptrCast(@alignCast(global_addr.value))),
                    ).*,
                },
            },
            inline else => |val_type| @unionInit(
                Value,
                @tagName(val_type),
                @as(
                    *const runtime.GlobalAddr.Pointee(val_type),
                    @constCast(@ptrCast(@alignCast(global_addr.value))),
                ).*,
            ),
        });

        if (i.nextOpcodeHandler(fuel, int)) |next| {
            @call(.always_tail, next, .{ i, s, loc, vals, fuel, int });
        }
    }

    pub fn @"global.set"(i: *Instructions, s: *Stp, loc: u32, vals: *ValStack, fuel: *Fuel, int: *Interpreter) void {
        const global_idx = i.nextIdx(Module.GlobalIdx);
        const global_addr = int.currentFrame().function.expanded().wasm
            .module.header().globalAddr(global_idx);

        const popped = vals.pop().?;
        switch (global_addr.global_type.val_type) {
            .v128 => unreachable, // TODO
            .externref => {
                @as(
                    *runtime.ExternAddr,
                    @ptrCast(@alignCast(global_addr.value)),
                ).* = popped.externref.addr;
            },
            inline else => |val_type| {
                @as(
                    *runtime.GlobalAddr.Pointee(val_type),
                    @ptrCast(@alignCast(global_addr.value)),
                ).* = @field(popped, @tagName(val_type));
            },
        }

        if (i.nextOpcodeHandler(fuel, int)) |next| {
            @call(.always_tail, next, .{ i, s, loc, vals, fuel, int });
        }
    }

    /// https://webassembly.github.io/spec/core/exec/instructions.html#exec-table-get
    pub fn @"table.get"(i: *Instructions, s: *Stp, loc: u32, vals: *ValStack, fuel: *Fuel, int: *Interpreter) void {
        const table_idx = i.nextIdx(Module.TableIdx);
        const table = int.currentFrame().function.expanded().wasm
            .module.header().tableAddr(table_idx).table;

        const value = &vals.items[vals.items.len - 1];
        const idx: u32 = @bitCast(value.i32);
        const dst = std.mem.asBytes(value);

        @memcpy(
            dst[0..table.stride.toBytes()],
            table.elementSlice(idx) catch {
                int.state = .{
                    .trapped = Trap.init(
                        .table_access_out_of_bounds,
                        {},
                    ),
                };
                return;
            },
        );

        // Fill ExternRef padding
        @memset(dst[table.stride.toBytes()..], 0);

        if (i.nextOpcodeHandler(fuel, int)) |next| {
            @call(.always_tail, next, .{ i, s, loc, vals, fuel, int });
        }
    }

    /// https://webassembly.github.io/spec/core/exec/instructions.html#exec-table-set
    pub fn @"table.set"(i: *Instructions, s: *Stp, loc: u32, vals: *ValStack, fuel: *Fuel, int: *Interpreter) void {
        const table_idx = i.nextIdx(Module.TableIdx);
        const table = int.currentFrame().function.expanded().wasm
            .module.header().tableAddr(table_idx).table;

        const ref = vals.pop().?;
        const idx: u32 = @bitCast(vals.pop().?.i32);

        @memcpy(
            table.elementSlice(idx) catch {
                int.state = .{
                    .trapped = Trap.init(
                        .table_access_out_of_bounds,
                        {},
                    ),
                };
                return;
            },
            std.mem.asBytes(&ref)[0..table.stride.toBytes()],
        );

        if (i.nextOpcodeHandler(fuel, int)) |next| {
            @call(.always_tail, next, .{ i, s, loc, vals, fuel, int });
        }
    }

    pub const @"i32.load" = linearMemoryHandlers("i32").load;
    pub const @"i64.load" = linearMemoryHandlers("i64").load;
    pub const @"f32.load" = linearMemoryHandlers("f32").load;
    pub const @"f64.load" = linearMemoryHandlers("f64").load;
    pub const @"i32.load8_s" = extendingLinearMemoryLoad("i32", i8);
    pub const @"i32.load8_u" = extendingLinearMemoryLoad("i32", u8);
    pub const @"i32.load16_s" = extendingLinearMemoryLoad("i32", i16);
    pub const @"i32.load16_u" = extendingLinearMemoryLoad("i32", u16);
    pub const @"i64.load8_s" = extendingLinearMemoryLoad("i64", i8);
    pub const @"i64.load8_u" = extendingLinearMemoryLoad("i64", u8);
    pub const @"i64.load16_s" = extendingLinearMemoryLoad("i64", i16);
    pub const @"i64.load16_u" = extendingLinearMemoryLoad("i64", u16);
    pub const @"i64.load32_s" = extendingLinearMemoryLoad("i64", i32);
    pub const @"i64.load32_u" = extendingLinearMemoryLoad("i64", u32);
    pub const @"i32.store" = linearMemoryHandlers("i32").store;
    pub const @"i64.store" = linearMemoryHandlers("i64").store;
    pub const @"f32.store" = linearMemoryHandlers("f32").store;
    pub const @"f64.store" = linearMemoryHandlers("f64").store;
    pub const @"i32.store8" = narrowingLinearMemoryStore("i32", 8);
    pub const @"i32.store16" = narrowingLinearMemoryStore("i32", 16);
    pub const @"i64.store8" = narrowingLinearMemoryStore("i64", 8);
    pub const @"i64.store16" = narrowingLinearMemoryStore("i64", 16);
    pub const @"i64.store32" = narrowingLinearMemoryStore("i64", 32);

    pub fn @"memory.size"(i: *Instructions, s: *Stp, loc: u32, vals: *ValStack, fuel: *Fuel, int: *Interpreter) void {
        const mem_idx = i.nextIdx(Module.MemIdx);

        const size = int.currentFrame().function.expanded().wasm
            .module.header().memAddr(mem_idx).size / runtime.MemInst.page_size;

        vals.appendAssumeCapacity(.{ .i32 = @bitCast(@as(u32, @intCast(size))) });

        std.debug.assert(loc <= vals.items.len);
        if (i.nextOpcodeHandler(fuel, int)) |next| {
            @call(.always_tail, next, .{ i, s, loc, vals, fuel, int });
        }
    }

    pub fn @"memory.grow"(i: *Instructions, s: *Stp, loc: u32, vals: *ValStack, fuel: *Fuel, int: *Interpreter) void {
        const mem_idx = i.nextIdx(Module.MemIdx);
        const module = int.currentFrame().function.expanded().wasm.module;
        const mem = module.header().memAddr(mem_idx);

        const delta: u32 = @bitCast(vals.pop().?.i32);

        const grow_failed: i32 = -1;

        const result: i32 = result: {
            const delta_bytes = std.math.mul(u32, runtime.MemInst.page_size, delta) catch
                break :result grow_failed;

            if (mem.limit - mem.size < delta_bytes) {
                break :result grow_failed;
            } else if (mem.capacity - mem.size >= delta_bytes) {
                const new_size: u32 = @as(u32, @intCast(mem.size)) + delta_bytes;
                const old_size: u32 = @intCast(mem.size);
                mem.size = new_size;
                @memset(mem.bytes()[old_size..new_size], 0);
                break :result @bitCast(@divExact(@as(u32, @intCast(old_size)), runtime.MemInst.page_size));
            } else {
                int.state = .{
                    .interrupted = .{
                        .cause = .{
                            .memory_grow = .{ .delta = delta_bytes, .memory = mem },
                        },
                    },
                };
                return;
            }
        };

        vals.appendAssumeCapacity(.{ .i32 = result });

        std.debug.assert(loc <= vals.items.len);
        if (i.nextOpcodeHandler(fuel, int)) |next| {
            @call(.always_tail, next, .{ i, s, loc, vals, fuel, int });
        }
    }

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

    pub const @"f32.eq" = f32_opcode_handlers.eq;
    pub const @"f32.ne" = f32_opcode_handlers.ne;
    pub const @"f32.lt" = f32_opcode_handlers.lt;
    pub const @"f32.gt" = f32_opcode_handlers.gt;
    pub const @"f32.le" = f32_opcode_handlers.le;
    pub const @"f32.ge" = f32_opcode_handlers.ge;

    pub const @"f64.eq" = f64_opcode_handlers.eq;
    pub const @"f64.ne" = f64_opcode_handlers.ne;
    pub const @"f64.lt" = f64_opcode_handlers.lt;
    pub const @"f64.gt" = f64_opcode_handlers.gt;
    pub const @"f64.le" = f64_opcode_handlers.le;
    pub const @"f64.ge" = f64_opcode_handlers.ge;

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

    pub const @"f32.abs" = f32_opcode_handlers.abs;
    pub const @"f32.neg" = f32_opcode_handlers.neg;
    pub const @"f32.ceil" = f32_opcode_handlers.ceil;
    pub const @"f32.floor" = f32_opcode_handlers.floor;
    pub const @"f32.trunc" = f32_opcode_handlers.trunc;
    pub const @"f32.nearest" = f32_opcode_handlers.nearest;
    pub const @"f32.sqrt" = f32_opcode_handlers.sqrt;
    pub const @"f32.add" = f32_opcode_handlers.add;
    pub const @"f32.sub" = f32_opcode_handlers.sub;
    pub const @"f32.mul" = f32_opcode_handlers.mul;
    pub const @"f32.div" = f32_opcode_handlers.div;
    pub const @"f32.min" = f32_opcode_handlers.min;
    pub const @"f32.max" = f32_opcode_handlers.max;
    pub const @"f32.copysign" = f32_opcode_handlers.copysign;

    pub const @"f64.abs" = f64_opcode_handlers.abs;
    pub const @"f64.neg" = f64_opcode_handlers.neg;
    pub const @"f64.ceil" = f64_opcode_handlers.ceil;
    pub const @"f64.floor" = f64_opcode_handlers.floor;
    pub const @"f64.trunc" = f64_opcode_handlers.trunc;
    pub const @"f64.nearest" = f64_opcode_handlers.nearest;
    pub const @"f64.sqrt" = f64_opcode_handlers.sqrt;
    pub const @"f64.add" = f64_opcode_handlers.add;
    pub const @"f64.sub" = f64_opcode_handlers.sub;
    pub const @"f64.mul" = f64_opcode_handlers.mul;
    pub const @"f64.div" = f64_opcode_handlers.div;
    pub const @"f64.min" = f64_opcode_handlers.min;
    pub const @"f64.max" = f64_opcode_handlers.max;
    pub const @"f64.copysign" = f64_opcode_handlers.copysign;

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

    fn reinterpretOp(comptime Dst: type) (fn (anytype) error{}!Dst) {
        return struct {
            fn op(src: anytype) error{}!Dst {
                return @bitCast(src);
            }
        }.op;
    }

    pub const @"i32.wrap_i64" = defineConvOp("i64", "i32", conv_ops.@"i32.wrap_i64", undefined);
    pub const @"i32.trunc_f32_s" = i32_opcode_handlers.trunc_f32_s;
    pub const @"i32.trunc_f32_u" = i32_opcode_handlers.trunc_f32_u;
    pub const @"i32.trunc_f64_s" = i32_opcode_handlers.trunc_f64_s;
    pub const @"i32.trunc_f64_u" = i32_opcode_handlers.trunc_f64_u;
    pub const @"i64.extend_i32_s" = defineConvOp("i32", "i64", conv_ops.@"i64.extend_i32_s", undefined);
    pub const @"i64.extend_i32_u" = defineConvOp("i32", "i64", conv_ops.@"i64.extend_i32_u", undefined);
    pub const @"i64.trunc_f32_s" = i64_opcode_handlers.trunc_f32_s;
    pub const @"i64.trunc_f32_u" = i64_opcode_handlers.trunc_f32_u;
    pub const @"i64.trunc_f64_s" = i64_opcode_handlers.trunc_f64_s;
    pub const @"i64.trunc_f64_u" = i64_opcode_handlers.trunc_f64_u;
    pub const @"f32.convert_i32_s" = f32_opcode_handlers.convert_i32_s;
    pub const @"f32.convert_i32_u" = f32_opcode_handlers.convert_i32_u;
    pub const @"f32.convert_i64_s" = f32_opcode_handlers.convert_i64_s;
    pub const @"f32.convert_i64_u" = f32_opcode_handlers.convert_i64_u;
    pub const @"f32.demote_f64" = defineConvOp("f64", "f32", conv_ops.@"f32.demote_f64", undefined);
    pub const @"f64.convert_i32_s" = f64_opcode_handlers.convert_i32_s;
    pub const @"f64.convert_i32_u" = f64_opcode_handlers.convert_i32_u;
    pub const @"f64.convert_i64_s" = f64_opcode_handlers.convert_i64_s;
    pub const @"f64.convert_i64_u" = f64_opcode_handlers.convert_i64_u;
    pub const @"f64.promote_f32" = defineConvOp("f32", "f64", conv_ops.@"f64.promote_f32", undefined);
    pub const @"i32.reinterpret_f32" = defineConvOp("f32", "i32", reinterpretOp(i32), undefined);
    pub const @"i64.reinterpret_f64" = defineConvOp("f64", "i64", reinterpretOp(i64), undefined);
    pub const @"f32.reinterpret_i32" = defineConvOp("i32", "f32", reinterpretOp(f32), undefined);
    pub const @"f64.reinterpret_i64" = defineConvOp("i64", "f64", reinterpretOp(f64), undefined);

    fn intSignExtend(comptime I: type, comptime M: type) (fn (I) I) {
        std.debug.assert(@bitSizeOf(M) < @bitSizeOf(I));
        return struct {
            fn op(i: I) I {
                const j: I = @mod(i, @as(I, 1 << @bitSizeOf(M)));
                return @as(M, @truncate(j));
            }
        }.op;
    }

    pub const @"i32.extend8_s" = defineUnOp("i32", intSignExtend(i32, i8));
    pub const @"i32.extend16_s" = defineUnOp("i32", intSignExtend(i32, i16));
    pub const @"i64.extend8_s" = defineUnOp("i64", intSignExtend(i64, i8));
    pub const @"i64.extend16_s" = defineUnOp("i64", intSignExtend(i64, i16));
    pub const @"i64.extend32_s" = defineUnOp("i64", intSignExtend(i64, i32));

    pub fn @"ref.null"(i: *Instructions, s: *Stp, loc: u32, vals: *ValStack, fuel: *Fuel, int: *Interpreter) void {
        _ = i.readByte() catch unreachable;
        vals.appendAssumeCapacity(std.mem.zeroes(Value));

        std.debug.assert(loc <= vals.items.len);
        if (i.nextOpcodeHandler(fuel, int)) |next| {
            @call(.always_tail, next, .{ i, s, loc, vals, fuel, int });
        }
    }

    pub fn @"ref.is_null"(i: *Instructions, s: *Stp, loc: u32, vals: *ValStack, fuel: *Fuel, int: *Interpreter) void {
        const top = &vals.items[vals.items.len - 1];
        const is_null = std.mem.allEqual(u8, std.mem.asBytes(top), 0);
        // std.debug.dumpHex(std.mem.asBytes(top));
        // std.debug.print(
        //     "> ref.is_null (ref.extern {?}) -> {}\n",
        //     .{ top.externref.addr.nat.toInt(), is_null },
        // );

        top.* = .{ .i32 = @intFromBool(is_null) };

        std.debug.assert(loc <= vals.items.len);
        if (i.nextOpcodeHandler(fuel, int)) |next| {
            @call(.always_tail, next, .{ i, s, loc, vals, fuel, int });
        }
    }

    pub fn @"ref.func"(i: *Instructions, s: *Stp, loc: u32, vals: *ValStack, fuel: *Fuel, int: *Interpreter) void {
        const func_idx = i.nextIdx(Module.FuncIdx);
        const module = int.currentFrame().function.expanded().wasm.module.header();
        vals.appendAssumeCapacity(.{ .funcref = @bitCast(module.funcAddr(func_idx)) });

        std.debug.assert(loc <= vals.items.len);
        if (i.nextOpcodeHandler(fuel, int)) |next| {
            @call(.always_tail, next, .{ i, s, loc, vals, fuel, int });
        }
    }

    pub const @"0xFC" = fc_prefixed_dispatch.handler;
    pub const @"i32.trunc_sat_f32_s" = i32_opcode_handlers.trunc_sat_f32_s;
    pub const @"i32.trunc_sat_f32_u" = i32_opcode_handlers.trunc_sat_f32_u;
    pub const @"i32.trunc_sat_f64_s" = i32_opcode_handlers.trunc_sat_f64_s;
    pub const @"i32.trunc_sat_f64_u" = i32_opcode_handlers.trunc_sat_f64_u;
    pub const @"i64.trunc_sat_f32_s" = i64_opcode_handlers.trunc_sat_f32_s;
    pub const @"i64.trunc_sat_f32_u" = i64_opcode_handlers.trunc_sat_f32_u;
    pub const @"i64.trunc_sat_f64_s" = i64_opcode_handlers.trunc_sat_f64_s;
    pub const @"i64.trunc_sat_f64_u" = i64_opcode_handlers.trunc_sat_f64_u;

    /// https://webassembly.github.io/spec/core/exec/instructions.html#exec-memory-init
    pub fn @"memory.init"(i: *Instructions, s: *Stp, loc: u32, vals: *ValStack, fuel: *Fuel, int: *Interpreter) void {
        const data_idx = i.nextIdx(Module.DataIdx);
        const mem_idx = i.nextIdx(Module.MemIdx);
        const module = int.currentFrame().function.expanded().wasm.module.header();
        const mem = module.memAddr(mem_idx);

        const n: u32 = @bitCast(vals.pop().?.i32);
        const src_addr: u32 = @bitCast(vals.pop().?.i32);
        const d: u32 = @bitCast(vals.pop().?.i32);

        mem.init(module.dataSegment(data_idx), n, src_addr, d) catch {
            int.state = .{ .trapped = Trap.init(.memory_access_out_of_bounds, {}) };
            return;
        };

        std.debug.assert(loc <= vals.items.len);
        if (i.nextOpcodeHandler(fuel, int)) |next| {
            @call(.always_tail, next, .{ i, s, loc, vals, fuel, int });
        }
    }

    pub fn @"data.drop"(i: *Instructions, s: *Stp, loc: u32, vals: *ValStack, fuel: *Fuel, int: *Interpreter) void {
        const data_idx = i.nextIdx(Module.DataIdx);

        int.currentFrame().function.expanded().wasm.module.header()
            .dataSegmentDropFlag(data_idx)
            .drop();

        std.debug.assert(loc <= vals.items.len);
        if (i.nextOpcodeHandler(fuel, int)) |next| {
            @call(.always_tail, next, .{ i, s, loc, vals, fuel, int });
        }
    }

    /// https://webassembly.github.io/spec/core/exec/instructions.html#exec-memory-copy
    pub fn @"memory.copy"(i: *Instructions, s: *Stp, loc: u32, vals: *ValStack, fuel: *Fuel, int: *Interpreter) void {
        const dst_idx = i.nextIdx(Module.MemIdx);
        const src_idx = i.nextIdx(Module.MemIdx);
        const module = int.currentFrame().function.expanded().wasm.module.header();
        const dst_mem = module.memAddr(dst_idx);
        const src_mem = module.memAddr(src_idx);

        const n: u32 = @bitCast(vals.pop().?.i32);
        const src_addr: u32 = @bitCast(vals.pop().?.i32);
        const d: u32 = @bitCast(vals.pop().?.i32);

        dst_mem.copy(src_mem, n, src_addr, d) catch {
            int.state = .{ .trapped = Trap.init(.memory_access_out_of_bounds, {}) };
            return;
        };

        std.debug.assert(loc <= vals.items.len);
        if (i.nextOpcodeHandler(fuel, int)) |next| {
            @call(.always_tail, next, .{ i, s, loc, vals, fuel, int });
        }
    }

    /// https://webassembly.github.io/spec/core/exec/instructions.html#exec-memory-fill
    pub fn @"memory.fill"(i: *Instructions, s: *Stp, loc: u32, vals: *ValStack, fuel: *Fuel, int: *Interpreter) void {
        const mem_idx = i.nextIdx(Module.MemIdx);
        const mem = int.currentFrame().function.expanded().wasm.module.header().memAddr(mem_idx);

        const n: u32 = @bitCast(vals.pop().?.i32);
        const dupe: u8 = @truncate(@as(u32, @bitCast(vals.pop().?.i32)));
        const d: u32 = @bitCast(vals.pop().?.i32);

        mem.fill(n, dupe, d) catch {
            int.state = .{ .trapped = Trap.init(.memory_access_out_of_bounds, {}) };
            return;
        };

        std.debug.assert(loc <= vals.items.len);
        if (i.nextOpcodeHandler(fuel, int)) |next| {
            @call(.always_tail, next, .{ i, s, loc, vals, fuel, int });
        }
    }

    /// https://webassembly.github.io/spec/core/exec/instructions.html#exec-table-init
    pub fn @"table.init"(i: *Instructions, s: *Stp, loc: u32, vals: *ValStack, fuel: *Fuel, int: *Interpreter) void {
        const elem_idx = i.nextIdx(Module.ElemIdx);
        const table_idx = i.nextIdx(Module.TableIdx);
        const module = int.currentFrame().function.expanded().wasm.module;

        const n: u32 = @bitCast(vals.pop().?.i32);
        const src_idx: u32 = @bitCast(vals.pop().?.i32);
        const d: u32 = @bitCast(vals.pop().?.i32);

        runtime.TableInst.init(
            table_idx,
            module,
            elem_idx,
            n,
            src_idx,
            d,
        ) catch {
            int.state = .{ .trapped = Trap.init(.table_access_out_of_bounds, {}) };
            return;
        };

        std.debug.assert(loc <= vals.items.len);
        if (i.nextOpcodeHandler(fuel, int)) |next| {
            @call(.always_tail, next, .{ i, s, loc, vals, fuel, int });
        }
    }

    pub fn @"elem.drop"(i: *Instructions, s: *Stp, loc: u32, vals: *ValStack, fuel: *Fuel, int: *Interpreter) void {
        const elem_idx = i.nextIdx(Module.ElemIdx);

        int.currentFrame().function.expanded().wasm.module.header()
            .elemSegmentDropFlag(elem_idx)
            .drop();

        std.debug.assert(loc <= vals.items.len);
        if (i.nextOpcodeHandler(fuel, int)) |next| {
            @call(.always_tail, next, .{ i, s, loc, vals, fuel, int });
        }
    }

    /// https://webassembly.github.io/spec/core/exec/instructions.html#exec-table-copy
    pub fn @"table.copy"(i: *Instructions, s: *Stp, loc: u32, vals: *ValStack, fuel: *Fuel, int: *Interpreter) void {
        const dst_idx = i.nextIdx(Module.TableIdx);
        const src_idx = i.nextIdx(Module.TableIdx);
        const module = int.currentFrame().function.expanded().wasm.module.header();
        const dst_table = module.tableAddr(dst_idx);
        const src_table = module.tableAddr(src_idx);

        const n: u32 = @bitCast(vals.pop().?.i32);
        const src_addr: u32 = @bitCast(vals.pop().?.i32);
        const d: u32 = @bitCast(vals.pop().?.i32);

        dst_table.table.copy(
            src_table.table,
            n,
            src_addr,
            d,
        ) catch {
            int.state = .{ .trapped = Trap.init(.table_access_out_of_bounds, {}) };
            return;
        };

        std.debug.assert(loc <= vals.items.len);
        if (i.nextOpcodeHandler(fuel, int)) |next| {
            @call(.always_tail, next, .{ i, s, loc, vals, fuel, int });
        }
    }

    /// https://webassembly.github.io/spec/core/exec/instructions.html#exec-table-grow
    pub fn @"table.grow"(i: *Instructions, s: *Stp, loc: u32, vals: *ValStack, fuel: *Fuel, int: *Interpreter) void {
        const table_idx = i.nextIdx(Module.TableIdx);
        const module = int.currentFrame().function.expanded().wasm.module;
        const table_addr = module.header().tableAddr(table_idx);
        const table = table_addr.table;

        const delta: u32 = @bitCast(vals.pop().?.i32);
        const elem = vals.pop().?;
        const grow_failed: i32 = -1;
        const result: i32 = if (table.limit - table.len < delta)
            grow_failed
        else if (table.capacity - table.len >= delta) result: {
            const new_size: u32 = table.len + delta;
            const old_size: u32 = table.len;
            table.len = new_size;

            table.fillWithinCapacity(
                std.mem.asBytes(&elem)[0..table.stride.toBytes()],
                old_size,
                new_size,
            );

            break :result @bitCast(old_size);
        } else {
            int.state = .{
                .interrupted = .{
                    .cause = .{
                        .table_grow = .{
                            .delta = delta,
                            .table = table_addr,
                            .elem = elem,
                        },
                    },
                },
            };
            return;
        };

        vals.appendAssumeCapacity(.{ .i32 = result });

        std.debug.assert(loc <= vals.items.len);
        if (i.nextOpcodeHandler(fuel, int)) |next| {
            @call(.always_tail, next, .{ i, s, loc, vals, fuel, int });
        }
    }

    /// https://webassembly.github.io/spec/core/exec/instructions.html#exec-table-size
    pub fn @"table.size"(i: *Instructions, s: *Stp, loc: u32, vals: *ValStack, fuel: *Fuel, int: *Interpreter) void {
        const table_idx = i.nextIdx(Module.TableIdx);

        const size = int.currentFrame().function.expanded().wasm
            .module.header().tableAddr(table_idx).table.len;

        vals.appendAssumeCapacity(.{ .i32 = @bitCast(@as(u32, @intCast(size))) });

        std.debug.assert(loc <= vals.items.len);
        if (i.nextOpcodeHandler(fuel, int)) |next| {
            @call(.always_tail, next, .{ i, s, loc, vals, fuel, int });
        }
    }

    /// https://webassembly.github.io/spec/core/exec/instructions.html#exec-table-fill
    pub fn @"table.fill"(i: *Instructions, s: *Stp, loc: u32, vals: *ValStack, fuel: *Fuel, int: *Interpreter) void {
        const table_idx = i.nextIdx(Module.TableIdx);
        const table = int.currentFrame().function.expanded()
            .wasm.module.header().tableAddr(table_idx).table;

        const n: u32 = @bitCast(vals.pop().?.i32);
        const dupe = vals.pop().?;
        const d: u32 = @bitCast(vals.pop().?.i32);

        table.fill(n, std.mem.asBytes(&dupe)[0..table.stride.toBytes()], d) catch {
            int.state = .{ .trapped = Trap.init(.table_access_out_of_bounds, {}) };
            return;
        };

        std.debug.assert(loc <= vals.items.len);
        if (i.nextOpcodeHandler(fuel, int)) |next| {
            @call(.always_tail, next, .{ i, s, loc, vals, fuel, int });
        }
    }
};

/// If the handler is not appearing in this table, make sure it is public first.
const byte_dispatch_table = table: {
    var handlers: [256]*const OpcodeHandler = dispatchTable(
        opcodes.ByteOpcode,
        opcode_handlers.invalid,
        256,
    );

    handlers[@intFromEnum(opcodes.IllegalOpcode.@"wasmstint.validation_fail")] = functionValidationFailure;

    break :table handlers;
};

/// Given a WASM function at the top of the call stack, resumes execution.
fn enterMainLoop(interp: *Interpreter, fuel: *Fuel) void {
    var starting_frame = interp.currentFrame();
    std.debug.assert(starting_frame.function.expanded() == .wasm);

    const handler = starting_frame.wasm.instructions.nextOpcodeHandler(
        fuel,
        interp,
    ).?;

    _ = handler(
        &starting_frame.wasm.instructions,
        &starting_frame.wasm.branch_table,
        starting_frame.values_base,
        &interp.value_stack,
        fuel,
        interp,
    );
}

/// Discards the current computation.
pub fn reset(interp: *Interpreter) void {
    interp.value_stack.clearRetainingCapacity();
    interp.call_stack.clearRetainingCapacity();
    interp.hash_stack.clearRetainingCapacity();
    interp.state = .{ .awaiting_host = .{ .types = &[0]Module.ValType{} } };
}

pub fn deinit(interp: *Interpreter, alloca: Allocator) void {
    interp.value_stack.deinit(alloca);
    interp.call_stack.deinit(alloca);
    interp.* = undefined;
}
