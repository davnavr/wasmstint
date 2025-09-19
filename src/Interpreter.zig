//! Represents a single thread of WebAssembly computation.
//!
//! Based on <https://doi.org/10.48550/arXiv.2205.01183>.

const FuncRef = runtime.FuncAddr.Nullable;

const ExternRef = extern struct {
    addr: runtime.ExternAddr,
    padding: enum(usize) {
        zero = 0,
    } = .zero,

    comptime {
        std.debug.assert(@sizeOf(ExternRef) == @sizeOf([2]usize));
    }
};

const Value = extern union {
    i32: i32,
    f32: f32,
    i64: i64,
    f64: f64,
    externref: ExternRef,
    funcref: FuncRef,

    const Tag = enum {
        i32,
        f32,
        i64,
        f64,
        externref,
        funcref,

        fn Type(comptime tag: Tag) type {
            return @FieldType(Value, @tagName(tag));
        }
    };

    comptime {
        std.debug.assert(@sizeOf(Value) == switch (@sizeOf(*anyopaque)) {
            4 => 8, // 16 if support for v128 is added
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

    /// Constructs a `TaggedValue` based on the compile-time type of `value`.
    pub fn initInferred(value: anytype) TaggedValue {
        const T = @TypeOf(value);

        if (@typeInfo(T) == .pointer) {
            @compileError("pointer type " ++ @typeName(T) ++ " is not supported");
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

    pub fn format(value: *const TaggedValue, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try writer.writeByte('(');
        switch (value.*) {
            inline .i32, .i64 => |i| {
                try writer.writeAll(@tagName(value.*));
                // TODO: Config for hex formatting and signed/unsigned integer values
                try writer.print(".const {}", .{i});
            },
            inline .f32, .f64 => |z| {
                try writer.writeAll(@tagName(value.*));
                try writer.writeAll(".const ");
                // TODO: Config for hex representation for float values
                try writer.print("{} (; 0x{X} ;)", .{
                    z,
                    @as(
                        std.meta.Int(.unsigned, @bitSizeOf(@TypeOf(z))),
                        @bitCast(z),
                    ),
                });
            },
            inline .funcref, .externref => |*ref| try ref.format(writer),
        }

        try writer.writeByte(')');
    }

    pub fn formatSlice(
        values: []const TaggedValue,
        writer: *std.Io.Writer,
    ) std.Io.Writer.Error!void {
        for (0.., values) |i, val| {
            if (i > 0) {
                try writer.writeByte(' ');
            }

            try val.format(writer);
        }
    }

    pub fn sliceFormatter(values: []const TaggedValue) std.fmt.Alt(
        []const TaggedValue,
        formatSlice,
    ) {
        return std.fmt.Alt([]const TaggedValue, formatSlice){ .data = values };
    }
};

/// Records information about a called WASM or host function.
///
/// ## Stack Layout
///
/// ```txt
/// |============  bottom   ============|
/// |                                   |
/// |      `StackFrame` - previous      |
/// |                                   |
/// |-----------------------------------|
/// |                                   |
/// | `[*]Value` - previous value stack |
/// |                                   |
/// |- - - - - - - - - - - - - - - - - -| <- current locals base
/// |                                   |
/// |      `[*]Value` - parameters      |
/// |                                   |
/// |-----------------------------------|
/// |                                   |
/// |    `[*]Value` - current locals    |
/// |                                   |
/// |-----------------------------------|
/// |                                   |
/// |      `StackFrame` - current       |
/// |                                   |
/// |-----------------------------------|
/// |                                   |
/// |     `[*]Value` - value stack      |
/// |                                   |
/// |==============  top  ==============|
/// ```
pub const StackFrame = extern struct {
    /// For every WASM stack frame, a checksum of the previous stack frame's data (its contents
    /// on the value stack and the `StackFrame` structure itself) is calculated. This is
    /// possible since WASM code only allows the function at the top of the stack to modify the
    /// value stack.
    ///
    /// This is used to detect bugs in debug mode where the value stacks of functions are
    /// incorrectly modified.
    ///
    /// On function return, this is recalculated to determine if an OOB error occurred.
    checksum: if (builtin.mode == .Debug) u128 else void,

    function: runtime.FuncAddr,

    signature: *const Module.FuncType,
    /// Set to true when the function returns.
    ///
    /// If the function is the start function, then this indicates that the module was successfully
    /// instantiated. Otherwise, this points to a dummy memory location which is never read.
    instantiate_flag: *bool,

    /// The total number of parameters and local variables.
    local_count: u32,
    /// Offset to the previous stack frame.
    prev_frame: Offset,
    padding: u64 = undefined,
    /// Where `Wasm` would be if `function.expanded() == .wasm`.
    wasm: u0 = 0,

    const Offset = enum(u32) {
        none = std.math.maxInt(u32),
        _,
    };

    /// The value stack pointer is not saved since it is implied by offset of `StackFrame`.
    pub const Wasm = extern struct {
        ip: Ip,
        eip: Eip,
        stp: Stp,
        padding: usize = undefined,

        const size_in_values: comptime_int = @divExact(@sizeOf(Wasm), @sizeOf(Value));
    };

    comptime {
        std.debug.assert(@sizeOf(StackFrame) == @sizeOf(Value) * size_in_values);
        std.debug.assert(@sizeOf(Wasm) == @sizeOf(Value) * Wasm.size_in_values);
    }

    fn ChangePointee(
        comptime Self: type,
        comptime size: std.builtin.Type.Pointer.Size,
        comptime alignment: u16,
        comptime Pointee: type,
    ) type {
        std.debug.assert(@typeInfo(Self).pointer.child == StackFrame);
        std.debug.assert(@typeInfo(Self).pointer.size == .one);
        std.debug.assert(@typeInfo(Self).pointer.alignment >= alignment);
        return @Type(.{
            .pointer = std.builtin.Type.Pointer{
                .size = size,
                .is_const = @typeInfo(Self).pointer.is_const,
                .is_volatile = false,
                .address_space = .generic,
                .child = Pointee,
                .alignment = alignment,
                .is_allowzero = false,
                .sentinel_ptr = null,
            },
        });
    }

    /// Asserts that `frame` is of a WASM function.
    fn wasmFrame(
        frame: anytype,
    ) ChangePointee(@TypeOf(frame), .one, @sizeOf(Value), Wasm) {
        std.debug.assert(frame.function.expanded() == .wasm);
        return @ptrCast(@alignCast(&frame.wasm));
    }

    /// Asserts that `frame` is of a WASM function.
    fn currentModule(frame: *const StackFrame) runtime.ModuleInst {
        return frame.function.expanded().wasm.module;
    }

    /// Gets a slice of the function parameters and locals.
    fn localValues(
        frame: anytype,
        bounds: []align(@sizeOf(Value)) const Value,
    ) ChangePointee(@TypeOf(frame), .slice, @sizeOf(Value), Value) {
        const base: ChangePointee(@TypeOf(frame), .many, @sizeOf(Value), Value) =
            @ptrCast(frame);

        const locals = (base - frame.local_count)[0..frame.local_count];
        std.debug.assert(@intFromPtr(bounds.ptr) <= @intFromPtr(locals.ptr));
        std.debug.assert(
            @intFromPtr(&locals.ptr[locals.len]) <= @intFromPtr(&bounds.ptr[bounds.len]),
        );
        std.debug.assert(@intFromPtr(&locals.ptr[locals.len]) == @intFromPtr(frame));
        return locals;
    }

    const size_in_values: comptime_int = @divExact(@sizeOf(StackFrame), @sizeOf(Value));

    fn valueStackBase(frame: anytype) ChangePointee(@TypeOf(frame), .many, @sizeOf(Value), Value) {
        return @as([*]align(@sizeOf(Value)) Value, @constCast(@ptrCast(frame))) +
            StackFrame.size_in_values +
            if (frame.function.expanded() == .wasm)
                @as(usize, StackFrame.Wasm.size_in_values)
            else
                @as(usize, 0);
    }

    /// Calculates a checksum of the stack frame's contents.
    fn calculateChecksum(
        frame: *align(@sizeOf(Value)) const StackFrame,
        /// A slice of the `Interpreter`'s stack, containing the `frame`, its locals, and its
        /// values.
        ///
        /// `stack[stack.len - 1]` refers to the value currently at the top of the value stack
        /// for the function.
        stack: []align(@sizeOf(Value)) const Value,
    ) u128 {
        // No need to check `std.meta.hasUniqueRepresentation`, since even padding bits are
        // expected to remain unchanged. This still probably violates some rule somewhere.
        // comptime {
        //     std.debug.assert(std.meta.hasUniqueRepresentation(StackFrame));
        //     std.debug.assert(std.meta.hasUniqueRepresentation(Wasm));
        // }

        const stack_end = &stack.ptr[stack.len];
        const locals = frame.localValues(stack);

        // Check that frame is in bounds.
        std.debug.assert(size_in_values + locals.len <= stack.len);
        std.debug.assert(@intFromPtr(stack.ptr) <= @intFromPtr(frame));
        std.debug.assert(@intFromPtr(frame.valueStackBase()) <= @intFromPtr(stack_end));

        switch (frame.function.expanded()) {
            .wasm => |wasm| if (wasm.code().isValidationFinished()) {
                std.debug.assert(
                    stack.len - (size_in_values + locals.len) <= wasm.code().inner.max_values,
                );
            },
            .host => {},
        }

        // Fowler-Noll-Vo is designed for both hashing AND checksums.
        return std.hash.Fnv1a_128.hash(
            std.mem.sliceAsBytes(
                @as(
                    []align(@sizeOf(Value)) const Value,
                    locals.ptr[0..(stack_end - locals.ptr)],
                ),
            ),
        );
    }
};

/// In `.Debug` mode, this ensures that `State` structs operate on the correct `Interpreter`.
const Version = packed struct {
    const enabled = builtin.mode == .Debug;

    number: if (enabled) u32 else void =
        if (enabled) 0 else void,

    fn increment(ver: *Version) void {
        if (enabled) {
            ver.number +%= 1;
        }
    }

    fn check(expected: Version, actual: Version) void {
        if (comptime enabled) {
            if (expected.number != actual.number) {
                std.debug.panic("bad interpreter version: expected {}, got {}", .{ expected, actual });
            }
        }
    }
};

/// Uses a simple contiguous stack design, a segmented stack would have to deal with the
/// "hot splitting" problem (which is why Rust and Go rejected it).
const Stack = struct {
    base: [*]align(@sizeOf(Value)) Value,
    len: u32,
    cap: u32,

    fn init(
        allocator: Allocator,
        /// In terms of # of `Value`s.
        capacity: u32,
    ) Allocator.Error!Stack {
        const allocation: []align(@sizeOf(Value)) Value = if (capacity == 0)
            &.{}
        else
            try allocator.alignedAlloc(Value, .fromByteUnits(@sizeOf(Value)), capacity);
        return .{
            .base = allocation.ptr,
            .cap = capacity,
            .len = 0,
        };
    }

    fn ChangePointee(
        comptime Self: type,
        comptime size: std.builtin.Type.Pointer.Size,
        comptime alignment: u16,
        comptime Pointee: type,
    ) type {
        std.debug.assert(@typeInfo(Self).pointer.child == Stack);
        std.debug.assert(@typeInfo(Self).pointer.size == .one);
        std.debug.assert(@typeInfo(Self).pointer.alignment >= @alignOf(Stack));
        return @Type(.{
            .pointer = .{
                .size = size,
                .is_const = @typeInfo(Self).pointer.is_const,
                .is_volatile = false,
                .alignment = alignment,
                .child = Pointee,
                .address_space = .generic,
                .is_allowzero = false,
                .sentinel_ptr = null,
            },
        });
    }

    fn Slice(comptime Self: type) type {
        return ChangePointee(Self, .slice, @sizeOf(Value), Value);
    }

    fn allocatedSlice(stack: anytype) Slice(@TypeOf(stack)) {
        std.debug.assert(stack.len <= stack.cap);
        return stack.base[0..stack.cap];
    }

    fn slice(stack: anytype) Slice(@TypeOf(stack)) {
        return stack.allocatedSlice()[0..stack.len];
    }

    fn topSlice(stack: anytype, len: usize) Slice(@TypeOf(stack)) {
        const items = stack.slice();
        return items[items.len - len ..];
    }

    // /// Asserts that the stack is not empty.
    // fn pop(stack: *Stack) Value {
    //     const i = stack.len;
    //     stack.len -= 1;
    //     return stack.allocatedSlice()[i];
    // }

    // /// Asserts that the stack has enough remaining capacity.
    // fn push(stack: *Stack, value: Value) void {
    //     const i = stack.len;
    //     stack.len += 1;
    //     stack.allocatedSlice()[i] = value;
    // }

    fn stackFrame(
        stack: anytype,
        offset: StackFrame.Offset,
    ) ?ChangePointee(@TypeOf(stack), .one, @sizeOf(Value), StackFrame) {
        switch (offset) {
            .none => return null,
            else => {
                const base_idx = @intFromEnum(offset);
                const values: Slice(@TypeOf(stack)) =
                    @alignCast(stack.slice()[base_idx .. base_idx + StackFrame.size_in_values]);

                return @ptrCast(values);
            },
        }
    }

    const ParameterAllocation = enum { allocate, preallocated };

    const StackFrameSize = packed struct(u64) {
        /// In units of `Value`s.
        allocated_size: u32,
        /// Number of local variables to allocate space for.
        allocated_local_count: u16,
        total_local_count: u16,
    };

    fn stackFrameSize(
        callee: runtime.FuncAddr,
        comptime params: ParameterAllocation,
    ) error{ValidationNeeded}!StackFrameSize {
        const param_count = callee.signature().param_count;
        const allocated_param_count = switch (params) {
            .allocate => param_count,
            .preallocated => 0,
        };

        const local_count: u16 = switch (callee.expanded()) {
            .host => 0,
            .wasm => |wasm| wasm: {
                const code = wasm.code();
                if (code.isValidationFinished()) {
                    break :wasm code.inner.local_values;
                } else {
                    return error.ValidationNeeded;
                }
            },
        };

        const allocated_local_count = allocated_param_count + local_count;
        const value_stack_size = switch (callee.expanded()) {
            .host => 0,
            .wasm => |wasm| StackFrame.Wasm.size_in_values + wasm.code().inner.max_values,
        };

        return .{
            .allocated_local_count = allocated_local_count,
            .total_local_count = param_count + local_count,
            .allocated_size = StackFrame.size_in_values + allocated_local_count + value_stack_size,
        };
    }

    const PushedStackFrame = struct {
        offset: StackFrame.Offset,
        frame: *align(@sizeOf(Value)) StackFrame,
    };

    const PushStackFrameError = error{ValidationNeeded} || Allocator.Error;

    /// Asserts that `callee` has already been validated.
    fn pushStackFrameWithinCapacity(
        stack: *Stack,
        prev_frame: StackFrame.Offset,
        instantiate_flag: *bool,
        comptime params: ParameterAllocation,
        callee: runtime.FuncAddr,
    ) PushStackFrameError!PushedStackFrame {
        const frame_info = try stackFrameSize(callee, params);
        std.debug.assert(frame_info.allocated_size > frame_info.allocated_local_count);
        if (frame_info.allocated_size > stack.cap - stack.len) {
            return error.OutOfMemory;
        }

        errdefer comptime unreachable;

        const old_stack_top = stack.base + stack.len;

        const prev_frame_ptr: ?*align(@sizeOf(Value)) StackFrame = stack.stackFrame(prev_frame);
        const prev_frame_hash = if (prev_frame_ptr) |prev|
            prev.calculateChecksum(
                stack.slice()[0 .. stack.len - switch (params) {
                    .allocate => 0,
                    .preallocated => callee.signature().param_count,
                }],
            )
        else
            0;

        const offset: StackFrame.Offset =
            @enumFromInt(stack.len + frame_info.allocated_local_count);

        const frame_values: []align(@sizeOf(Value)) Value =
            stack.allocatedSlice()[stack.len .. stack.len + frame_info.allocated_size];

        @memset(frame_values, undefined);

        const frame_base: []align(@sizeOf(Value)) Value = @alignCast(
            frame_values[frame_info.allocated_local_count..],
        );
        const frame_ptr: *align(@sizeOf(Value)) StackFrame = @ptrCast(
            frame_base[0..StackFrame.size_in_values],
        );
        frame_ptr.* = StackFrame{
            .checksum = if (builtin.mode == .Debug) prev_frame_hash,
            .function = callee,
            .signature = callee.signature(),
            .instantiate_flag = instantiate_flag,
            .local_count = frame_info.total_local_count,
            .prev_frame = prev_frame,
        };

        std.debug.assert(@intFromPtr(&stack.base[@intFromEnum(offset)]) == @intFromPtr(frame_ptr));

        stack.len += @intCast(frame_ptr.valueStackBase() - (stack.base + stack.len));

        switch (callee.expanded()) {
            .host => {},
            .wasm => |wasm| {
                const code = wasm.code();
                if (builtin.mode == .Debug and !code.isValidationFinished()) {
                    std.debug.panic(
                        "validation check should have already occurred for {f}",
                        .{callee},
                    );
                }

                frame_ptr.wasmFrame().* = StackFrame.Wasm{
                    .ip = code.inner.instructions_start,
                    .eip = code.inner.instructions_end,
                    .stp = .{ .ptr = code.inner.side_table_ptr },
                };

                // Zero the local variables
                @memset(
                    frame_ptr.localValues(frame_values)[callee.signature().param_count..],
                    std.mem.zeroes(Value),
                );
            },
        }

        if (builtin.mode == .Debug and
            @intFromPtr(frame_ptr.valueStackBase()) != @intFromPtr(stack.base + stack.len))
        {
            std.debug.panic(
                "incorrect value stack base!\n" ++
                    "{*} - frame allocation start\n" ++
                    "{*} - frame\n" ++
                    "{*} - frame values base\n" ++
                    "{*} - old stack top\n" ++
                    "{*} - stack top\n" ++
                    "allocated {} with {t} parameters\n",
                .{
                    frame_values.ptr,
                    frame_base,
                    frame_ptr.valueStackBase(),
                    old_stack_top,
                    stack.base + stack.len,
                    frame_info,
                    params,
                },
            );
        }

        return .{
            .offset = offset,
            .frame = frame_ptr,
        };
    }

    const ReserveStackFrame = struct {
        new_len: u32,
    };

    fn reserveStackFrame(
        stack: *Stack,
        alloca: Allocator,
        comptime params: ParameterAllocation,
        callee: runtime.FuncAddr,
    ) Allocator.Error!ReserveStackFrame {
        const frame_size = (stackFrameSize(callee, params) catch unreachable).allocated_size;
        const new_len = std.math.add(u32, stack.len, frame_size) catch
            return error.OutOfMemory;

        const new_cap: u32 = @max(new_len, stack.cap +| @max(1, stack.cap / 2));

        const old_allocation = stack.allocatedSlice();
        if (alloca.resize(old_allocation, new_cap)) {
            stack.cap = new_cap;
        } else if (alloca.resize(old_allocation, new_len)) {
            @branchHint(.unlikely);
            stack.cap = new_len;
        } else {
            const new_allocation =
                alloca.alignedAlloc(Value, .fromByteUnits(@sizeOf(Value)), new_cap) catch
                    try alloca.alignedAlloc(Value, .fromByteUnits(@sizeOf(Value)), new_len);

            errdefer comptime unreachable;

            @memcpy(new_allocation[0..stack.len], old_allocation[0..stack.len]);

            alloca.free(old_allocation);
            stack.base = new_allocation.ptr;
            stack.cap = @intCast(new_allocation.len);
        }

        return .{ .new_len = new_len };
    }

    /// Potentially invalidates pointers to the stack.
    ///
    /// Asserts that `callee` has already been validated.
    fn pushStackFrame(
        stack: *Stack,
        alloca: Allocator,
        prev_frame: StackFrame.Offset,
        instantiate_flag: *bool,
        comptime params: ParameterAllocation,
        callee: runtime.FuncAddr,
    ) PushStackFrameError!PushedStackFrame {
        alloc_needed: {
            return stack.pushStackFrameWithinCapacity(
                prev_frame,
                instantiate_flag,
                params,
                callee,
            ) catch |e| switch (e) {
                error.ValidationNeeded => |err| err,
                error.OutOfMemory => {
                    @branchHint(.unlikely);
                    break :alloc_needed;
                },
            };
        }

        const growth = try stack.reserveStackFrame(alloca, params, callee);

        const new_frame = stack.pushStackFrameWithinCapacity(
            prev_frame,
            instantiate_flag,
            params,
            callee,
        ) catch unreachable;

        std.debug.assert(growth.new_len == stack.len);
        return new_frame;
    }

    fn deinit(stack: *Stack, alloca: Allocator) void {
        if (stack.cap > 0) {
            alloca.free(stack.allocatedSlice());
        }
        stack.* = undefined;
    }
};

stack: Stack,
current_frame: StackFrame.Offset = .none,
call_depth: u32 = 0,
dummy_instantiate_flag: bool = false,
version: Version = .{},

const Interpreter = @This();

/// Places an upper bound on the number of WASM instructions an interpreter can execute.
pub const Fuel = extern struct {
    remaining: u64,
};

pub const InitOptions = struct {
    /// The initial size, in bytes, of the stack.
    ///
    /// Currently, this value is rounded down to the nearest multiple of `@sizeOf(Value)`.
    stack_reserve: u32 = @sizeOf(Value) * 1024,
};

const Wrapper = struct {
    version: Version,
    interpreter_unchecked: *Interpreter,

    fn init(interp: *Interpreter) Wrapper {
        return .{
            .version = interp.version,
            .interpreter_unchecked = interp,
        };
    }

    fn get(interp: Wrapper) *Interpreter {
        interp.interpreter_unchecked.version.check(interp.version);
        return interp.interpreter_unchecked;
    }
};

pub fn init(
    interp: *Interpreter,
    /// Used to allocate the `stack`.
    alloca: Allocator,
    options: InitOptions,
) Allocator.Error!State.AwaitingHost {
    interp.* = .{
        .stack = try .init(alloca, @divFloor(options.stack_reserve, @sizeOf(Value))),
    };

    return .{ .interpreter = .init(interp) };
}

/// Discards the current computation.
pub fn reset(interp: *Interpreter) State {
    interp.version.increment();
    if (builtin.mode == .Debug) {
        @memset(interp.stack.slice(), undefined);
    }
    interp.stack.len = 0;
    interp.call_depth = 0;
    interp.current_frame = .none;
    return .{ .awaiting_host = .{ .interpreter = .init(interp) } };
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

    pub const MemoryAccessOutOfBounds = struct {
        memory: Module.MemIdx,
        cause: Cause,
        info: Info,

        pub const Info = union {
            @"memory.init": void,
            @"memory.copy": void,
            @"memory.fill": void,
            access: Access,

            pub const Access = packed struct {
                address: std.meta.Int(.unsigned, @typeInfo(usize).int.bits),
                size: std.mem.Alignment,
                maximum: usize,
            };
        };

        pub const Cause = std.meta.FieldEnum(Info);

        fn init(
            mem: Module.MemIdx,
            comptime cause: Cause,
            info: @FieldType(Info, @tagName(cause)),
        ) MemoryAccessOutOfBounds {
            return .{
                .memory = mem,
                .cause = cause,
                .info = @unionInit(Info, @tagName(cause), info),
            };
        }
    };

    pub const TableAccessOutOfBounds = struct {
        table: Module.TableIdx,
        cause: Cause,

        pub const Cause = union(enum) {
            @"table.init",
            @"call.indirect",
            @"table.copy",
            @"table.fill",
            access: Access,

            pub const Access = struct { index: u32 };
        };

        pub fn init(table: Module.TableIdx, cause: Cause) TableAccessOutOfBounds {
            return .{ .table = table, .cause = cause };
        }
    };

    pub const Information = union {
        indirect_call_to_null: struct {
            index: usize,
        },
        lazy_validation_failure: struct {
            function: Module.FuncIdx,
        },
        memory_access_out_of_bounds: MemoryAccessOutOfBounds,
        table_access_out_of_bounds: TableAccessOutOfBounds,
    };

    fn InformationType(comptime code: Code) type {
        return if (@hasField(Information, @tagName(code)))
            @FieldType(Information, @tagName(code))
        else
            void;
    }

    fn init(
        comptime code: Code,
        information: InformationType(code),
    ) Trap {
        return Trap{
            .code = code,
            .information = if (@hasField(Information, @tagName(code)))
                @unionInit(Information, @tagName(code), information)
            else
                undefined,
        };
    }

    fn initIntegerOperation(e: error{ Overflow, DivisionByZero, NotANumber }) Trap {
        return switch (e) {
            error.Overflow => Trap.init(.integer_overflow, {}),
            error.DivisionByZero => Trap.init(.integer_division_by_zero, {}),
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
        /// Modifying this value is a violation of WebAssembly semantics.
        old_size: usize,
        /// Invariant that `new_size >= memory.size`.
        new_size: usize,
        result: *align(@sizeOf(Value)) Value,

        /// The amount to increase the size of the memory by, in bytes.
        pub fn delta(grow: *const MemoryGrow) usize {
            return grow.new_size - grow.memory.size;
        }
    };

    pub const TableGrow = struct {
        table: runtime.TableAddr,
        /// Also used as the result where an `i32` to indicate the old size is written.
        elem: *align(@sizeOf(Value)) Value,
        old_len: u32,
        /// Invariant that `new_size >= table.len`.
        new_len: u32,
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
    trapped: Trapped,
    // unhandled_exception: Exception,

    pub fn interpreter(state: *const State) *Interpreter {
        switch (state.*) {
            inline else => |*case| {
                const wrapper: *const Wrapper = &case.interpreter;
                return wrapper.get();
            },
        }
    }

    /// Either WASM code is ready to be interpreted, or WASM code is awaiting the results of
    /// calling a host function.
    pub const AwaitingHost = struct {
        interpreter: Wrapper,
        /// The types of the parameters provided to the called host function.
        param_types: []const Module.ValType = &.{},
        /// The types of the values at the top of the value stack, which are the results of the most
        /// recently called function.
        result_types: []const Module.ValType = &.{},

        fn copyValues(
            types: []const Module.ValType,
            values: []align(@sizeOf(Value)) const Value,
            output: []TaggedValue,
        ) void {
            for (output, types, values) |*dst, ty, *val| {
                dst.* = switch (ty) {
                    .v128 => unreachable, // Not implemented
                    .externref => TaggedValue{ .externref = val.externref.addr },
                    inline else => |tag| @unionInit(
                        TaggedValue,
                        @tagName(tag),
                        @field(val, @tagName(tag)),
                    ),
                };
            }
        }

        /// Copies the parameters passed to the host function to a list.
        pub fn copyParamsTo(self: *const AwaitingHost, output: []TaggedValue) void {
            const interp = self.interpreter.get();
            const param_count = self.param_types.len;
            copyValues(
                self.param_types,
                interp.stack.topSlice(param_count + self.result_types.len)[0..param_count],
                output,
            );
        }

        pub fn copyResultsTo(self: *const AwaitingHost, output: []TaggedValue) void {
            const interp = self.interpreter.get();
            copyValues(self.result_types, interp.stack.topSlice(self.result_types.len), output);
        }

        /// Copies the parameters passed to the host function to a new allocation.
        pub fn allocParams(
            self: *const AwaitingHost,
            allocator: Allocator,
        ) Allocator.Error![]TaggedValue {
            const params = try allocator.alloc(TaggedValue, self.param_types.len);
            self.copyParamsTo(params);
            return params;
        }

        /// Copies the results from the most recent function call to a new allocation.
        pub fn allocResults(
            self: *const AwaitingHost,
            allocator: Allocator,
        ) Allocator.Error![]TaggedValue {
            const results = try allocator.alloc(TaggedValue, self.result_types.len);
            self.copyResultsTo(results);
            return results;
        }

        fn valuesTyped(
            comptime T: type,
            types: []const Module.ValType,
            values: []align(@sizeOf(Value)) const Value,
        ) error{ValueTypeOrCountMismatch}!T {
            const result_fields = tuple: {
                switch (@typeInfo(T)) {
                    .@"struct" => |s| if (s.is_tuple) break :tuple s.fields,
                    else => {},
                }

                @compileError("expect tuple, got " ++ @typeName(T));
            };

            std.debug.assert(types.len == values.len);
            if (result_fields.len != types.len) {
                return error.ValueTypeOrCountMismatch;
            }

            var results: T = undefined;
            inline for (0.., result_fields, types, values) |i, *field, ty, *src| {
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

        pub fn paramsTyped(
            self: *const AwaitingHost,
            comptime T: type,
        ) error{ValueTypeOrCountMismatch}!T {
            const interp = self.interpreter.get();
            return valuesTyped(
                T,
                self.param_types,
                interp.stack.topSlice(
                    self.param_types.len + self.result_types.len,
                )[0..self.param_types.len],
            );
        }

        /// Begins the process of calling a function, allocating stack space.
        ///
        /// For a host function, this returns back to the caller, while a WASM function
        /// will enter the interpreter loop, returning when a `Trap` occurs or when `Interrupted`.
        ///
        /// Returns `error.OutOfMemory` if `alloca` could not reserve enough space to execute the
        /// function, or if the call stack depth counter overflowed.
        ///
        /// Always sets `result_types` to the empty slice.
        pub fn beginCall(
            self: AwaitingHost,
            alloca: Allocator,
            callee: runtime.FuncAddr,
            arguments: []const TaggedValue,
            fuel: *Fuel,
        ) (error{ ValueTypeOrCountMismatch, ValidationNeeded, OutOfMemory })!State {
            const interp: *Interpreter = self.interpreter.get();

            const saved_stack_len = interp.stack.len;
            errdefer interp.stack.len = saved_stack_len;
            // results replaced with new function call
            interp.stack.len -= @intCast(self.result_types.len);
            // self.result_types = &.{};

            const signature = callee.signature();
            if (arguments.len != signature.param_count) {
                return error.ValueTypeOrCountMismatch; // wrong # of arguments provided
            }

            // Can't check argument types after stack frame is pushed, would partially overwrite
            // result values (`self.result_types`)
            for (arguments, signature.parameters()) |*src, param_type| {
                if (param_type != src.value_type()) {
                    return error.ValueTypeOrCountMismatch; // argument type mismatch
                }
            }

            const old_call_depth = interp.call_depth;
            interp.call_depth = std.math.add(u32, interp.call_depth, 1) catch
                return error.OutOfMemory; // call stack depth counter overflow
            errdefer interp.call_depth = old_call_depth;

            const new_frame = try interp.stack.pushStackFrame(
                alloca,
                interp.current_frame,
                &interp.dummy_instantiate_flag,
                .allocate,
                callee,
            );

            errdefer unreachable;

            const frame_arguments = new_frame.frame.localValues(
                interp.stack.slice()[0..@intFromEnum(new_frame.offset)],
            )[0..signature.param_count];

            for (frame_arguments, arguments) |*dst, *src| {
                dst.* = src.untagged();
            }

            interp.current_frame = new_frame.offset;
            interp.version.increment();
            return switch (callee.expanded()) {
                .host => |host| State{
                    .awaiting_host = AwaitingHost{
                        .interpreter = .init(interp),
                        .param_types = host.func.signature.parameters(),
                    },
                },
                .wasm => interp.enterMainLoop(fuel),
            };
        }

        /// Instantiates a module, beginning the process of invoking its start function (if it
        /// exists) as if passed to `.beginCall()`.
        pub fn instantiateModule(
            self: AwaitingHost,
            alloca: Allocator,
            module: *runtime.ModuleAlloc,
            fuel: *Fuel,
        ) Stack.PushStackFrameError!State {
            std.debug.assert(!module.instantiated);
            const interp: *Interpreter = self.interpreter.get();

            const maybe_start_idx =
                module.requiring_instantiation.header().module.inner.raw.start.get();
            const start_frame = if (maybe_start_idx) |start_idx|
                try interp.stack.pushStackFrame(
                    alloca,
                    interp.current_frame,
                    &module.instantiated,
                    .preallocated,
                    module.requiring_instantiation.header().funcAddr(start_idx),
                )
            else
                null;

            errdefer unreachable;

            interp.version.increment();

            {
                var instantiation_error: ModuleInstantiationSetupError = undefined;
                moduleInstantiationSetup(module, &instantiation_error) catch return State{
                    .trapped = Trapped.init(
                        .init(interp),
                        if (start_frame) |pushed_frame| pushed_frame.offset else .none,
                        switch (instantiation_error) {
                            inline else => |info, tag| .init(
                                @field(Trap.Code, @tagName(tag)),
                                info,
                            ),
                        },
                    ),
                };
            }
            if (start_frame) |pushed_frame| {
                const start = pushed_frame.frame.function;
                std.debug.assert(start.signature().param_count == 0);
                std.debug.assert(start.signature().result_count == 0);

                interp.version.increment();
                return switch (start.expanded()) {
                    .host => State{
                        .awaiting_host = AwaitingHost{ .interpreter = .init(interp) },
                    },
                    .wasm => interp.enterMainLoop(fuel),
                };
            } else {
                module.instantiated = true;
                return State{ .awaiting_host = .{ .interpreter = .init(interp) } };
            }
        }

        /// Returns the current host function being called, or `null` if the call stack is empty.
        pub fn currentHostFunction(self: *const AwaitingHost) ?runtime.FuncAddr.Expanded.Host {
            const interp: *const Interpreter = self.interpreter.get();
            const frame: ?*align(@sizeOf(Value)) const StackFrame = interp.currentFrame();
            return if (frame) |stack_frame|
                stack_frame.function.expanded().host
            else
                null;
        }

        /// Return from the currently executing host function to the calling function, typically
        /// WASM code whose interpretation will continue with the given `fuel` amount.
        ///
        /// Asserts that the call stack is not empty.
        pub fn returnFromHost(
            self: *AwaitingHost,
            results: []const TaggedValue,
            fuel: *Fuel,
        ) error{ValueTypeOrCountMismatch}!State {
            const interp: *Interpreter = self.interpreter.get();
            const popped_addr: *align(@sizeOf(Value)) StackFrame = interp.currentFrame().?;
            const popped = popped_addr.*;
            const expected_checksum = popped.checksum;
            const signature = popped.signature;

            if (results.len != signature.result_count)
                return error.ValueTypeOrCountMismatch;

            interp.call_depth -= 1;
            errdefer interp.call_depth += 1;

            const saved_stack_len = interp.stack.len;
            errdefer interp.stack.len = saved_stack_len;
            std.debug.assert(saved_stack_len <= interp.stack.cap);

            const popped_locals = popped_addr.localValues(interp.stack.slice());
            const results_dst = popped_locals.ptr[0..results.len];
            std.debug.assert(@intFromPtr(interp.stack.base) <= @intFromPtr(results_dst.ptr));
            std.debug.assert(
                @intFromPtr(&results_dst.ptr[results_dst.len]) <=
                    @intFromPtr(&interp.stack.slice().ptr[interp.stack.len]),
            );

            for (
                results,
                signature.results(),
                results_dst,
            ) |*src, result_type, *dst| {
                if (result_type != src.value_type())
                    return error.ValueTypeOrCountMismatch;

                dst.* = src.untagged();
            }

            errdefer comptime unreachable;
            interp.stack.len = @intCast(
                @divExact(
                    @intFromPtr(popped_locals.ptr) - @intFromPtr(interp.stack.base),
                    @sizeOf(Value),
                ) + results.len,
            );
            std.debug.assert(interp.stack.len < saved_stack_len);
            interp.version.increment();
            popped.instantiate_flag.* = true;

            interp.current_frame = popped.prev_frame;
            if (interp.currentFrame()) |current| {
                switch (current.function.expanded()) {
                    .wasm => {
                        const actual_checksum =
                            interp.stack.stackFrame(interp.current_frame).?.calculateChecksum(
                                interp.stack.slice()[0 .. interp.stack.len - results.len],
                            );

                        if (builtin.mode == .Debug and expected_checksum != actual_checksum) {
                            std.debug.panic(
                                "frame checksum mismatch:\nexpected: {X}\nactual: {X}",
                                .{ expected_checksum, actual_checksum },
                            );
                        }

                        return interp.enterMainLoop(fuel);
                    },
                    .host => {},
                }
            }

            return State{
                .awaiting_host = .{
                    .interpreter = .init(interp),
                    .result_types = signature.results(),
                    .param_types = self.param_types,
                },
            };
        }

        pub fn returnFromHostTyped(
            self: *AwaitingHost,
            results: anytype,
            fuel: *Fuel,
        ) error{ValueTypeOrCountMismatch}!State {
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

        // pub fn trapWithHostCode(self: *AwaitingHost, code: u31) State {
        //     const interp: *Interpreter = self.interpreter.get();
        //     interp.version.increment();
        //     return State{
        //         .trapped = .init(),
        //     };
        // }
    };

    pub const Trapped = struct {
        interpreter: Wrapper,
        /// `null` if the trap occurred during module instantiation *before* the it's `start` function
        /// (if it exists) was invoked.
        ///
        /// A pointer, rather than an offset, is used as modifications to the stack are not alloewd
        /// in the `Trapped` state.
        frame: ?*align(@sizeOf(Value)) const StackFrame,
        trap: Trap,

        fn init(interp: Wrapper, frame: StackFrame.Offset, trap: Trap) Trapped {
            return .{
                .interpreter = interp,
                .frame = interp.get().stack.stackFrame(frame),
                .trap = trap,
            };
        }
    };

    /// Indicates that a WASM function being called by WASM needs to be
    /// validated.
    ///
    /// In this state, the instruction pointer refers to the interrupted `call` instruction to
    /// execute again.
    pub const AwaitingValidation = struct {
        padding: enum(usize) { padding = 0 } = .padding,

        const interpreter = State.stateInterpreterPtr;

        // pub fn waitForLazyValidation(Timeout)

        pub fn validate(
            self: *AwaitingValidation,
            /// Used to allocate information about the function body, such as
            /// the the side table.
            code_allocator: Allocator,
            scratch: *std.heap.ArenaAllocator,
            fuel: *Fuel,
        ) error{OutOfMemory}!State {
            _ = self;
            _ = code_allocator;
            _ = scratch;
            _ = fuel;
            @compileError("TODO: lazy validation");
            // TODO: call pushStackFrame then reset len ala CallStackExhaustion.resumeExecution()

            // const interp: *Interpreter = self.interpreter();
            // const current_frame = interp.currentFrame();

            // const callee = current_frame.function;
            // const function = callee.expanded().wasm;
            // const code = function.code();
            // const finished = code.validate(
            //     code_allocator,
            //     function.module.header().module,
            //     scratch,
            // ) catch {
            //     interp.state = .{
            //         .trapped = Trap.init(
            //             .lazy_validation_failure,
            //             .{ .function = function.idx },
            //         ),
            //     };

            //     return &interp.state;
            // };

            // if (finished) {
            //     current_frame.wasm = .{
            //         .instructions = Instructions.init(
            //             code.inner.instructions_start,
            //             code.inner.instructions_end,
            //         ),
            //         .branch_table = code.inner.side_table_ptr,
            //     };

            //     _ = interp.allocateValueStackSpace(alloca, &code.inner) catch {
            //         interp.state = .{
            //             .call_stack_exhaustion = .{
            //                 .callee = callee,
            //                 .values_base = @intCast(interp.value_stack.items.len),
            //                 .signature = callee.signature(),
            //             },
            //         };

            //         return &interp.state;
            //     };

            //     interp.state = .{ .awaiting_host = .{ .types = &.{} } };
            //     interp.enterMainLoop(fuel);
            // }

            // return &interp.state;
        }
    };

    /// A call instruction required pushing a new stack frame, which required a reallocation of the
    /// `call_stack`.
    ///
    /// In this state, the instruction pointer refers to the `call` instruction to execute again.
    pub const CallStackExhaustion = struct {
        callee: runtime.FuncAddr,
        interpreter: Wrapper,

        pub fn resumeExecution(
            self: CallStackExhaustion,
            alloca: Allocator,
            fuel: *Fuel,
        ) error{OutOfMemory}!State {
            const interp: *Interpreter = self.interpreter.get();
            const saved_stack_len = interp.stack.len;
            _ = try interp.stack.reserveStackFrame(alloca, .preallocated, self.callee);
            errdefer comptime unreachable;
            std.debug.assert(interp.stack.len == saved_stack_len);

            interp.version.increment();
            return interp.enterMainLoop(fuel);
        }
    };

    /// Execution of WASM bytecode was interrupted.
    ///
    /// The host can stop using the interpreter further, resume execution with more fuel by calling
    /// `.resumeExecution()`, or reuse the interpreter for a new computation after calling `.reset()`.
    ///
    /// In this state, the IP of the current frame refers to the instruction after the one that
    /// caused the interrupt, or if `cause == .out_of_fuel`, the instruction that was not
    /// executed when fuel ran out.
    pub const Interrupted = struct {
        interpreter: Wrapper,
        cause: InterruptionCause,

        /// Resumes execution of WASM bytecode after being `interrupted`.
        pub fn resumeExecution(self: Interrupted, fuel: *Fuel) State {
            const interp: *Interpreter = self.interpreter.get();
            interp.version.increment();
            return interp.enterMainLoop(fuel);
        }
    };

    const initial = State{
        .awaiting_host = .{ .types = &[0]Module.ValType{} },
    };
};

const ModuleInstantiationSetupError = union(enum) {
    memory_access_out_of_bounds: Trap.MemoryAccessOutOfBounds,
    table_access_out_of_bounds: Trap.TableAccessOutOfBounds,
};

/// Performs the steps of module instantiation up to but excluding the invocation of the *start*
/// function.
fn moduleInstantiationSetup(
    module: *runtime.ModuleAlloc,
    err: *ModuleInstantiationSetupError,
) error{ModuleInstantiationTrapped}!void {
    const module_inst = module.requiring_instantiation.header();
    const wasm = module_inst.module;
    const global_types = wasm.globalTypes()[wasm.inner.raw.global_import_count..];
    for (
        wasm.inner.raw.global_exprs[0..global_types.len],
        module_inst.definedGlobalValues(),
        global_types,
    ) |*init_expr, global_value, *global_type| {
        errdefer comptime unreachable;
        switch (init_expr.*) {
            .i32_or_f32 => |n32| {
                std.debug.assert(global_type.val_type == .i32 or global_type.val_type == .f32);
                @as(*u32, @ptrCast(@alignCast(global_value))).* = n32;
            },
            .i64_or_f64 => |n64| {
                std.debug.assert(global_type.val_type == .i64 or global_type.val_type == .f64);
                @as(*u64, @ptrCast(@alignCast(global_value))).* = n64;
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

    for (wasm.inner.raw.active_elems[0..wasm.inner.raw.active_elems_count]) |*active_elem| {
        const offset: u32 = offset: switch (active_elem.header.offset_tag) {
            .@"i32.const" => active_elem.offset.@"i32.const",
            .@"global.get" => {
                const global = module_inst.globalAddr(active_elem.offset.@"global.get");
                std.debug.assert(global.global_type.val_type == .i32);
                break :offset @as(*const u32, @ptrCast(@alignCast(global.value))).*;
            },
        };

        runtime.TableInst.init(
            active_elem.header.table,
            module.requiring_instantiation,
            active_elem.header.elements,
            null,
            0,
            offset,
        ) catch |e| switch (e) {
            error.TableAccessOutOfBounds => {
                err.* = .{
                    .table_access_out_of_bounds = .{
                        .table = active_elem.header.table,
                        .cause = .@"table.init",
                    },
                };
                return error.ModuleInstantiationTrapped;
            },
        };

        module_inst.elemSegmentDropFlag(active_elem.header.elements).drop();
    }

    for (wasm.inner.raw.active_datas[0..wasm.inner.raw.active_datas_count]) |*active_data| {
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
        mem.init(src, @intCast(src.len), 0, offset) catch |e| switch (e) {
            error.MemoryAccessOutOfBounds => {
                err.* = .{
                    .memory_access_out_of_bounds = .init(
                        active_data.header.memory,
                        .@"memory.init",
                        {},
                    ),
                };
                return error.ModuleInstantiationTrapped;
            },
        };

        module_inst.dataSegmentDropFlag(active_data.data).drop();
    }
}

fn currentFrame(
    interp: anytype,
) ?Stack.ChangePointee(@TypeOf(&interp.stack), .one, @sizeOf(Value), StackFrame) {
    return interp.stack.stackFrame(interp.current_frame);
}

const Ip = Module.Code.Ip;
/// Pointer to the last `end` instruction which denotes an implicit return from the function.
const Eip = *const Module.Code.End;

/// The Side-Table Pointer.
const Stp = packed struct(usize) {
    ptr: [*]const Module.Code.SideTableEntry,

    fn checkBounds(s: Stp, interp: *const Interpreter) void {
        const stp = @intFromPtr(s.ptr);
        const current_frame: *align(@sizeOf(Value)) const StackFrame = interp.currentFrame().?;
        const code = current_frame.function.expanded().wasm.code();
        std.debug.assert(@intFromPtr(code.inner.side_table_ptr) <= stp);
        std.debug.assert(stp < @intFromPtr(code.inner.side_table_ptr + code.inner.side_table_len));
    }
};

const SideTable = packed struct(usize) {
    next: Stp,

    fn init(stp: Stp) SideTable {
        return .{ .next = stp };
    }

    fn increment(table: *SideTable, interp: *const Interpreter) void {
        table.next.ptr += 1;
        table.next.checkBounds(interp);
    }

    fn addPtrWithOffset(ptr: anytype, offset: isize) @TypeOf(ptr) {
        std.debug.assert(@typeInfo(@TypeOf(ptr)) == .pointer);
        const sum = if (offset < 0) ptr - @abs(offset) else ptr + @as(usize, @intCast(offset));
        // std.debug.print(" > {*} + {} = {*}\n", .{ ptr, offset, sum });
        return sum;
    }

    fn takeBranch(
        table: *SideTable,
        interp: *Interpreter,
        base_ip: Ip,
        i: *Instr,
        vals: *ValStack,
        branch: u32,
    ) void {
        const current_frame: *align(@sizeOf(Value)) const StackFrame = interp.currentFrame().?;
        const code = current_frame.function.expanded().wasm.code();
        const wasm_base_ptr = @intFromPtr(current_frame.function.expanded().wasm
            .module.header().module.inner.wasm.ptr);

        const target: *const Module.Code.SideTableEntry = &table.next.ptr[branch];
        std.debug.assert(@intFromPtr(code.inner.side_table_ptr) <= @intFromPtr(target));
        std.debug.assert(@intFromPtr(target) <=
            @intFromPtr(code.inner.side_table_ptr + code.inner.side_table_len));

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

        i.next = addPtrWithOffset(base_ip, target.delta_ip.done);
        std.debug.assert(@intFromPtr(code.inner.instructions_end) == @intFromPtr(i.end));
        _ = i.bytes();
        std.debug.assert(@intFromPtr(code.inner.instructions_start) <= @intFromPtr(i.next));

        // std.debug.print(
        //     " ? NEXT[{X:0>6}]: 0x{X} ({s})\n",
        //     .{
        //         @intFromPtr(i.p) - wasm_base_ptr,
        //         i.p[0],
        //         @tagName(@as(opcodes.ByteOpcode, @enumFromInt(i.p[0]))),
        //     },
        // );

        table.next.ptr = addPtrWithOffset(table.next.ptr + branch, target.delta_stp);
        table.next.checkBounds(interp);

        // std.debug.print(
        //     " ? STP=#{}\n",
        //     .{(@intFromPtr(s.*) - @intFromPtr(code.inner.side_table_ptr)) / @sizeOf(Module.Code.SideTableEntry)},
        // );

        // std.debug.print(" ? value stack height was {}\n", .{vals.items.len});

        const vals_top_offset: u32 = @intCast(vals.stack.ptr - interp.stack.base);
        const dst_start_offset = vals_top_offset - target.pop_count;

        const src = vals.top(interp, target.copy_count);
        const dst = interp.stack.slice()[dst_start_offset .. dst_start_offset + target.copy_count];
        @memmove(dst, src);
        vals.stack.ptr = addPtrWithOffset(
            vals.stack.ptr,
            @as(i16, target.copy_count) - target.pop_count,
        );

        // std.debug.print(" ? value stack height is {}\n", .{});

        std.debug.assert(vals_top_offset == dst_start_offset + target.copy_count);
        std.debug.assert(
            @intFromPtr(current_frame.valueStackBase()) <= @intFromPtr(vals.stack.ptr),
        );
    }
};

/// The value Stack Pointer.
const Sp = packed struct(usize) {
    /// Refers to `&Stack.base[Stack.len]`.
    ptr: [*]align(@sizeOf(Value)) Value,

    fn init(stack: *const Stack) Sp {
        return .{ .ptr = stack.base + stack.len };
    }
};

/// The WebAssembly [value stack], which contains the operands that instructions manipulate.
///
/// [value stack]: https://webassembly.github.io/spec/core/exec/runtime.html#stack
const ValStack = extern struct {
    /// Points to the "top" of the value stack, which is just past the last valid value.
    stack: Sp,

    fn init(stack: Sp, interp: *const Interpreter) ValStack {
        std.debug.assert(@intFromPtr(interp.stack.base) <= @intFromPtr(stack.ptr));
        std.debug.assert(
            @intFromPtr(stack.ptr) <= @intFromPtr(interp.stack.base + interp.stack.cap),
        );
        return .{
            .stack = stack,
        };
    }

    fn top(
        vals: *const ValStack,
        interp: *const Interpreter,
        count: u32,
    ) []align(@sizeOf(Value)) Value {
        const values = @as(
            [*]align(@sizeOf(Value)) Value,
            vals.stack.ptr - count,
        )[0..count];

        // Check for underflow
        if (builtin.mode == .Debug) {
            std.debug.assert(@intFromPtr(interp.stack.base) <= @intFromPtr(values.ptr));
            std.debug.assert(
                @intFromPtr(vals.stack.ptr) <= @intFromPtr(interp.stack.base + interp.stack.cap),
            );

            const current_frame: ?*align(@sizeOf(Value)) const StackFrame = interp.currentFrame();
            if (current_frame) |frame| {
                const value_stack_base = frame.valueStackBase();
                if (@intFromPtr(value_stack_base) > @intFromPtr(values.ptr)) {
                    std.debug.panic(
                        "value stack underflow!\n" ++
                            "{*} - current function value base\n" ++
                            "{*} - current frame\n" ++
                            "{*} - start of {} top values\n" ++
                            "{*} - current stack top\n" ++
                            "{*} - stack base\n",
                        .{
                            value_stack_base,
                            frame,
                            values.ptr,
                            count,
                            vals.stack.ptr,
                            interp.stack.base,
                        },
                    );
                }
            }
        }

        return values;
    }

    fn topArray(
        vals: *const ValStack,
        interp: *const Interpreter,
        comptime count: u32,
    ) *align(@sizeOf(Value)) [count]Value {
        return vals.top(interp, count)[0..count];
    }

    /// Asserts that popping does not underflow the stack, writing into the
    /// `StackFrame` itself or the data of previous stack frames.
    fn popSlice(
        vals: *ValStack,
        interp: *const Interpreter,
        count: u32,
    ) []align(@sizeOf(Value)) Value {
        const popped = vals.top(interp, count);
        vals.stack.ptr = popped.ptr;
        return popped;
    }

    fn popArray(
        vals: *ValStack,
        interp: *const Interpreter,
        comptime count: u32,
    ) *align(@sizeOf(Value)) [count]Value {
        comptime {
            std.debug.assert(count > 0);
        }
        return vals.popSlice(interp, count)[0..count];
    }

    /// `.@"0"` always refers to the value that was the lowest on the stack.
    fn TypedValues(comptime types: []const Value.Tag) type {
        var fields: [types.len]type = undefined;
        for (types, &fields) |ty, *dst| {
            dst.* = ty.Type();
        }

        return std.meta.Tuple(&fields);
    }

    fn popTyped(
        vals: *ValStack,
        interp: *const Interpreter,
        comptime types: []const Value.Tag,
    ) TypedValues(types) {
        const values = vals.popArray(interp, types.len);
        var typed: TypedValues(types) = undefined;
        inline for (types, values, &typed) |ty, *src, *dst| {
            dst.* = @field(src, @tagName(ty));
        }
        return typed;
    }

    fn pushSlice(
        vals: *ValStack,
        interp: *const Interpreter,
        count: u32,
    ) []align(@sizeOf(Value)) Value {
        const pushed = vals.stack.ptr[0..count];
        @memset(pushed, undefined);

        vals.stack.ptr += count;
        // Check for overflow
        if (builtin.mode == .Debug) {
            std.debug.assert( // value stack overflow
                @intFromPtr(vals.stack.ptr) <=
                    @intFromPtr(interp.stack.base + interp.stack.cap),
            );
        }

        return pushed;
    }

    fn pushArray(
        vals: *ValStack,
        interp: *const Interpreter,
        comptime count: u32,
    ) *align(@sizeOf(Value)) [count]Value {
        comptime {
            std.debug.assert(count > 0);
        }
        return vals.pushSlice(interp, count)[0..count];
    }

    fn pushTyped(
        vals: *ValStack,
        interp: *const Interpreter,
        comptime types: []const Value.Tag,
        values: TypedValues(types),
    ) void {
        const pushed = vals.pushArray(interp, types.len);
        inline for (types, pushed, &values) |ty, *dst, src| {
            dst.* = @unionInit(Value, @tagName(ty), src);
        }
    }
};

const Locals = packed struct(usize) {
    ptr: [*]align(@sizeOf(Value)) Value,

    fn get(
        locals: Locals,
        interp: *Interpreter,
        idx: u32,
    ) *align(@sizeOf(Value)) Value {
        const locals_slice = if (builtin.mode == .Debug) checked: {
            const current_frame: *align(@sizeOf(Value)) StackFrame = interp.currentFrame().?;
            break :checked current_frame.localValues(interp.stack.slice());
        } else locals.ptr[0 .. idx + 1];

        std.debug.assert(@intFromPtr(locals.ptr) == @intFromPtr(locals_slice.ptr));
        return &locals_slice[idx];
    }
};

// TODO(Zig): waiting for a calling convention w/o callee-saved registers
// - (i.e. `preserve_none` or `ghccc`)
const OpcodeHandler = fn (
    ip: Ip,
    sp: Sp,
    fuel: *Fuel,
    stp: Stp,
    // `x86_64-windows` passes 4 parameters in registers
    locals: Locals,
    interp: *Interpreter,
    // `x86_64` System V ABI passes 6 parameters in registers
    eip: Eip,
    state: *State,
    module: runtime.ModuleInst,
) StateTransition;

// const WrappedOpcodeHandler = fn (
//     i: *Instructions,
//     vals: *ValStack,
//     fuel: *Fuel,
//     stp: Stp,
//     locals: Locals,
//     interp: *Interpreter,
//     state: *State,
//     module: runtime.ModuleInst,
// ) StateTransition; // allow void return if handler doesn't trap

// fn wrappedOpcodeHandler(handler: WrappedOpcodeHandler) OpcodeHandler {
//     return struct {
//         fn wrapped(
//             ip: Ip,
//             sp: Sp,
//             fuel: *Fuel,
//             stp: Stp,
//             locals: Locals,
//             interp: *Interpreter,
//             eip: Eip,
//             state: *State,
//             module: runtime.ModuleInst,
//         ) StateTransition {}
//     }.wrapped;
// }

// Is a `packed struct` to work around https://github.com/ziglang/zig/issues/18189
const StateTransition = packed struct(std.meta.Int(.unsigned, @bitSizeOf(Version))) {
    version: Version,
    serialize_token: SerializeToken,

    const SerializeToken = enum(u0) {
        wrote_ip_and_stp_to_the_current_stack_frame,

        comptime {
            std.debug.assert(@sizeOf(SerializeToken) == 0);
        }
    };

    fn serializeStackFrame(
        instr: Instr,
        vals: ValStack,
        stp: SideTable,
        interp: *Interpreter,
    ) SerializeToken {
        const current_frame: *align(@sizeOf(Value)) StackFrame = interp.currentFrame().?;
        const wasm_frame: *align(@sizeOf(Value)) StackFrame.Wasm = current_frame.wasmFrame();
        wasm_frame.ip = instr.next;
        wasm_frame.stp = stp.next;
        std.debug.assert(@intFromPtr(wasm_frame.eip) == @intFromPtr(instr.end));

        std.debug.assert(@intFromPtr(interp.stack.base) <= @intFromPtr(vals.stack.ptr));
        std.debug.assert(
            @intFromPtr(vals.stack.ptr) < @intFromPtr(interp.stack.base + interp.stack.cap),
        );
        interp.stack.len = @intCast(vals.stack.ptr - interp.stack.base);
        std.debug.assert(interp.stack.len <= interp.stack.cap);

        return .wrote_ip_and_stp_to_the_current_stack_frame;
    }

    fn trap(
        instr: Instr,
        vals: ValStack,
        stp: SideTable,
        interp: *Interpreter,
        state: *State,
        info: Trap,
    ) StateTransition {
        @branchHint(.unlikely);
        const serialized = serializeStackFrame(instr, vals, stp, interp);
        interp.version.increment();

        state.* = .{
            .trapped = State.Trapped.init(.init(interp), interp.current_frame, info),
        };
        return .{ .version = interp.version, .serialize_token = serialized };
    }

    fn interrupted(
        instr: Instr,
        vals: ValStack,
        stp: SideTable,
        interp: *Interpreter,
        state: *State,
        cause: InterruptionCause,
    ) StateTransition {
        const serialized = serializeStackFrame(instr, vals, stp, interp);
        interp.version.increment();

        state.* = .{ .interrupted = .{ .interpreter = .init(interp), .cause = cause } };
        return .{ .version = interp.version, .serialize_token = serialized };
    }

    fn awaitingHost(
        vals: ValStack,
        interp: *Interpreter,
        state: *State,
        callee_signature: *const Module.FuncType,
    ) StateTransition {
        interp.version.increment();

        const frame: ?*align(@sizeOf(Value)) StackFrame = interp.currentFrame();
        state.* = .{
            .awaiting_host = .{
                .interpreter = .init(interp),
                .param_types = if (frame) |called| called.signature.parameters() else &.{},
                .result_types = callee_signature.results(),
            },
        };
        interp.stack.len = @intCast(vals.stack.ptr - interp.stack.base);
        std.debug.assert(
            @intFromPtr(vals.stack.ptr) <= @intFromPtr(interp.stack.base + interp.stack.cap),
        );
        return .{
            .version = interp.version,
            .serialize_token = .wrote_ip_and_stp_to_the_current_stack_frame,
        };
    }

    fn callStackExhaustion(
        call_ip: Ip,
        eip: Eip,
        vals: ValStack,
        stp: SideTable,
        interp: *Interpreter,
        state: *State,
        callee: runtime.FuncAddr,
    ) StateTransition {
        const serialized = serializeStackFrame(.init(call_ip, eip), vals, stp, interp);
        interp.version.increment();

        state.* = .{ .call_stack_exhaustion = .{ .callee = callee, .interpreter = .init(interp) } };
        return .{ .version = interp.version, .serialize_token = serialized };
    }
};

const Instr = struct {
    /// Invariant that `start <= next and next <= end + 1`.
    next: Ip,
    end: Eip,

    inline fn init(ip: Ip, eip: Eip) Instr {
        const instr = Instr{ .next = ip, .end = eip };
        _ = instr.bytes();
        return instr;
    }

    inline fn bytes(i: Instr) []const u8 {
        return i.next[0..(@intFromPtr(i.end) + 1 - @intFromPtr(i.next))];
    }

    inline fn readByteArray(i: *Instr, comptime n: usize) *const [n]u8 {
        const arr = i.bytes()[0..n];
        i.next += n;
        _ = i.bytes();
        return arr;
    }

    pub inline fn readByte(i: *Instr) u8 {
        const b = i.readByteArray(1)[0];
        return b;
    }

    fn readIdxRawRemaining(i: *Instr, first_byte: u8) u32 {
        var value: u32 = first_byte;
        for (1..5) |idx| {
            const next_byte = i.readByte();
            value |= @shlExact(
                @as(u32, next_byte),
                @as(u5, @intCast(idx * 7)),
            );

            if (next_byte & 0x80 == 0) {
                return value;
            }
        }

        unreachable;
    }

    inline fn readIdxRaw(i: *Instr) u32 {
        const first_byte = i.readByte();
        if (first_byte & 0x80 == 0) {
            return first_byte;
        } else {
            @branchHint(.unlikely);
            return i.readIdxRawRemaining(first_byte);
        }
    }

    inline fn readIdx(reader: *Instr, comptime I: type) I {
        return @enumFromInt(
            @as(@typeInfo(I).@"enum".tag_type, @intCast(reader.readIdxRaw())),
        );
    }

    inline fn readIleb128(reader: *Instr, comptime I: type) I {
        comptime {
            std.debug.assert(@typeInfo(I).int.signedness == .signed);
        }

        const U = std.meta.Int(.unsigned, @typeInfo(I).int.bits);
        const max_byte_len =
            comptime std.math.divCeil(u16, @typeInfo(I).int.bits, 7) catch unreachable;
        const Result = std.meta.Int(.unsigned, max_byte_len * 8);

        var result: Result = 0;
        for (0..max_byte_len) |i| {
            const shift: std.math.Log2Int(I) = @intCast(i * 7);
            const byte = reader.readByte();

            if (byte & 0x80 == 0) {
                if (i < max_byte_len - 1 and byte & 0x40 != 0) {
                    // value is signed, sign extension is needed
                    result |= @bitCast(
                        std.math.shl(
                            std.meta.Int(.signed, @typeInfo(Result).int.bits),
                            -1,
                            shift + 7,
                        ),
                    );
                }

                return @bitCast(@as(U, @truncate(result)));
            } else {
                result |= @shlExact(@as(Result, byte & 0x7F), shift);
            }
        }

        unreachable;
    }

    inline fn readNextOpcodeHandler(
        reader: *Instr,
        fuel: *Fuel,
        locals: Locals,
        interp: *Interpreter,
        module: runtime.ModuleInst,
    ) *const OpcodeHandler {
        if (builtin.mode == .Debug) {
            const current_frame: *align(@sizeOf(Value)) const StackFrame = interp.currentFrame().?;
            std.debug.assert(
                @intFromPtr(module.inner) ==
                    @intFromPtr(current_frame.function.expanded().wasm.module.inner),
            );
            std.debug.assert(
                @intFromPtr(locals.ptr) ==
                    @intFromPtr(current_frame.localValues(interp.stack.allocatedSlice()).ptr),
            );
        }

        if (fuel.remaining == 0) {
            @branchHint(.unlikely);
            return opcode_handlers.outOfFuelHandler;
        } else {
            const next_opcode = reader.readByte();

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

    inline fn dispatchNextOpcode(
        reader: Instr,
        vals: ValStack,
        fuel: *Fuel,
        stp: SideTable,
        locals: Locals,
        interp: *Interpreter,
        state: *State,
        module: runtime.ModuleInst,
    ) StateTransition {
        var i = reader;
        const handler = i.readNextOpcodeHandler(fuel, locals, interp, module);
        return @call(
            .always_tail,
            handler,
            .{
                i.next,
                vals.stack,
                fuel,
                stp.next,
                locals,
                interp,
                i.end,
                state,
                module,
            },
        );
    }

    inline fn skipValType(reader: *Instr) void {
        const b = reader.readByte();
        _ = @as(Module.ValType, @enumFromInt(b));
    }

    inline fn skipBlockType(reader: *Instr) void {
        {
            // Assume that most block types are one byte long
            const first_byte = reader.readByte();
            // Does this even have a performance impact?
            if (first_byte & 0x80 == 0) {
                @branchHint(.likely);
                return;
            }
        }

        for (0..4) |_| {
            const byte = reader.readByte();
            if (byte & 0x80 == 0) {
                return;
            }
        }

        unreachable;
    }
};

/// Moves return values to their appropriate place in the value stack.
///
/// Execution of the handlers for the `end` (only when it is last opcode of a function)
/// and `return` instructions ends up here.
///
/// To ensure the interpreter cannot overflow the native stack, opcode handlers must call this
/// function via `@call` with either `.always_tail` or `always_inline`.
fn returnFromWasm(
    ip: Ip,
    sp: Sp,
    fuel: *Fuel,
    stp: Stp,
    locals: Locals,
    interp: *Interpreter,
    eip: Eip,
    state: *State,
    module: runtime.ModuleInst,
) StateTransition {
    const popped: *align(@sizeOf(Value)) StackFrame = interp.currentFrame().?;
    std.debug.assert(popped.function.expanded() == .wasm);
    std.debug.assert(@intFromPtr(popped.valueStackBase()) <= @intFromPtr(sp.ptr));

    interp.call_depth -= 1;
    interp.current_frame = popped.prev_frame;
    popped.instantiate_flag.* = true;

    const result_dst: []align(@sizeOf(Value)) Value =
        popped.localValues(interp.stack.allocatedSlice())
            .ptr[0..popped.signature.result_count];

    const caller_frame: ?*align(@sizeOf(Value)) StackFrame = interp.currentFrame();
    if (builtin.mode == .Debug) {
        const expected_checksum = popped.checksum;
        const actual_checksum = if (interp.call_depth > 0)
            caller_frame.?.calculateChecksum(
                interp.stack.allocatedSlice()[0..(result_dst.ptr - interp.stack.base)],
            )
        else
            0;

        if (expected_checksum != actual_checksum) {
            std.debug.panic(
                "bad checksum for {f}\nexpected: {X:0>32}\nactual: {X:0>32}",
                .{ caller_frame.?.function, expected_checksum, actual_checksum },
            );
        }
    }

    var vals = ValStack.init(sp, interp);
    const result_src: []align(@sizeOf(Value)) const Value =
        vals.popSlice(interp, @intCast(result_dst.len));

    @memmove(result_dst, result_src);
    vals.stack.ptr = result_dst.ptr + result_dst.len;

    const popped_signature = popped.signature;
    @memset(
        @as([]align(@sizeOf(Value)) Value, @ptrCast(popped)),
        undefined,
    );

    return_to_host: {
        if (interp.call_depth == 0) break :return_to_host;

        switch (caller_frame.?.function.expanded()) {
            .wasm => return Instr.init(ip, eip)
                .dispatchNextOpcode(vals, fuel, .init(stp), locals, interp, state, module),
            .host => break :return_to_host,
        }

        comptime unreachable;
    }

    return .awaitingHost(vals, interp, state, popped_signature);
}

/// Continues execution of WASM code up to calling the `target_function`, with arguments expected
/// to be on top of the value stack.
///
/// To ensure the interpreter cannot overflow the stack, opcode handlers must ensure this function
/// is called inline.
///
/// If enough stack space is not available, then the interpreter is interrupted and the IP is set to
/// `call_ip`, which is a pointer to the call instruction to restart.
inline fn invokeWithinWasm(
    old_i: Instr,
    old_vals: ValStack,
    fuel: *Fuel,
    old_stp: SideTable,
    interp: *Interpreter,
    state: *State,
    /// Pointer to the byte containing the call opcode.
    call_ip: Ip,
    callee: runtime.FuncAddr,
) StateTransition {
    const signature = callee.signature();

    // Overlap trick to avoid copying arguments.
    const args: []align(@sizeOf(Value)) Value = old_vals.top(interp, signature.param_count);

    if (interp.call_depth == std.math.maxInt(@FieldType(Interpreter, "call_depth"))) {
        @branchHint(.cold);
        return .callStackExhaustion(call_ip, old_i.end, old_vals, old_stp, interp, state, callee);
    }

    var new_vals = old_vals;

    const new_frame = setup: {
        interp.stack.len = @intCast(new_vals.stack.ptr - interp.stack.base);
        std.debug.assert(interp.stack.len <= interp.stack.cap);

        defer new_vals.stack.ptr = interp.stack.base + interp.stack.len;

        break :setup interp.stack.pushStackFrameWithinCapacity(
            interp.current_frame,
            &interp.dummy_instantiate_flag,
            .preallocated,
            callee,
        ) catch |e| switch (e) {
            error.OutOfMemory => return .callStackExhaustion(
                call_ip,
                old_i.end,
                old_vals,
                old_stp,
                interp,
                state,
                callee,
            ),
            error.ValidationNeeded => @panic("TODO: awaiting_validation"),
        };
    };

    interp.currentFrame().?.wasmFrame().* = StackFrame.Wasm{
        .ip = old_i.next,
        .eip = old_i.end,
        .stp = old_stp.next,
    };

    interp.call_depth += 1; // overflow check before frame was pushed
    interp.current_frame = new_frame.offset;

    const new_locals: []align(@sizeOf(Value)) Value =
        new_frame.frame.localValues(interp.stack.slice());
    std.debug.assert(@intFromPtr(new_locals.ptr) == @intFromPtr(args.ptr));
    std.debug.assert(args.len <= new_locals.len);

    switch (callee.expanded()) {
        .wasm => |wasm| {
            const new_wasm_frame: *align(@sizeOf(Value)) StackFrame.Wasm =
                new_frame.frame.wasmFrame();
            return Instr.init(new_wasm_frame.ip, new_wasm_frame.eip).dispatchNextOpcode(
                new_vals,
                fuel,
                .init(new_wasm_frame.stp),
                Locals{ .ptr = new_locals.ptr },
                interp,
                state,
                wasm.module,
            );
        },
        .host => |host| return .awaitingHost(new_vals, interp, state, &host.func.signature),
    }
}

const MemArg = struct {
    mem: *const runtime.MemInst,
    idx: Module.MemIdx,
    offset: u32,

    fn read(i: *Instr, module: runtime.ModuleInst) MemArg {
        // TODO: Spec probably only allows reading single byte here!
        // align, maximum is 16 bytes (1 << 4)
        _ = @as(u3, @intCast(i.readByte()));
        const mem_idx = Module.MemIdx.default;
        return .{
            .offset = @as(u32, i.readIdxRaw()),
            .mem = module.header().memAddr(mem_idx),
            .idx = mem_idx,
        };
    }

    fn trap(
        mem_arg: MemArg,
        address: usize,
        size: std.mem.Alignment,
    ) Trap {
        return Trap.init(.memory_access_out_of_bounds, .init(
            mem_arg.idx,
            .access,
            .{
                .address = address + mem_arg.offset,
                .size = size,
                .maximum = mem_arg.mem.limit,
            },
        ));
    }
};

fn linearMemoryAccessor(
    /// How many bytes are read to and written from linear memory.
    ///
    /// Must be a positive power of two.
    comptime access_size: std.mem.Alignment,
    comptime handler: fn (
        *Instr,
        *ValStack,
        *Fuel,
        SideTable,
        Locals,
        *Interpreter,
        *State,
        runtime.ModuleInst,
        *[access_size.toByteUnits()]u8,
    ) StateTransition,
) OpcodeHandler {
    return struct {
        comptime {
            std.debug.assert(builtin.cpu.arch.endian() == .little);
        }

        const access_size_bytes: comptime_int = access_size.toByteUnits();

        fn accessLinearMemory(
            ip: Ip,
            sp: Sp,
            fuel: *Fuel,
            stp: Stp,
            locals: Locals,
            interp: *Interpreter,
            eip: Eip,
            state: *State,
            module: runtime.ModuleInst,
        ) StateTransition {
            var i = Instr.init(ip, eip);
            var vals = ValStack.init(sp, interp);
            const side_table = SideTable.init(stp);

            const mem_arg = MemArg.read(&i, module);
            const base_addr: u32 = @bitCast(vals.popTyped(interp, &.{.i32}).@"0");
            // std.debug.print(" > access of size {} @ 0x{X} + {} into memory size={}\n", .{ access_size, base_addr, mem_arg.offset, mem_arg.mem.size });
            const effective_addr = std.math.add(u32, base_addr, mem_arg.offset) catch
                return .trap(i, vals, side_table, interp, state, mem_arg.trap(base_addr, access_size));
            const end_addr = std.math.add(u32, effective_addr, access_size_bytes - 1) catch
                return .trap(i, vals, side_table, interp, state, mem_arg.trap(base_addr, access_size));

            return if (mem_arg.mem.size <= end_addr)
                .trap(i, vals, side_table, interp, state, mem_arg.trap(base_addr, access_size))
            else
                @call(
                    .always_inline,
                    handler,
                    .{
                        &i,
                        &vals,
                        fuel,
                        side_table,
                        locals,
                        interp,
                        state,
                        module,
                        mem_arg.mem.bytes()[effective_addr..][0..access_size_bytes],
                    },
                );
        }
    }.accessLinearMemory;
}

fn linearMemoryHandlers(comptime field: Value.Tag) type {
    return struct {
        comptime {
            std.debug.assert(builtin.cpu.arch.endian() == .little);
        }

        const T = field.Type();

        fn performLoad(
            i: *Instr,
            vals: *ValStack,
            fuel: *Fuel,
            stp: SideTable,
            locals: Locals,
            interp: *Interpreter,
            state: *State,
            module: runtime.ModuleInst,
            access: *[@sizeOf(T)]u8,
        ) StateTransition {
            vals.pushTyped(interp, &.{field}, .{@as(T, @bitCast(access.*))});

            return i.dispatchNextOpcode(vals.*, fuel, stp, locals, interp, state, module);
        }

        pub const load = linearMemoryAccessor(.fromByteUnits(@sizeOf(T)), performLoad);

        fn performStore(
            i: *Instr,
            vals: *ValStack,
            fuel: *Fuel,
            stp: SideTable,
            locals: Locals,
            interp: *Interpreter,
            state: *State,
            module: runtime.ModuleInst,
            access: *[@sizeOf(T)]u8,
        ) StateTransition {
            access.* = @bitCast(vals.popTyped(interp, &.{field}).@"0");
            return i.dispatchNextOpcode(vals.*, fuel, stp, locals, interp, state, module);
        }

        pub const store = linearMemoryAccessor(.fromByteUnits(@sizeOf(T)), performStore);
    };
}

fn extendingLinearMemoryLoad(comptime field: Value.Tag, comptime S: type) OpcodeHandler {
    return struct {
        const T = field.Type();

        comptime {
            std.debug.assert(std.meta.hasUniqueRepresentation(S));
            std.debug.assert(@sizeOf(S) < @sizeOf(T));
        }

        fn handler(
            i: *Instr,
            vals: *ValStack,
            fuel: *Fuel,
            stp: SideTable,
            locals: Locals,
            interp: *Interpreter,
            state: *State,
            module: runtime.ModuleInst,
            access: *[@sizeOf(S)]u8,
        ) StateTransition {
            vals.pushTyped(interp, &.{field}, .{@as(S, @bitCast(access.*))});
            return i.dispatchNextOpcode(vals.*, fuel, stp, locals, interp, state, module);
        }

        pub const extendingLoad = linearMemoryAccessor(.fromByteUnits(@sizeOf(S)), handler);
    }.extendingLoad;
}

fn narrowingLinearMemoryStore(
    comptime field: Value.Tag,
    comptime access_size: std.mem.Alignment,
) OpcodeHandler {
    return struct {
        const T = field.Type();
        const S = std.meta.Int(.signed, access_size.toByteUnits() * 8);

        comptime {
            std.debug.assert(std.meta.hasUniqueRepresentation(S));
            std.debug.assert(@sizeOf(S) < @sizeOf(T));
        }

        fn handler(
            i: *Instr,
            vals: *ValStack,
            fuel: *Fuel,
            stp: SideTable,
            locals: Locals,
            interp: *Interpreter,
            state: *State,
            module: runtime.ModuleInst,
            access: *[@sizeOf(S)]u8,
        ) StateTransition {
            const narrowed: S = @truncate(vals.popTyped(interp, &.{field}).@"0");
            access.* = @bitCast(narrowed);
            return i.dispatchNextOpcode(vals.*, fuel, stp, locals, interp, state, module);
        }

        pub const narrowingLoad = linearMemoryAccessor(access_size, handler);
    }.narrowingLoad;
}

// fn BinOp(comptime value_field: Value.Tag) type {
//     const T = value_field.Type();
//     return fn (c_1: T, c_2: T) T;
// }

/// https://webassembly.github.io/spec/core/exec/instructions.html#exec-binop
fn defineBinOp(
    comptime value_field: Value.Tag,
    comptime op: anytype,
    comptime trap: anytype,
) OpcodeHandler {
    return struct {
        fn binOpHandler(
            ip: Ip,
            sp: Sp,
            fuel: *Fuel,
            stp: Stp,
            locals: Locals,
            interp: *Interpreter,
            eip: Eip,
            state: *State,
            module: runtime.ModuleInst,
        ) StateTransition {
            var i = Instr.init(ip, eip);
            var vals = ValStack.init(sp, interp);

            const operands = vals.popTyped(interp, &(.{value_field} ** 2));
            const c_2 = operands[1];
            const c_1 = operands[0];
            const result = @call(.always_inline, op, .{ c_1, c_2 }) catch |e|
                return .trap(i, vals, .init(stp), interp, state, @call(.always_inline, trap, .{e}));

            vals.pushTyped(interp, &.{value_field}, .{result});

            return i.dispatchNextOpcode(vals, fuel, .init(stp), locals, interp, state, module);
        }
    }.binOpHandler;
}

/// https://webassembly.github.io/spec/core/exec/instructions.html#exec-unop
fn defineUnOp(
    comptime value_field: Value.Tag,
    comptime op: fn (c_1: value_field.Type()) value_field.Type(),
) OpcodeHandler {
    return struct {
        fn unOpHandler(
            ip: Ip,
            sp: Sp,
            fuel: *Fuel,
            stp: Stp,
            locals: Locals,
            interp: *Interpreter,
            eip: Eip,
            state: *State,
            module: runtime.ModuleInst,
        ) StateTransition {
            var i = Instr.init(ip, eip);
            var vals = ValStack.init(sp, interp);

            const c_1 = vals.popTyped(interp, &.{value_field}).@"0";
            const result = @call(.always_inline, op, .{c_1});
            vals.pushTyped(interp, &.{value_field}, .{result});

            return i.dispatchNextOpcode(vals, fuel, .init(stp), locals, interp, state, module);
        }
    }.unOpHandler;
}

/// https://webassembly.github.io/spec/core/exec/instructions.html#exec-testop
fn defineTestOp(
    comptime value_field: Value.Tag,
    comptime op: fn (c_1: value_field.Type()) bool,
) OpcodeHandler {
    return struct {
        fn handler(
            ip: Ip,
            sp: Sp,
            fuel: *Fuel,
            stp: Stp,
            locals: Locals,
            interp: *Interpreter,
            eip: Eip,
            state: *State,
            module: runtime.ModuleInst,
        ) StateTransition {
            var i = Instr.init(ip, eip);
            var vals = ValStack.init(sp, interp);

            const c_1 = vals.popTyped(interp, &.{value_field}).@"0";
            const result = @call(.always_inline, op, .{c_1});
            vals.pushTyped(interp, &.{.i32}, .{@intFromBool(result)});

            return i.dispatchNextOpcode(vals, fuel, .init(stp), locals, interp, state, module);
        }
    }.handler;
}

/// https://webassembly.github.io/spec/core/exec/instructions.html#exec-relop
fn defineRelOp(
    comptime value_field: Value.Tag,
    comptime op: fn (c_1: value_field.Type(), c_2: value_field.Type()) bool,
) OpcodeHandler {
    return struct {
        fn handler(
            ip: Ip,
            sp: Sp,
            fuel: *Fuel,
            stp: Stp,
            locals: Locals,
            interp: *Interpreter,
            eip: Eip,
            state: *State,
            module: runtime.ModuleInst,
        ) StateTransition {
            var i = Instr.init(ip, eip);
            var vals = ValStack.init(sp, interp);

            const operands = vals.popTyped(interp, &(.{value_field} ** 2));
            const c_2 = operands[1];
            const c_1 = operands[0];
            const result = @call(.always_inline, op, .{ c_1, c_2 });
            vals.pushTyped(interp, &.{.i32}, .{@intFromBool(result)});

            return i.dispatchNextOpcode(vals, fuel, .init(stp), locals, interp, state, module);
        }
    }.handler;
}

/// https://webassembly.github.io/spec/core/exec/instructions.html#exec-cvtop
fn defineConvOp(
    comptime src_field: Value.Tag,
    comptime dst_field: Value.Tag,
    comptime op: anytype, // fn (t_1: src_field.Type()) dst_field.Type(),
    comptime trap: anytype,
) OpcodeHandler {
    return struct {
        fn handler(
            ip: Ip,
            sp: Sp,
            fuel: *Fuel,
            stp: Stp,
            locals: Locals,
            interp: *Interpreter,
            eip: Eip,
            state: *State,
            module: runtime.ModuleInst,
        ) StateTransition {
            var i = Instr.init(ip, eip);
            var vals = ValStack.init(sp, interp);

            const t_1 = vals.popTyped(interp, &.{src_field}).@"0";
            const result = @call(.always_inline, op, .{t_1}) catch |e|
                return .trap(i, vals, .init(stp), interp, state, @call(.always_inline, trap, .{e}));

            vals.pushTyped(interp, &.{dst_field}, .{result});

            return i.dispatchNextOpcode(vals, fuel, .init(stp), locals, interp, state, module);
        }
    }.handler;
}

fn integerOpcodeHandlers(comptime Signed: type) type {
    return struct {
        const Unsigned = std.meta.Int(.unsigned, @typeInfo(Signed).int.bits);
        const value_field = @field(Value.Tag, @typeName(Signed));

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

        fn @"const"(
            ip: Ip,
            sp: Sp,
            fuel: *Fuel,
            stp: Stp,
            locals: Locals,
            interp: *Interpreter,
            eip: Eip,
            state: *State,
            module: runtime.ModuleInst,
        ) StateTransition {
            var i = Instr.init(ip, eip);
            var vals = ValStack.init(sp, interp);

            const n = i.readIleb128(Signed);
            vals.pushTyped(interp, &.{value_field}, .{n});

            // std.debug.print(
            //     " > (" ++ @typeName(Signed) ++ ".const) {[0]} (0x{[0]X}) ;; height = {[1]}\n",
            //     .{ n, vals.items.len },
            // );

            return i.dispatchNextOpcode(vals, fuel, .init(stp), locals, interp, state, module);
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
        const div_s = defineBinOp(value_field, operators.div_s, Trap.initIntegerOperation);
        const div_u = defineBinOp(value_field, operators.div_u, Trap.initIntegerOperation);
        const rem_s = defineBinOp(value_field, operators.rem_s, Trap.initIntegerOperation);
        const rem_u = defineBinOp(value_field, operators.rem_u, Trap.initIntegerOperation);
        const @"and" = defineBinOp(value_field, operators.@"and", undefined);
        const @"or" = defineBinOp(value_field, operators.@"or", undefined);
        const xor = defineBinOp(value_field, operators.xor, undefined);
        const shl = defineBinOp(value_field, operators.shl, undefined);
        const shr_s = defineBinOp(value_field, operators.shr_s, undefined);
        const shr_u = defineBinOp(value_field, operators.shr_u, undefined);
        const rotl = defineBinOp(value_field, operators.rotl, undefined);
        const rotr = defineBinOp(value_field, operators.rotr, undefined);

        const trunc_f32_s = defineConvOp(.f32, value_field, operators.trunc_s, Trap.initIntegerOperation);
        const trunc_f32_u = defineConvOp(.f32, value_field, operators.trunc_u, Trap.initIntegerOperation);
        const trunc_f64_s = defineConvOp(.f64, value_field, operators.trunc_s, Trap.initIntegerOperation);
        const trunc_f64_u = defineConvOp(.f64, value_field, operators.trunc_u, Trap.initIntegerOperation);

        const trunc_sat_f32_s = defineConvOp(.f32, value_field, operators.trunc_sat_s, Trap.initIntegerOperation);
        const trunc_sat_f32_u = defineConvOp(.f32, value_field, operators.trunc_sat_u, Trap.initIntegerOperation);
        const trunc_sat_f64_s = defineConvOp(.f64, value_field, operators.trunc_sat_s, Trap.initIntegerOperation);
        const trunc_sat_f64_u = defineConvOp(.f64, value_field, operators.trunc_sat_u, Trap.initIntegerOperation);
    };
}

const i32_opcode_handlers = integerOpcodeHandlers(i32);
const i64_opcode_handlers = integerOpcodeHandlers(i64);

fn floatOpcodeHandlers(comptime F: type) type {
    return struct {
        const value_field = @field(Value.Tag, @typeName(F));
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

        fn @"const"(
            ip: Ip,
            sp: Sp,
            fuel: *Fuel,
            stp: Stp,
            locals: Locals,
            interp: *Interpreter,
            eip: Eip,
            state: *State,
            module: runtime.ModuleInst,
        ) StateTransition {
            var i = Instr.init(ip, eip);
            var vals = ValStack.init(sp, interp);

            const z = std.mem.readInt(
                std.meta.Int(.unsigned, @bitSizeOf(F)),
                i.readByteArray(@sizeOf(F)),
                .little,
            );

            vals.pushTyped(interp, &.{value_field}, .{@bitCast(z)});

            return i.dispatchNextOpcode(vals, fuel, .init(stp), locals, interp, state, module);
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

        const convert_i32_s = defineConvOp(.i32, value_field, operators.convert_s, undefined);
        const convert_i32_u = defineConvOp(.i32, value_field, operators.convert_u, undefined);
        const convert_i64_s = defineConvOp(.i64, value_field, operators.convert_s, undefined);
        const convert_i64_u = defineConvOp(.i64, value_field, operators.convert_u, undefined);
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
            ip: Ip,
            sp: Sp,
            fuel: *Fuel,
            stp: Stp,
            locals: Locals,
            interp: *Interpreter,
            eip: Eip,
            state: *State,
            module: runtime.ModuleInst,
        ) StateTransition {
            _ = sp;
            _ = fuel;
            _ = stp;
            _ = locals;
            _ = interp;
            _ = eip;
            _ = state;
            _ = module;
            std.debug.panic(
                "invalid instruction 0x{X:0>2} ... 0x{X:0>2}",
                .{ @intFromEnum(prefix), (ip - 1)[0] },
            );
        }

        const invalid: OpcodeHandler = switch (builtin.mode) {
            .Debug, .ReleaseSafe => panicInvalidInstruction,
            .ReleaseFast, .ReleaseSmall => undefined,
        };

        const entries = dispatchTable(Opcode, invalid, null);

        pub fn handler(
            ip: Ip,
            sp: Sp,
            fuel: *Fuel,
            stp: Stp,
            locals: Locals,
            interp: *Interpreter,
            eip: Eip,
            state: *State,
            module: runtime.ModuleInst,
        ) StateTransition {
            var i = Instr.init(ip, eip);
            const n = i.readIdx(Opcode);
            const next = entries[@intFromEnum(n)];
            std.debug.assert(@intFromPtr(i.end) == @intFromPtr(eip));
            return @call(
                .always_tail,
                next,
                .{ i.next, sp, fuel, stp, locals, interp, eip, state, module },
            );
        }
    };
}

const fc_prefixed_dispatch = prefixDispatchTable(.@"0xFC", opcodes.FCPrefixOpcode);

const opcode_handlers = struct {
    fn panicInvalidInstruction(
        ip: Ip,
        sp: Sp,
        fuel: *Fuel,
        stp: Stp,
        locals: Locals,
        interp: *Interpreter,
        eip: Eip,
        state: *State,
        module: runtime.ModuleInst,
    ) StateTransition {
        _ = sp;
        _ = fuel;
        _ = stp;
        _ = locals;
        _ = interp;
        _ = eip;
        _ = state;
        _ = module;
        const bad_opcode: u8 = (ip - 1)[0];
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

    fn outOfFuelHandler(
        ip: Ip,
        sp: Sp,
        fuel: *Fuel,
        stp: Stp,
        locals: Locals,
        interp: *Interpreter,
        eip: Eip,
        state: *State,
        module: runtime.ModuleInst,
    ) StateTransition {
        std.debug.assert(fuel.remaining == 0);
        _ = locals;
        _ = module;
        return .interrupted(
            .init(ip, eip),
            .init(sp, interp),
            .init(stp),
            interp,
            state,
            .out_of_fuel,
        );
    }

    pub fn @"unreachable"(
        ip: Ip,
        sp: Sp,
        fuel: *Fuel,
        stp: Stp,
        locals: Locals,
        interp: *Interpreter,
        eip: Eip,
        state: *State,
        module: runtime.ModuleInst,
    ) StateTransition {
        _ = fuel;
        _ = locals;
        _ = module;

        const unreachable_ip = ip - 1;
        const is_validation_failure = @intFromPtr(unreachable_ip) ==
            @intFromPtr(Module.Code.validation_failed.instructions_start);
        const info: Trap = if (is_validation_failure) invalid: {
            @branchHint(.cold);

            const current_frame: *align(@sizeOf(Value)) const StackFrame = interp.currentFrame().?;
            const wasm_callee = current_frame.function.expanded().wasm;
            std.debug.assert(wasm_callee.code().isValidationFinished());

            break :invalid .init(.lazy_validation_failure, .{ .function = wasm_callee.idx });
        } else .init(.unreachable_code_reached, {});

        return .trap(.init(ip, eip), .init(sp, interp), .init(stp), interp, state, info);
    }

    pub fn nop(
        ip: Ip,
        sp: Sp,
        fuel: *Fuel,
        stp: Stp,
        locals: Locals,
        interp: *Interpreter,
        eip: Eip,
        state: *State,
        module: runtime.ModuleInst,
    ) StateTransition {
        return Instr.init(ip, eip).dispatchNextOpcode(
            .init(sp, interp),
            fuel,
            .init(stp),
            locals,
            interp,
            state,
            module,
        );
    }

    pub fn block(
        ip: Ip,
        sp: Sp,
        fuel: *Fuel,
        stp: Stp,
        locals: Locals,
        interp: *Interpreter,
        eip: Eip,
        state: *State,
        module: runtime.ModuleInst,
    ) StateTransition {
        var i = Instr.init(ip, eip);
        i.skipBlockType();
        return i.dispatchNextOpcode(
            .init(sp, interp),
            fuel,
            .init(stp),
            locals,
            interp,
            state,
            module,
        );
    }

    pub const loop = block;

    pub fn @"if"(
        ip: Ip,
        sp: Sp,
        fuel: *Fuel,
        stp: Stp,
        locals: Locals,
        interp: *Interpreter,
        eip: Eip,
        state: *State,
        module: runtime.ModuleInst,
    ) StateTransition {
        var i = Instr.init(ip, eip);
        var vals = ValStack.init(sp, interp);
        var side_table = SideTable.init(stp);

        const c = vals.popTyped(interp, &.{.i32}).@"0";

        // std.debug.print(" > (if) {}?\n", .{c != 0});

        if (c == 0) {
            // No need to read LEB128 block type.
            side_table.takeBranch(interp, ip - 1, &i, &vals, 0);
        } else {
            i.skipBlockType();
            side_table.increment(interp);
        }

        return i.dispatchNextOpcode(vals, fuel, side_table, locals, interp, state, module);
    }

    pub fn @"else"(
        ip: Ip,
        sp: Sp,
        fuel: *Fuel,
        stp: Stp,
        locals: Locals,
        interp: *Interpreter,
        eip: Eip,
        state: *State,
        module: runtime.ModuleInst,
    ) StateTransition {
        var i = Instr.init(ip, eip);
        var vals = ValStack.init(sp, interp);
        var side_table = SideTable.init(stp);

        side_table.takeBranch(interp, ip - 1, &i, &vals, 0);

        return i.dispatchNextOpcode(vals, fuel, side_table, locals, interp, state, module);
    }

    pub fn end(
        ip: Ip,
        sp: Sp,
        fuel: *Fuel,
        stp: Stp,
        locals: Locals,
        interp: *Interpreter,
        eip: Eip,
        state: *State,
        module: runtime.ModuleInst,
    ) StateTransition {
        const end_ptr: Eip = @ptrCast(ip - 1);
        _ = end_ptr.*;
        return if (@intFromPtr(end_ptr) == @intFromPtr(eip))
            @call(
                .always_tail,
                returnFromWasm,
                .{ ip, sp, fuel, stp, locals, interp, eip, state, module },
            )
        else
            Instr.init(ip, eip).dispatchNextOpcode(
                .init(sp, interp),
                fuel,
                .init(stp),
                locals,
                interp,
                state,
                module,
            );
    }

    pub fn br(
        ip: Ip,
        sp: Sp,
        fuel: *Fuel,
        stp: Stp,
        locals: Locals,
        interp: *Interpreter,
        eip: Eip,
        state: *State,
        module: runtime.ModuleInst,
    ) StateTransition {
        var i = Instr.init(ip, eip);
        var vals = ValStack.init(sp, interp);
        var side_table = SideTable.init(stp);

        // No need to read LEB128 branch target
        const br_ptr: Ip = ip - 1;
        std.debug.assert(br_ptr[0] == @intFromEnum(opcodes.ByteOpcode.br));
        side_table.takeBranch(interp, br_ptr, &i, &vals, 0);
        return i.dispatchNextOpcode(vals, fuel, side_table, locals, interp, state, module);
    }

    pub fn br_if(
        ip: Ip,
        sp: Sp,
        fuel: *Fuel,
        stp: Stp,
        locals: Locals,
        interp: *Interpreter,
        eip: Eip,
        state: *State,
        module: runtime.ModuleInst,
    ) StateTransition {
        var i = Instr.init(ip, eip);
        var vals = ValStack.init(sp, interp);
        var side_table = SideTable.init(stp);

        const br_if_ptr: Ip = ip - 1;
        std.debug.assert(br_if_ptr[0] == @intFromEnum(opcodes.ByteOpcode.br_if));

        const c = vals.popTyped(interp, &.{.i32}).@"0";
        // std.debug.print(" > (br_if) {}?\n", .{c != 0});
        if (c != 0) {
            // No need to read LEB128 branch target
            side_table.takeBranch(interp, br_if_ptr, &i, &vals, 0);
        } else {
            // branch target
            _ = i.readIdxRaw();
            side_table.increment(interp);
        }

        return i.dispatchNextOpcode(vals, fuel, side_table, locals, interp, state, module);
    }

    pub fn br_table(
        ip: Ip,
        sp: Sp,
        fuel: *Fuel,
        stp: Stp,
        locals: Locals,
        interp: *Interpreter,
        eip: Eip,
        state: *State,
        module: runtime.ModuleInst,
    ) StateTransition {
        const br_table_ptr: *const opcodes.ByteOpcode = @ptrCast(ip - 1);
        std.debug.assert(br_table_ptr.* == opcodes.ByteOpcode.br_table);

        var i = Instr.init(ip, eip);
        var vals = ValStack.init(sp, interp);
        var side_table = SideTable.init(stp);

        const label_count: u32 = i.readIdxRaw();

        // No need to read LEB128 labels

        const n: u32 = @bitCast(vals.popTyped(interp, &.{.i32}).@"0");

        // std.debug.print(" > br_table [{}]\n", .{n});

        side_table.takeBranch(interp, @ptrCast(br_table_ptr), &i, &vals, @min(n, label_count));

        return i.dispatchNextOpcode(vals, fuel, side_table, locals, interp, state, module);
    }

    pub const @"return" = returnFromWasm;

    pub fn call(
        ip: Ip,
        sp: Sp,
        fuel: *Fuel,
        stp: Stp,
        locals: Locals,
        interp: *Interpreter,
        eip: Eip,
        state: *State,
        module: runtime.ModuleInst,
    ) StateTransition {
        _ = locals;
        const call_ip = ip - 1;
        std.debug.assert(call_ip[0] == @intFromEnum(opcodes.ByteOpcode.call));

        var i = Instr.init(ip, eip);

        if (builtin.mode == .Debug) {
            const current_frame: *align(@sizeOf(Value)) const StackFrame = interp.currentFrame().?;
            std.debug.assert(
                @intFromPtr(current_frame.function.expanded().wasm.module.inner) ==
                    @intFromPtr(module.inner),
            );
        }

        const func_idx = i.readIdx(Module.FuncIdx);
        const callee = module.header().funcAddr(func_idx);
        return invokeWithinWasm(
            i,
            .init(sp, interp),
            fuel,
            .init(stp),
            interp,
            state,
            call_ip,
            callee,
        );
    }

    pub fn call_indirect(
        ip: Ip,
        sp: Sp,
        fuel: *Fuel,
        stp: Stp,
        locals: Locals,
        interp: *Interpreter,
        eip: Eip,
        state: *State,
        module: runtime.ModuleInst,
    ) StateTransition {
        _ = locals;
        const call_ip = ip - 1;
        std.debug.assert(call_ip[0] == @intFromEnum(opcodes.ByteOpcode.call_indirect));

        var i = Instr.init(ip, eip);
        var vals = ValStack.init(sp, interp);

        const current_module = module.header();
        const expected_signature = i.readIdx(Module.TypeIdx).funcType(current_module.module);
        const table_idx = i.readIdx(Module.TableIdx);

        const elem_index: u32 = @bitCast(vals.popTyped(interp, &.{.i32}).@"0");

        const table_addr = current_module.tableAddr(table_idx);
        std.debug.assert(table_addr.elem_type == .funcref);
        const table = table_addr.table;

        if (table.len <= elem_index) {
            @branchHint(.unlikely);
            return .trap(
                i,
                vals,
                .init(stp),
                interp,
                state,
                .init(.table_access_out_of_bounds, .init(table_idx, .@"call.indirect")),
            );
        }

        const callee = table.base.func_ref[0..table.len][elem_index].funcInst() orelse {
            @branchHint(.unlikely);
            return .trap(
                i,
                vals,
                .init(stp),
                interp,
                state,
                .init(.indirect_call_to_null, .{ .index = elem_index }),
            );
        };

        if (!expected_signature.matches(callee.signature())) {
            @branchHint(.unlikely);
            return .trap(
                i,
                vals,
                .init(stp),
                interp,
                state,
                .init(.indirect_call_signature_mismatch, {}),
            );
        }

        return invokeWithinWasm(i, vals, fuel, .init(stp), interp, state, call_ip, callee);
    }

    pub fn drop(
        ip: Ip,
        sp: Sp,
        fuel: *Fuel,
        stp: Stp,
        locals: Locals,
        interp: *Interpreter,
        eip: Eip,
        state: *State,
        module: runtime.ModuleInst,
    ) StateTransition {
        var i = Instr.init(ip, eip);
        var vals = ValStack.init(sp, interp);

        _ = vals.popArray(interp, 1);

        // std.debug.print(" height after drop: {}\n", .{vals.items.len});

        return i.dispatchNextOpcode(vals, fuel, .init(stp), locals, interp, state, module);
    }

    pub fn select(
        ip: Ip,
        sp: Sp,
        fuel: *Fuel,
        stp: Stp,
        locals: Locals,
        interp: *Interpreter,
        eip: Eip,
        state: *State,
        module: runtime.ModuleInst,
    ) StateTransition {
        var i = Instr.init(ip, eip);
        var vals = ValStack.init(sp, interp);

        const popped = vals.popArray(interp, 2);
        const c = popped[1].i32;
        if (c == 0) {
            vals.topArray(interp, 1)[0] = popped[0];
        }

        return i.dispatchNextOpcode(vals, fuel, .init(stp), locals, interp, state, module);
    }

    pub fn @"select t"(
        ip: Ip,
        sp: Sp,
        fuel: *Fuel,
        stp: Stp,
        locals: Locals,
        interp: *Interpreter,
        eip: Eip,
        state: *State,
        module: runtime.ModuleInst,
    ) StateTransition {
        var i = Instr.init(ip, eip);

        const type_count: u32 = i.readIdxRaw();
        std.debug.assert(type_count == 1);

        for (0..type_count) |_| {
            i.skipValType();
        }

        if (type_count == 1)
            return @call(
                switch (builtin.mode) {
                    .Debug, .ReleaseSmall => .always_tail,
                    .ReleaseSafe, .ReleaseFast => .always_inline,
                },
                select,
                .{ i.next, sp, fuel, stp, locals, interp, eip, state, module },
            )
        else
            unreachable;
    }

    pub fn @"local.get"(
        ip: Ip,
        sp: Sp,
        fuel: *Fuel,
        stp: Stp,
        locals: Locals,
        interp: *Interpreter,
        eip: Eip,
        state: *State,
        module: runtime.ModuleInst,
    ) StateTransition {
        var i = Instr.init(ip, eip);
        var vals = ValStack.init(sp, interp);

        const n: u16 = @intCast(i.readIdxRaw());
        const src: *align(@sizeOf(Value)) const Value = locals.get(interp, n);

        // std.debug.print(" > before local.get {}, sp = {*}\n", .{ n, sp.ptr });
        vals.pushArray(interp, 1)[0] = src.*;

        // std.debug.print(" > (local.get {}) (i32.const {})\n", .{ n, value.i32 });

        return i.dispatchNextOpcode(vals, fuel, .init(stp), locals, interp, state, module);
    }

    pub fn @"local.set"(
        ip: Ip,
        sp: Sp,
        fuel: *Fuel,
        stp: Stp,
        locals: Locals,
        interp: *Interpreter,
        eip: Eip,
        state: *State,
        module: runtime.ModuleInst,
    ) StateTransition {
        var i = Instr.init(ip, eip);
        var vals = ValStack.init(sp, interp);

        const n: u16 = @intCast(i.readIdxRaw());
        const dst: *align(@sizeOf(Value)) Value = locals.get(interp, n);
        dst.* = vals.popArray(interp, 1)[0];

        return i.dispatchNextOpcode(vals, fuel, .init(stp), locals, interp, state, module);
    }

    pub fn @"local.tee"(
        ip: Ip,
        sp: Sp,
        fuel: *Fuel,
        stp: Stp,
        locals: Locals,
        interp: *Interpreter,
        eip: Eip,
        state: *State,
        module: runtime.ModuleInst,
    ) StateTransition {
        var i = Instr.init(ip, eip);
        var vals = ValStack.init(sp, interp);

        const n: u16 = @intCast(i.readIdxRaw());
        locals.get(interp, n).* = vals.topArray(interp, 1)[0];

        return i.dispatchNextOpcode(vals, fuel, .init(stp), locals, interp, state, module);
    }

    pub fn @"global.get"(
        ip: Ip,
        sp: Sp,
        fuel: *Fuel,
        stp: Stp,
        locals: Locals,
        interp: *Interpreter,
        eip: Eip,
        state: *State,
        module: runtime.ModuleInst,
    ) StateTransition {
        var i = Instr.init(ip, eip);
        var vals = ValStack.init(sp, interp);

        const global_idx = i.readIdx(Module.GlobalIdx);
        const global_addr = module.header().globalAddr(global_idx);

        vals.pushArray(interp, 1).* = .{switch (global_addr.global_type.val_type) {
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
        }};

        return i.dispatchNextOpcode(vals, fuel, .init(stp), locals, interp, state, module);
    }

    pub fn @"global.set"(
        ip: Ip,
        sp: Sp,
        fuel: *Fuel,
        stp: Stp,
        locals: Locals,
        interp: *Interpreter,
        eip: Eip,
        state: *State,
        module: runtime.ModuleInst,
    ) StateTransition {
        var i = Instr.init(ip, eip);
        var vals = ValStack.init(sp, interp);

        const global_idx = i.readIdx(Module.GlobalIdx);
        const global_addr = module.header().globalAddr(global_idx);

        const popped: *align(@sizeOf(Value)) const Value = &vals.popArray(interp, 1)[0];
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

        return i.dispatchNextOpcode(vals, fuel, .init(stp), locals, interp, state, module);
    }

    /// https://webassembly.github.io/spec/core/exec/instructions.html#exec-table-get
    pub fn @"table.get"(
        ip: Ip,
        sp: Sp,
        fuel: *Fuel,
        stp: Stp,
        locals: Locals,
        interp: *Interpreter,
        eip: Eip,
        state: *State,
        module: runtime.ModuleInst,
    ) StateTransition {
        var i = Instr.init(ip, eip);
        var vals = ValStack.init(sp, interp);

        const table_idx = i.readIdx(Module.TableIdx);
        const table = module.header().tableAddr(table_idx).table;

        const operand = &vals.topArray(interp, 1)[0];
        const idx: u32 = @bitCast(operand.i32);
        const dst = std.mem.asBytes(operand);

        @memcpy(
            dst[0..table.stride.toBytes()],
            table.elementSlice(idx) catch return .trap(
                i,
                vals,
                .init(stp),
                interp,
                state,
                .init(
                    .table_access_out_of_bounds,
                    .init(table_idx, .{ .access = .{ .index = idx } }),
                ),
            ),
        );

        // Fill ExternRef padding
        @memset(dst[table.stride.toBytes()..], 0);

        return i.dispatchNextOpcode(vals, fuel, .init(stp), locals, interp, state, module);
    }

    /// https://webassembly.github.io/spec/core/exec/instructions.html#exec-table-set
    pub fn @"table.set"(
        ip: Ip,
        sp: Sp,
        fuel: *Fuel,
        stp: Stp,
        locals: Locals,
        interp: *Interpreter,
        eip: Eip,
        state: *State,
        module: runtime.ModuleInst,
    ) StateTransition {
        var i = Instr.init(ip, eip);
        var vals = ValStack.init(sp, interp);

        const table_idx = i.readIdx(Module.TableIdx);
        const table = module.header().tableAddr(table_idx).table;

        const operands = vals.popArray(interp, 2);
        const ref: *align(@sizeOf(Value)) const Value = &operands[1];
        const idx: u32 = @bitCast(operands[0].i32);

        @memcpy(
            table.elementSlice(idx) catch return .trap(
                i,
                vals,
                .init(stp),
                interp,
                state,
                .init(
                    .table_access_out_of_bounds,
                    .init(table_idx, .{ .access = .{ .index = idx } }),
                ),
            ),
            std.mem.asBytes(ref)[0..table.stride.toBytes()],
        );

        return i.dispatchNextOpcode(vals, fuel, .init(stp), locals, interp, state, module);
    }

    pub const @"i32.load" = linearMemoryHandlers(.i32).load;
    pub const @"i64.load" = linearMemoryHandlers(.i64).load;
    pub const @"f32.load" = linearMemoryHandlers(.f32).load;
    pub const @"f64.load" = linearMemoryHandlers(.f64).load;
    pub const @"i32.load8_s" = extendingLinearMemoryLoad(.i32, i8);
    pub const @"i32.load8_u" = extendingLinearMemoryLoad(.i32, u8);
    pub const @"i32.load16_s" = extendingLinearMemoryLoad(.i32, i16);
    pub const @"i32.load16_u" = extendingLinearMemoryLoad(.i32, u16);
    pub const @"i64.load8_s" = extendingLinearMemoryLoad(.i64, i8);
    pub const @"i64.load8_u" = extendingLinearMemoryLoad(.i64, u8);
    pub const @"i64.load16_s" = extendingLinearMemoryLoad(.i64, i16);
    pub const @"i64.load16_u" = extendingLinearMemoryLoad(.i64, u16);
    pub const @"i64.load32_s" = extendingLinearMemoryLoad(.i64, i32);
    pub const @"i64.load32_u" = extendingLinearMemoryLoad(.i64, u32);
    pub const @"i32.store" = linearMemoryHandlers(.i32).store;
    pub const @"i64.store" = linearMemoryHandlers(.i64).store;
    pub const @"f32.store" = linearMemoryHandlers(.f32).store;
    pub const @"f64.store" = linearMemoryHandlers(.f64).store;
    pub const @"i32.store8" = narrowingLinearMemoryStore(.i32, .@"1");
    pub const @"i32.store16" = narrowingLinearMemoryStore(.i32, .@"2");
    pub const @"i64.store8" = narrowingLinearMemoryStore(.i64, .@"1");
    pub const @"i64.store16" = narrowingLinearMemoryStore(.i64, .@"2");
    pub const @"i64.store32" = narrowingLinearMemoryStore(.i64, .@"4");

    pub fn @"memory.size"(
        ip: Ip,
        sp: Sp,
        fuel: *Fuel,
        stp: Stp,
        locals: Locals,
        interp: *Interpreter,
        eip: Eip,
        state: *State,
        module: runtime.ModuleInst,
    ) StateTransition {
        var i = Instr.init(ip, eip);
        var vals = ValStack.init(sp, interp);

        const mem_idx = i.readIdx(Module.MemIdx);

        const size = module.header().memAddr(mem_idx).size / runtime.MemInst.page_size;
        vals.pushTyped(interp, &.{.i32}, .{@bitCast(@as(u32, @intCast(size)))});

        return i.dispatchNextOpcode(vals, fuel, .init(stp), locals, interp, state, module);
    }

    pub fn @"memory.grow"(
        ip: Ip,
        sp: Sp,
        fuel: *Fuel,
        stp: Stp,
        locals: Locals,
        interp: *Interpreter,
        eip: Eip,
        state: *State,
        module: runtime.ModuleInst,
    ) StateTransition {
        var i = Instr.init(ip, eip);
        var vals = ValStack.init(sp, interp);

        const mem_idx = i.readIdx(Module.MemIdx);
        const mem = module.header().memAddr(mem_idx);

        const operand: *align(@sizeOf(Value)) Value = &vals.top(interp, 1)[0];
        const delta: u32 = @bitCast(operand.i32);
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
                return .interrupted(i, vals, .init(stp), interp, state, .{
                    .memory_grow = .{
                        .old_size = @intCast(mem.size),
                        .new_size = @as(u32, @intCast(mem.size)) + delta_bytes,
                        .memory = mem,
                        .result = operand,
                    },
                });
            }
        };

        operand.* = .{ .i32 = result };

        return i.dispatchNextOpcode(vals, fuel, .init(stp), locals, interp, state, module);
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

    fn reinterpretOp(comptime Src: type, comptime Dst: type) (fn (Src) error{}!Dst) {
        return struct {
            fn op(src: Src) error{}!Dst {
                return @bitCast(src);
            }
        }.op;
    }

    pub const @"i32.wrap_i64" = defineConvOp(.i64, .i32, conv_ops.@"i32.wrap_i64", undefined);
    pub const @"i32.trunc_f32_s" = i32_opcode_handlers.trunc_f32_s;
    pub const @"i32.trunc_f32_u" = i32_opcode_handlers.trunc_f32_u;
    pub const @"i32.trunc_f64_s" = i32_opcode_handlers.trunc_f64_s;
    pub const @"i32.trunc_f64_u" = i32_opcode_handlers.trunc_f64_u;
    pub const @"i64.extend_i32_s" = defineConvOp(.i32, .i64, conv_ops.@"i64.extend_i32_s", undefined);
    pub const @"i64.extend_i32_u" = defineConvOp(.i32, .i64, conv_ops.@"i64.extend_i32_u", undefined);
    pub const @"i64.trunc_f32_s" = i64_opcode_handlers.trunc_f32_s;
    pub const @"i64.trunc_f32_u" = i64_opcode_handlers.trunc_f32_u;
    pub const @"i64.trunc_f64_s" = i64_opcode_handlers.trunc_f64_s;
    pub const @"i64.trunc_f64_u" = i64_opcode_handlers.trunc_f64_u;
    pub const @"f32.convert_i32_s" = f32_opcode_handlers.convert_i32_s;
    pub const @"f32.convert_i32_u" = f32_opcode_handlers.convert_i32_u;
    pub const @"f32.convert_i64_s" = f32_opcode_handlers.convert_i64_s;
    pub const @"f32.convert_i64_u" = f32_opcode_handlers.convert_i64_u;
    pub const @"f32.demote_f64" = defineConvOp(.f64, .f32, conv_ops.@"f32.demote_f64", undefined);
    pub const @"f64.convert_i32_s" = f64_opcode_handlers.convert_i32_s;
    pub const @"f64.convert_i32_u" = f64_opcode_handlers.convert_i32_u;
    pub const @"f64.convert_i64_s" = f64_opcode_handlers.convert_i64_s;
    pub const @"f64.convert_i64_u" = f64_opcode_handlers.convert_i64_u;
    pub const @"f64.promote_f32" = defineConvOp(.f32, .f64, conv_ops.@"f64.promote_f32", undefined);
    pub const @"i32.reinterpret_f32" = defineConvOp(.f32, .i32, reinterpretOp(f32, i32), undefined);
    pub const @"i64.reinterpret_f64" = defineConvOp(.f64, .i64, reinterpretOp(f64, i64), undefined);
    pub const @"f32.reinterpret_i32" = defineConvOp(.i32, .f32, reinterpretOp(i32, f32), undefined);
    pub const @"f64.reinterpret_i64" = defineConvOp(.i64, .f64, reinterpretOp(i64, f64), undefined);

    fn intSignExtend(comptime I: type, comptime M: type) (fn (I) I) {
        std.debug.assert(@bitSizeOf(M) < @bitSizeOf(I));
        return struct {
            fn op(i: I) I {
                const j: I = @mod(i, @as(I, 1 << @bitSizeOf(M)));
                return @as(M, @truncate(j));
            }
        }.op;
    }

    pub const @"i32.extend8_s" = defineUnOp(.i32, intSignExtend(i32, i8));
    pub const @"i32.extend16_s" = defineUnOp(.i32, intSignExtend(i32, i16));
    pub const @"i64.extend8_s" = defineUnOp(.i64, intSignExtend(i64, i8));
    pub const @"i64.extend16_s" = defineUnOp(.i64, intSignExtend(i64, i16));
    pub const @"i64.extend32_s" = defineUnOp(.i64, intSignExtend(i64, i32));

    pub fn @"ref.null"(
        ip: Ip,
        sp: Sp,
        fuel: *Fuel,
        stp: Stp,
        locals: Locals,
        interp: *Interpreter,
        eip: Eip,
        state: *State,
        module: runtime.ModuleInst,
    ) StateTransition {
        var i = Instr.init(ip, eip);
        var vals = ValStack.init(sp, interp);

        _ = i.readByte();
        vals.pushArray(interp, 1)[0] = std.mem.zeroes(Value);

        return i.dispatchNextOpcode(vals, fuel, .init(stp), locals, interp, state, module);
    }

    pub fn @"ref.is_null"(
        ip: Ip,
        sp: Sp,
        fuel: *Fuel,
        stp: Stp,
        locals: Locals,
        interp: *Interpreter,
        eip: Eip,
        state: *State,
        module: runtime.ModuleInst,
    ) StateTransition {
        var i = Instr.init(ip, eip);
        var vals = ValStack.init(sp, interp);

        const top: *align(@sizeOf(Value)) Value = &vals.topArray(interp, 1)[0];
        const is_null = std.mem.allEqual(u8, std.mem.asBytes(top), 0);
        // std.debug.dumpHex(std.mem.asBytes(top));
        // std.debug.print(
        //     "> ref.is_null (ref.extern {?}) -> {}\n",
        //     .{ top.externref.addr.nat.toInt(), is_null },
        // );

        top.* = .{ .i32 = @intFromBool(is_null) };

        return i.dispatchNextOpcode(vals, fuel, .init(stp), locals, interp, state, module);
    }

    pub fn @"ref.func"(
        ip: Ip,
        sp: Sp,
        fuel: *Fuel,
        stp: Stp,
        locals: Locals,
        interp: *Interpreter,
        eip: Eip,
        state: *State,
        module: runtime.ModuleInst,
    ) StateTransition {
        var i = Instr.init(ip, eip);
        var vals = ValStack.init(sp, interp);

        const func_idx = i.readIdx(Module.FuncIdx);
        vals.pushTyped(interp, &.{.funcref}, .{@bitCast(module.header().funcAddr(func_idx))});

        return i.dispatchNextOpcode(vals, fuel, .init(stp), locals, interp, state, module);
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
    pub fn @"memory.init"(
        ip: Ip,
        sp: Sp,
        fuel: *Fuel,
        stp: Stp,
        locals: Locals,
        interp: *Interpreter,
        eip: Eip,
        state: *State,
        module: runtime.ModuleInst,
    ) StateTransition {
        var i = Instr.init(ip, eip);
        var vals = ValStack.init(sp, interp);

        const data_idx = i.readIdx(Module.DataIdx);
        const mem_idx = i.readIdx(Module.MemIdx);
        const module_inst = module.header();
        const mem = module_inst.memAddr(mem_idx);

        const operands = vals.popTyped(interp, &(.{.i32} ** 3));
        const n: u32 = @bitCast(operands[2]);
        const src_addr: u32 = @bitCast(operands[1]);
        const d: u32 = @bitCast(operands[0]);

        mem.init(module_inst.dataSegment(data_idx), n, src_addr, d) catch return .trap(
            i,
            vals,
            .init(stp),
            interp,
            state,
            .init(.memory_access_out_of_bounds, .init(mem_idx, .@"memory.init", {})),
        );

        return i.dispatchNextOpcode(vals, fuel, .init(stp), locals, interp, state, module);
    }

    pub fn @"data.drop"(
        ip: Ip,
        sp: Sp,
        fuel: *Fuel,
        stp: Stp,
        locals: Locals,
        interp: *Interpreter,
        eip: Eip,
        state: *State,
        module: runtime.ModuleInst,
    ) StateTransition {
        var i = Instr.init(ip, eip);

        const data_idx = i.readIdx(Module.DataIdx);

        module.header().dataSegmentDropFlag(data_idx).drop();

        return i.dispatchNextOpcode(
            .init(sp, interp),
            fuel,
            .init(stp),
            locals,
            interp,
            state,
            module,
        );
    }

    /// https://webassembly.github.io/spec/core/exec/instructions.html#exec-memory-copy
    pub fn @"memory.copy"(
        ip: Ip,
        sp: Sp,
        fuel: *Fuel,
        stp: Stp,
        locals: Locals,
        interp: *Interpreter,
        eip: Eip,
        state: *State,
        module: runtime.ModuleInst,
    ) StateTransition {
        var i = Instr.init(ip, eip);
        var vals = ValStack.init(sp, interp);

        const dst_idx = i.readIdx(Module.MemIdx);
        const src_idx = i.readIdx(Module.MemIdx);
        const module_inst = module.header();
        const dst_mem = module_inst.memAddr(dst_idx);
        const src_mem = module_inst.memAddr(src_idx);

        const operands = vals.popArray(interp, 3);
        const n: u32 = @bitCast(operands[2].i32);
        const src_addr: u32 = @bitCast(operands[1].i32);
        const d: u32 = @bitCast(operands[0].i32);

        dst_mem.copy(src_mem, n, src_addr, d) catch return .trap(
            i,
            vals,
            .init(stp),
            interp,
            state,
            .init(
                .memory_access_out_of_bounds,
                .init(if (dst_mem.size < src_mem.size) dst_idx else src_idx, .@"memory.copy", {}),
            ),
        );

        return i.dispatchNextOpcode(vals, fuel, .init(stp), locals, interp, state, module);
    }

    /// https://webassembly.github.io/spec/core/exec/instructions.html#exec-memory-fill
    pub fn @"memory.fill"(
        ip: Ip,
        sp: Sp,
        fuel: *Fuel,
        stp: Stp,
        locals: Locals,
        interp: *Interpreter,
        eip: Eip,
        state: *State,
        module: runtime.ModuleInst,
    ) StateTransition {
        var i = Instr.init(ip, eip);
        var vals = ValStack.init(sp, interp);

        const mem_idx = i.readIdx(Module.MemIdx);
        const mem = module.header().memAddr(mem_idx);

        const operands = vals.popArray(interp, 3);
        const n: u32 = @bitCast(operands[2].i32);
        const dupe: u8 = @truncate(@as(u32, @bitCast(operands[1].i32)));
        const d: u32 = @bitCast(operands[0].i32);

        mem.fill(n, dupe, d) catch return .trap(
            i,
            vals,
            .init(stp),
            interp,
            state,
            .init(.memory_access_out_of_bounds, .init(mem_idx, .@"memory.fill", {})),
        );

        return i.dispatchNextOpcode(vals, fuel, .init(stp), locals, interp, state, module);
    }

    /// https://webassembly.github.io/spec/core/exec/instructions.html#exec-table-init
    pub fn @"table.init"(
        ip: Ip,
        sp: Sp,
        fuel: *Fuel,
        stp: Stp,
        locals: Locals,
        interp: *Interpreter,
        eip: Eip,
        state: *State,
        module: runtime.ModuleInst,
    ) StateTransition {
        var i = Instr.init(ip, eip);
        var vals = ValStack.init(sp, interp);

        const elem_idx = i.readIdx(Module.ElemIdx);
        const table_idx = i.readIdx(Module.TableIdx);

        const operands = vals.popArray(interp, 3);
        const n: u32 = @bitCast(operands[2].i32);
        const src_idx: u32 = @bitCast(operands[1].i32);
        const d: u32 = @bitCast(operands[1].i32);

        runtime.TableInst.init(
            table_idx,
            module,
            elem_idx,
            n,
            src_idx,
            d,
        ) catch return .trap(
            i,
            vals,
            .init(stp),
            interp,
            state,
            .init(.table_access_out_of_bounds, .init(table_idx, .@"table.init")),
        );

        return i.dispatchNextOpcode(vals, fuel, .init(stp), locals, interp, state, module);
    }

    pub fn @"elem.drop"(
        ip: Ip,
        sp: Sp,
        fuel: *Fuel,
        stp: Stp,
        locals: Locals,
        interp: *Interpreter,
        eip: Eip,
        state: *State,
        module: runtime.ModuleInst,
    ) StateTransition {
        var i = Instr.init(ip, eip);

        const elem_idx = i.readIdx(Module.ElemIdx);

        module.header().elemSegmentDropFlag(elem_idx).drop();

        return i.dispatchNextOpcode(
            .init(sp, interp),
            fuel,
            .init(stp),
            locals,
            interp,
            state,
            module,
        );
    }

    /// https://webassembly.github.io/spec/core/exec/instructions.html#exec-table-copy
    pub fn @"table.copy"(
        ip: Ip,
        sp: Sp,
        fuel: *Fuel,
        stp: Stp,
        locals: Locals,
        interp: *Interpreter,
        eip: Eip,
        state: *State,
        module: runtime.ModuleInst,
    ) StateTransition {
        var i = Instr.init(ip, eip);
        var vals = ValStack.init(sp, interp);

        const dst_idx = i.readIdx(Module.TableIdx);
        const src_idx = i.readIdx(Module.TableIdx);
        const module_inst = module.header();
        const dst_table = module_inst.tableAddr(dst_idx);
        const src_table = module_inst.tableAddr(src_idx);

        const operands = vals.popArray(interp, 3);
        const n: u32 = @bitCast(operands[2].i32);
        const src_addr: u32 = @bitCast(operands[1].i32);
        const d: u32 = @bitCast(operands[1].i32);

        dst_table.table.copy(
            src_table.table,
            n,
            src_addr,
            d,
        ) catch return .trap(
            i,
            vals,
            .init(stp),
            interp,
            state,
            .init(
                .table_access_out_of_bounds,
                .init(
                    if (dst_table.table.len < src_table.table.len) dst_idx else src_idx,
                    .@"table.copy",
                ),
            ),
        );

        return i.dispatchNextOpcode(vals, fuel, .init(stp), locals, interp, state, module);
    }

    /// https://webassembly.github.io/spec/core/exec/instructions.html#exec-table-grow
    pub fn @"table.grow"(
        ip: Ip,
        sp: Sp,
        fuel: *Fuel,
        stp: Stp,
        locals: Locals,
        interp: *Interpreter,
        eip: Eip,
        state: *State,
        module: runtime.ModuleInst,
    ) StateTransition {
        var i = Instr.init(ip, eip);
        var vals = ValStack.init(sp, interp);

        const table_idx = i.readIdx(Module.TableIdx);
        const table_addr = module.header().tableAddr(table_idx);
        const table = table_addr.table;

        const delta: u32 = @bitCast(vals.popTyped(interp, &.{.i32})[0]);
        const result_or_elem: *align(@sizeOf(Value)) Value = &vals.topArray(interp, 1)[0];

        const grow_failed: i32 = -1;

        const result: i32 = if (table.limit - table.len < delta)
            grow_failed
        else if (table.capacity - table.len >= delta) result: {
            const new_size: u32 = table.len + delta;
            const old_size: u32 = table.len;
            table.len = new_size;

            table.fillWithinCapacity(
                std.mem.asBytes(result_or_elem)[0..table.stride.toBytes()],
                old_size,
                new_size,
            );

            break :result @bitCast(old_size);
        } else return .interrupted(
            i,
            vals,
            .init(stp),
            interp,
            state,
            .{
                .table_grow = .{
                    .table = table_addr,
                    .elem = result_or_elem,
                    .old_len = table.len,
                    .new_len = table.len + delta,
                },
            },
        );

        result_or_elem.* = .{ .i32 = result };

        return i.dispatchNextOpcode(vals, fuel, .init(stp), locals, interp, state, module);
    }

    /// https://webassembly.github.io/spec/core/exec/instructions.html#exec-table-size
    pub fn @"table.size"(
        ip: Ip,
        sp: Sp,
        fuel: *Fuel,
        stp: Stp,
        locals: Locals,
        interp: *Interpreter,
        eip: Eip,
        state: *State,
        module: runtime.ModuleInst,
    ) StateTransition {
        var i = Instr.init(ip, eip);
        var vals = ValStack.init(sp, interp);

        const table_idx = i.readIdx(Module.TableIdx);

        vals.pushTyped(
            interp,
            &.{.i32},
            .{@bitCast(module.header().tableAddr(table_idx).table.len)},
        );

        return i.dispatchNextOpcode(vals, fuel, .init(stp), locals, interp, state, module);
    }

    /// https://webassembly.github.io/spec/core/exec/instructions.html#exec-table-fill
    pub fn @"table.fill"(
        ip: Ip,
        sp: Sp,
        fuel: *Fuel,
        stp: Stp,
        locals: Locals,
        interp: *Interpreter,
        eip: Eip,
        state: *State,
        module: runtime.ModuleInst,
    ) StateTransition {
        var i = Instr.init(ip, eip);
        var vals = ValStack.init(sp, interp);

        const table_idx = i.readIdx(Module.TableIdx);
        const table = module.header().tableAddr(table_idx).table;

        const operands = vals.popArray(interp, 3);
        const n: u32 = @bitCast(operands[2].i32);
        const dupe: *align(@sizeOf(Value)) const Value = &operands[1];
        const d: u32 = @bitCast(operands[0].i32);

        table.fill(n, std.mem.asBytes(dupe)[0..table.stride.toBytes()], d) catch return .trap(
            i,
            vals,
            .init(stp),
            interp,
            state,
            .init(.table_access_out_of_bounds, .init(table_idx, .@"table.fill")),
        );

        return i.dispatchNextOpcode(vals, fuel, .init(stp), locals, interp, state, module);
    }
};

/// If the handler is not appearing in this table, make sure it is public first.
const byte_dispatch_table = dispatchTable(
    opcodes.ByteOpcode,
    opcode_handlers.invalid,
    256,
);

/// Given a WASM function at the top of the call stack, resumes execution.
///
/// Asserts that the top of the stack frame corresponds to a WASM function.
fn enterMainLoop(interp: *Interpreter, fuel: *Fuel) State {
    const old_version = interp.version;
    defer if (Version.enabled) std.debug.assert(old_version.number != interp.version.number);

    const starting_frame: *align(@sizeOf(Value)) StackFrame = interp.currentFrame().?;
    const wasm_frame: *align(@sizeOf(Value)) const StackFrame.Wasm = starting_frame.wasmFrame();
    std.debug.assert(@intFromPtr(wasm_frame.ip) <= @intFromPtr(wasm_frame.eip));

    const wasm_callee = starting_frame.function.expanded().wasm;
    const code = wasm_callee.code();
    std.debug.assert(code.isValidationFinished());

    {
        std.debug.assert(@intFromPtr(code.inner.instructions_start) <= @intFromPtr(wasm_frame.ip));
        std.debug.assert(@intFromPtr(code.inner.instructions_end) == @intFromPtr(wasm_frame.eip));

        std.debug.assert(@intFromPtr(wasm_frame.stp.ptr) <= @intFromPtr(code.inner.side_table_ptr));
        std.debug.assert( // side table OOB
            @intFromPtr(code.inner.side_table_ptr) <=
                @intFromPtr(&wasm_frame.stp.ptr[code.inner.side_table_len]),
        );
    }

    var state: State = undefined;
    var i = Instr.init(wasm_frame.ip, wasm_frame.eip);
    const locals = Locals{ .ptr = starting_frame.localValues(interp.stack.slice()).ptr };
    const handler: *const OpcodeHandler = i.readNextOpcodeHandler(
        fuel,
        locals,
        interp,
        wasm_callee.module,
    );

    const sp = Sp.init(&interp.stack);
    std.debug.assert(@intFromPtr(sp.ptr) == @intFromPtr(starting_frame.valueStackBase()));
    const transition: StateTransition = handler(
        i.next,
        sp,
        fuel,
        wasm_frame.stp,
        locals,
        interp,
        i.end,
        &state,
        wasm_callee.module,
    );

    transition.version.check(interp.version);
    return state;
}

pub fn deinit(interp: *Interpreter, alloca: Allocator) void {
    interp.stack.deinit(alloca);
    interp.* = undefined;
}

const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const Module = @import("Module.zig");
const runtime = @import("runtime.zig");
const opcodes = @import("opcodes.zig");
