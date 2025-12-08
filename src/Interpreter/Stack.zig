//! The `Interpreter` value and call stack. Contains the WebAssembly operand stack, stack frames,
//! and local variables.
//!
//! See `Frame` for more information on the structure.
//!
//! The `Stack` uses a simple contiguous stack design, a segmented stack would have to deal with the
//! "hot splitting" problem (which is why Rust and Go rejected it).

const Stack = @This();

/// Pushing values starts at lower addresses (smaller indices into the slice).
///
/// Invariant that the length fits in an `u32`.
allocated: []align(@sizeOf(Value)) Value,
call_depth: u32,
current_frame: Stack.Frame.Offset,

pub fn init(
    allocator: Allocator,
    /// Specified as a the number of `Value`s.
    capacity: u32,
) Allocator.Error!Stack {
    return Stack{
        .allocated = try allocator.alignedAlloc(Value, .fromByteUnits(@sizeOf(Value)), capacity),
        .call_depth = 0,
        .current_frame = .none,
    };
}

fn assertPtrInBounds(stack: Stack, ptr: [*]align(@sizeOf(Value)) const Value) void {
    std.debug.assert(@intFromPtr(stack.allocated.ptr) <= @intFromPtr(ptr));
    std.debug.assert(@intFromPtr(ptr) <= @intFromPtr(stack.allocated.ptr + stack.allocated.len));
}

fn assertSliceInBounds(stack: Stack, slice: []align(@sizeOf(Value)) const Value) void {
    std.debug.assert(@intFromPtr(stack.allocated.ptr) <= @intFromPtr(slice.ptr));
    std.debug.assert(
        @intFromPtr(slice.ptr + slice.len) <=
            @intFromPtr(stack.allocated.ptr + stack.allocated.len),
    );
}

fn ChangePointee(
    comptime Self: type,
    comptime size: std.builtin.Type.Pointer.Size,
    comptime alignment: u16,
    comptime Pointee: type,
) type {
    std.debug.assert(@typeInfo(Self).pointer.size == .one);
    std.debug.assert(@typeInfo(Self).pointer.alignment >= alignment);
    return @Type(.{
        .pointer = std.builtin.Type.Pointer{
            .size = size,
            .is_const = @typeInfo(Self).pointer.is_const,
            .is_volatile = false,
            .address_space = .generic,
            .alignment = alignment,
            .child = Pointee,
            .is_allowzero = false,
            .sentinel_ptr = null,
        },
    });
}

pub fn currentFrame(stack: *const Stack) ?*const Frame {
    return stack.frameAt(stack.current_frame);
}

/// This is a `packed struct` to allow passing in a single register to opcode handlers, even when
/// using the C calling convention.
pub const Top = packed struct(usize) {
    /// Points to the "top" of the value stack, which is just past the last valid value.
    ptr: [*]align(@sizeOf(Value)) Value,
};

/// The operand stack that WebAssembly instructions operate on.
pub const Values = struct {
    const bounds_checking = switch (builtin.mode) {
        .Debug, .ReleaseSafe => true,
        .ReleaseFast, .ReleaseSmall => false,
    };

    top: Top,
    /// How many values can be popped.
    remaining: if (bounds_checking) u16 else void,
    /// Limits how large `remaining` can be.
    max_height: if (bounds_checking) u16 else void,

    /// Performs bounds checking upfront, to allow for better optimized code.
    pub inline fn init(top: Top, stack: *const Stack, remaining: u16, max_height: u16) Values {
        if (bounds_checking) {
            std.debug.assert(remaining <= max_height);
        }

        if (stack.currentFrame()) |frame| {
            const base = frame.valueStackBase();
            std.debug.assert(@intFromPtr(base) <= @intFromPtr(top.ptr - remaining));
            switch (frame.function.expanded()) {
                .wasm => |wasm| {
                    const code = wasm.code();
                    std.debug.assert(code.isValidationFinished());
                    std.debug.assert( // OOB max height
                        @intFromPtr(top.ptr + max_height - remaining) <=
                            @intFromPtr(base + code.inner.max_values),
                    );
                },
                .host => {},
            }
        } else {
            stack.assertPtrInBounds(top.ptr);
        }

        return Values{
            .top = top,
            .remaining = if (bounds_checking) remaining,
            .max_height = if (bounds_checking) max_height,
        };
    }

    pub fn assertRemainingCountIs(stack: Values, expected: u16) void {
        if (bounds_checking) {
            std.debug.assert(stack.remaining == expected);
        }
    }

    /// Gets a slice of the top `count` values on the `stack`. The `Value` at index `0` is the
    /// bottom-most of the retrieved values.
    pub inline fn topSlice(
        stack: Values,
        /// The number of values to retrieve.
        count: u16,
    ) []align(@sizeOf(Value)) Value {
        const values = @as(
            [*]align(@sizeOf(Value)) Value,
            stack.top.ptr - count,
        )[0..count];

        std.debug.assert(count <= stack.remaining);

        return values;
    }

    /// See `topSlice`.
    pub fn topArray(stack: Values, comptime count: u16) *align(@sizeOf(Value)) [count]Value {
        return stack.topSlice(count)[0..count];
    }

    /// Pushing values will invalidate the slice of popped values, so the popped values should
    /// be copied or used as soon as possible.
    ///
    /// Asserts that the stack does not overflow.
    pub inline fn popSlice(stack: *Values, count: u16) []align(@sizeOf(Value)) Value {
        const popped = stack.topSlice(count);
        stack.top.ptr = popped.ptr;
        if (bounds_checking) {
            stack.remaining -= count;
        }
        return popped;
    }

    /// See `popSlice`.
    pub inline fn popArray(
        stack: *Values,
        comptime count: u16,
    ) *align(@sizeOf(Value)) [count]Value {
        return stack.popSlice(count)[0..count];
    }

    /// The field at index `0` always refers to the value that was the lowest on the stack.
    fn TypedValues(comptime types: []const Value.Tag) type {
        var fields: [types.len]type = undefined;
        for (types, &fields) |ty, *dst| {
            dst.* = ty.Type();
        }

        return std.meta.Tuple(&fields);
    }

    /// Pops values using `popArray` and copies them to a tuple.
    ///
    /// Since values are copied, so pushing values won't invalidate the popped values.
    pub fn popTyped(values: *Values, comptime types: []const Value.Tag) TypedValues(types) {
        const popped = values.popArray(types.len);
        var typed: TypedValues(types) = undefined;
        inline for (types, popped, &typed) |ty, *src, *dst| {
            dst.* = @field(src, @tagName(ty));
        }
        return typed;
    }

    /// Returns a slice where pushed values can be written to. The `Value` at index `0` is the
    /// lowest on the stack.
    ///
    /// May invalidate slices referring to previously popped values.
    ///
    /// Asserts that pushing does not exceed the maximum allowed height.
    pub fn pushSlice(values: *Values, count: u16) []align(@sizeOf(Value)) Value {
        const pushed = values.top.ptr[0..count];
        @memset(pushed, undefined);
        values.top.ptr += count;
        if (bounds_checking) {
            values.remaining += count;
            std.debug.assert(values.remaining <= values.max_height);
        }
        return pushed;
    }

    /// See `pushSlice`.
    pub fn pushArray(values: *Values, comptime count: u32) *align(@sizeOf(Value)) [count]Value {
        return values.pushSlice(count)[0..count];
    }

    /// Writes the values in the given tuple to the stack, where the field at index `0` is the
    /// lowest on the stack.
    ///
    /// See `pushArray`.
    pub fn pushTyped(
        stack: *Values,
        /// The types of the values to push.
        comptime types: []const Value.Tag,
        values: TypedValues(types),
    ) void {
        const pushed = stack.pushArray(types.len);
        inline for (types, pushed, &values) |ty, *dst, src| {
            dst.* = @unionInit(Value, @tagName(ty), src);
        }
    }
};

pub fn walkCallStack(stack: *const Stack) Walker {
    _ = stack.frameAt(stack.current_frame);
    return Walker{ .stack = stack.* };
}

pub const PushedFrame = struct {
    offset: Frame.Offset,
    frame: *Frame,

    pub fn top(pushed: PushedFrame) Top {
        return Top{ .ptr = pushed.frame.valueStackBase() };
    }
};

pub const PushFrameError = error{ValidationNeeded} || Allocator.Error;

/// Pushes a new stack frame, assuming that there is enough space remaining in the stack.
pub fn pushFrameWithinCapacity(
    stack: *Stack,
    /// Refers to the top of the stack before the new frame is pushed.
    ///
    /// If `params == .preallocated`, then below `top` is are the arguments to pass.
    top: Top,
    instantiate_flag: *bool,
    comptime params: ParameterAllocation,
    callee: FuncAddr,
) PushFrameError!PushedFrame {
    stack.assertPtrInBounds(top.ptr);

    const new_call_depth = std.math.add(u32, stack.call_depth, 1) catch {
        return error.OutOfMemory; // call depth overflow
    };

    const prev_frame_ptr: ?*Frame = stack.frameAt(stack.current_frame);
    if (prev_frame_ptr) |prev_frame| {
        std.debug.assert(@intFromPtr(prev_frame.valueStackBase()) <= @intFromPtr(top.ptr));
    }

    const frame_info = try FrameSize.calculate(callee, params);
    std.debug.assert(frame_info.allocated_size > frame_info.allocated_local_count);
    if (frame_info.allocated_size > (stack.allocated.ptr + stack.allocated.len) - top.ptr) {
        return error.OutOfMemory; // no more room in interpreter stack
    }

    errdefer comptime unreachable;

    // std.debug.print(
    //     "PUSHING STACK FRAME FOR {f} (size = {})\n",
    //     .{ callee, frame_info.allocated_size },
    // );

    const signature = callee.signature();

    const prev_frame_top = Top{
        .ptr = top.ptr - switch (params) {
            .allocate => 0,
            .preallocated => signature.param_count,
        },
    };
    const prev_frame_checksum = if (builtin.mode != .Debug) {
        // no checksum
    } else if (prev_frame_ptr) |prev|
        prev.calculateChecksum(stack, prev_frame_top)
    else
        0;

    const new_frame_offset: Frame.Offset =
        @enumFromInt((top.ptr - stack.allocated.ptr) + frame_info.allocated_local_count);

    std.debug.assert(new_frame_offset != .none);

    const new_frame_slice: []align(@sizeOf(Value)) Value = top.ptr[0..frame_info.allocated_size];
    stack.assertSliceInBounds(new_frame_slice);

    @memset(new_frame_slice, undefined);

    const new_frame: *Frame = @ptrCast(
        new_frame_slice[frame_info.allocated_local_count..][0..Frame.size_in_values],
    );
    new_frame.* = Frame{
        .checksum = prev_frame_checksum,
        .function = callee,
        .signature = signature,
        .instantiate_flag = instantiate_flag,
        .local_count = .{ .total = frame_info.total_local_count },
        .prev_frame = stack.current_frame,
        .wasm = undefined,
    };

    std.debug.assert( // new frame offset mismatch
        @intFromPtr(new_frame) == @intFromPtr(&stack.allocated[@intFromEnum(new_frame_offset)]),
    );

    const new_values =
        new_frame_slice[(frame_info.allocated_local_count + Frame.size_in_values)..];
    stack.assertSliceInBounds(new_values);
    std.debug.assert(@intFromPtr(new_values.ptr) == @intFromPtr(new_frame.valueStackBase()));

    switch (callee.expanded()) {
        .host => {},
        .wasm => |wasm| {
            const code = wasm.code();
            if (builtin.mode == .Debug and !code.isValidationFinished()) {
                unreachable; // validation check occurred above
            }

            std.debug.assert(new_values.len == code.inner.max_values);
            @memset(new_values, undefined);

            new_frame.wasm = .{
                .ip = code.inner.instructions_start,
                .eip = code.inner.instructions_end,
                .stp = code.inner.side_table_ptr,
            };

            const new_locals: []align(@sizeOf(Value)) Value =
                new_frame.localValues(stack)[signature.param_count..];

            // Zero the local variables that aren't parameters
            @memset(new_locals, std.mem.zeroes(Value));
        },
    }

    stack.call_depth = new_call_depth;
    stack.current_frame = new_frame_offset;

    return PushedFrame{ .offset = new_frame_offset, .frame = new_frame };
}

/// Allocates space to ensure a future call to `CallStack.pushWithinCapacity` succeeds.
///
/// Returns a pointer to the new `Top` of the stack, which is different only if a reallocation
/// occurred.
///
/// Potentially invalidates pointers to the stack (when `Allocator.resize` is called).
///
/// Allocates space for a new stack frame.
pub fn reserveFrame(
    stack: *Stack,
    top: *Top,
    alloca: Allocator,
    comptime params: ParameterAllocation,
    callee: FuncAddr,
) Allocator.Error!void {
    defer coz.progressNamed("wasmstint.Interpreter.reserveFrame");

    const frame_size = (FrameSize.calculate(callee, params) catch unreachable).allocated_size;

    stack.assertPtrInBounds(top.ptr);
    const old_len: u32 = @intCast(top.ptr - stack.allocated.ptr);
    const new_len = std.math.add(u32, @intCast(old_len), frame_size) catch
        return error.OutOfMemory;

    const old_cap: u32 = @intCast(stack.allocated.len);
    const new_cap: u32 = @max(old_cap, new_len);
    const new_cap_exp: u32 = @max(new_cap, old_cap +| @max(1, old_cap / 2)); // 1.5x growth factor
    std.debug.assert(new_cap <= new_cap_exp);

    const old_allocation = stack.allocated;
    if (alloca.resize(old_allocation, new_cap_exp)) {
        stack.allocated = old_allocation.ptr[0..new_cap_exp];
    } else if (alloca.resize(old_allocation, new_cap)) {
        // Try to get as much memory as possible from the allocator
        stack.allocated = old_allocation.ptr[0..new_cap];
    } else {
        // This branch means the allocator might not support `resize`
        const alignment = comptime std.mem.Alignment.fromByteUnits(@sizeOf(Value));
        const new_allocation = alloca.alignedAlloc(Value, alignment, new_cap_exp) catch
            try alloca.alignedAlloc(Value, alignment, new_cap);

        errdefer comptime unreachable;

        @memcpy(new_allocation[0..old_len], old_allocation[0..old_len]);

        alloca.free(old_allocation);
        stack.allocated = new_allocation;

        // needs to point into new allocation
        top.ptr = new_allocation.ptr + old_len;
        stack.assertPtrInBounds(top.ptr);
    }
}

pub fn pushFrame(
    stack: *Stack,
    top: *Top,
    alloca: Allocator,
    instantiate_flag: *bool,
    comptime params: ParameterAllocation,
    callee: FuncAddr,
) PushFrameError!PushedFrame {
    alloc_needed: {
        return stack.pushFrameWithinCapacity(
            top.*,
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

    try stack.reserveFrame(top, alloca, params, callee);

    return stack.pushFrameWithinCapacity(
        top.*,
        instantiate_flag,
        params,
        callee,
    ) catch unreachable; // reserved space for frame
}

const PoppedFrame = struct {
    /// Slice where the return values are written using `@memmove`.
    results: []align(@sizeOf(Value)) Value,
    signature: *const Module.FuncType,
    top: Top,
    info: if (builtin.mode == .Debug) struct {
        callee: FuncAddr,
        wasm: struct {
            eip: *const Module.Code.End,
        },
    } else void,
};

const CopyResults = enum { from_stack_top, manually };

/// Clobbers the contents of the popped frame.
///
/// Asserts that there is a frame at the top of the call stack.
pub fn popFrame(
    stack: *Stack,
    top: Top,
    comptime copy_results: CopyResults,
) PoppedFrame {
    const popped = stack.frameAt(stack.current_frame).?;
    const prev_frame = popped.prev_frame;
    const expected_checksum = popped.checksum;
    const signature = popped.signature;
    const popped_wasm = popped.wasm;
    const popped_func = popped.function;

    popped.instantiate_flag.* = true;

    const results: []align(@sizeOf(Value)) Value = popped.localValues(stack)
        .ptr[0..signature.result_count];
    stack.assertSliceInBounds(results);
    std.debug.assert(
        copy_results == .manually or @intFromPtr(results.ptr + results.len) <= @intFromPtr(top.ptr),
    );

    std.debug.assert(@intFromPtr(popped.valueStackBase()) <= @intFromPtr(top.ptr));
    const values_height: u16 = @intCast(top.ptr - popped.valueStackBase());
    var value_stack = Values.init(top, stack, values_height, values_height).topSlice(values_height);

    switch (copy_results) {
        .from_stack_top => {
            // Overlap is possible if # of results > # locals + size of `Frame`
            const results_src = value_stack[value_stack.len - results.len ..];
            // std.log.debug("ret wrote to {*}", .{results.ptr});
            @memmove(results, results_src);
        },
        .manually => {
            @memset(popped.localValues(stack), undefined);
            popped.* = undefined;
            @memset(value_stack, undefined);
        },
    }

    stack.current_frame = prev_frame;
    stack.call_depth -= 1; // can't underflow, assumed call stack is not empty

    if (stack.currentFrame()) |current| {
        const current_func = current.function.expanded();
        switch (current_func) {
            .wasm => if (builtin.mode == .Debug) {
                const prev_top = Top{ .ptr = results.ptr };
                const actual_checksum = current.calculateChecksum(stack, prev_top);
                if (expected_checksum != actual_checksum) {
                    std.debug.panic(
                        "frame checksum mismatch for {f}:\nexpected: {X}\nactual: {X}",
                        .{ current_func, expected_checksum, actual_checksum },
                    );
                }
            },
            .host => {},
        }
    }

    return PoppedFrame{
        .results = results,
        .top = Top{ .ptr = results.ptr + results.len },
        .signature = signature,
        .info = if (builtin.mode == .Debug) .{
            .callee = popped_func,
            .wasm = .{ .eip = popped_wasm.eip },
        },
    };
}

pub const ParameterAllocation = enum {
    allocate,
    /// Arguments to the function are already on the top of the stack.
    preallocated,
};

pub const FrameSize = packed struct(u64) {
    /// In units of `Value`s.
    allocated_size: u32,
    /// Number of local variables to allocate space for.
    allocated_local_count: u16,
    total_local_count: u16,

    /// Calculates the size of a stack frame that is being allocated.
    pub fn calculate(
        callee: FuncAddr,
        comptime params: ParameterAllocation,
    ) error{ValidationNeeded}!FrameSize {
        const signature = callee.signature();
        const param_count = signature.param_count;
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
            .host => signature.result_count -| param_count, // ensure enough space for results
            .wasm => |wasm| wasm.code().inner.max_values,
        };

        const allocated_size = Frame.size_in_values + allocated_local_count + value_stack_size;
        std.debug.assert(allocated_size > allocated_local_count);
        return FrameSize{
            .allocated_local_count = allocated_local_count,
            .total_local_count = param_count + local_count,
            .allocated_size = allocated_size,
        };
    }
};

/// Records information about a called WASM or host function.
///
/// ## Stack Layout
///
/// ```txt
/// |============  bottom   ============|
/// |                                   |
/// |        `Frame` - previous         |
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
/// |        `Frame` - current          |
/// |                                   |
/// |-----------------------------------|
/// |                                   |
/// |     `[*]Value` - value stack      |
/// |                                   |
/// |==============  top  ==============|
/// ```
pub const Frame = extern struct {
    /// For every WASM stack frame, a checksum of the previous stack frame's data (its contents
    /// on the value stack and the `StackFrame` structure itself) is calculated. This is
    /// possible since WASM code only allows the function at the top of the stack to modify the
    /// value stack.
    ///
    /// This is used to detect bugs in debug mode where the value stacks of functions are
    /// incorrectly modified.
    ///
    /// On function return, this is recalculated to determine if an OOB error occurred.
    checksum: (if (builtin.mode == .Debug) u128 else void) align(@sizeOf(Value)),

    function: FuncAddr align(@sizeOf(Value)),

    signature: *const Module.FuncType,
    /// Set to `true` when the function returns.
    ///
    /// If the function is the start function, then this indicates that the module was successfully
    /// instantiated. Otherwise, this points to a dummy memory location which is never read.
    instantiate_flag: *bool,

    local_count: packed struct(u32) {
        /// The total number of parameters and local variables.
        total: u17,
        padding: enum(u15) { padding = 0 } = .padding,
    },
    /// Offset indexing into `Stack.allocated` pointing to the previous stack frame.
    prev_frame: Offset,
    /// Fields only used for WASM frames.
    ///
    /// The value stack pointer is not saved since it is implied by offset of `StackFrame`.
    ///
    /// Could move back to variable-length `Frame`, but the resulting headache is only worth 16-bytes
    /// in savings per frame.
    wasm: extern struct {
        ip: Module.Code.Ip,

        /// Pointer to the last `end` instruction which denotes an implicit return from the function.
        eip: *const Module.Code.End,
        stp: SideTable.Ptr,
    },

    const Offset = enum(u32) {
        none = std.math.maxInt(u32),
        _,
    };

    comptime {
        std.debug.assert(@sizeOf(Frame) == @sizeOf(Value) * size_in_values);
        std.debug.assert(@alignOf(Frame) == @sizeOf(Value));
    }

    /// Asserts that `frame` is of a WASM function.
    pub fn currentModule(frame: *const Frame) runtime.ModuleInst {
        return frame.function.expanded().wasm.module;
    }

    /// Gets a slice of the function parameters and locals.
    pub fn localValues(
        frame: anytype,
        stack: *const Stack,
    ) ChangePointee(@TypeOf(frame), .slice, @sizeOf(Value), Value) {
        const base: ChangePointee(@TypeOf(frame), .many, @sizeOf(Value), Value) =
            @ptrCast(frame);

        stack.assertSliceInBounds(base[0..size_in_values]);

        const locals = (base - frame.local_count.total)[0..frame.local_count.total];
        stack.assertSliceInBounds(locals);
        return locals;
    }

    pub const size_in_values: comptime_int = @divExact(@sizeOf(Frame), @sizeOf(Value));

    pub fn valueStackBase(frame: anytype) ChangePointee(@TypeOf(frame), .many, @sizeOf(Value), Value) {
        return @as([*]align(@sizeOf(Value)) Value, @ptrCast(@constCast(frame))) +
            Frame.size_in_values;
    }

    /// Calculates a checksum of the stack frame's contents.
    pub fn calculateChecksum(
        /// The frame to calculate a checksum for.
        frame: *const Frame,
        stack: *const Stack,
        top: Top,
    ) u128 {
        const locals = frame.localValues(stack);
        const values_base = frame.valueStackBase();
        std.debug.assert(@intFromPtr(values_base) <= @intFromPtr(top.ptr));
        const values = frame.valueStackBase()[0..(top.ptr - values_base)];
        stack.assertSliceInBounds(values);

        const frame_function = frame.function.expanded();
        switch (frame_function) {
            .wasm => |wasm| if (builtin.mode == .Debug and wasm.code().isValidationFinished()) {
                std.debug.assert(values.len <= wasm.code().inner.max_values);
            },
            .host => {},
        }

        // std.debug.print(
        //     "Calculating hash for frame {f} {*} {} {?}" ++
        //         "with {} locals {*}..{*} & {} value stack {*}..{*}\n",
        //     .{
        //         frame.function,
        //         frame,
        //         frame.*,
        //         if (frame.function.expanded() == .wasm) frame.wasmFrame().* else null,
        //         locals.len,
        //         locals.ptr,
        //         locals_and_frame.ptr + locals_and_frame.len,
        //         value_stack.len,
        //         value_stack_base,
        //         values_end,
        //     },
        // );

        // Fowler-Noll-Vo is designed for both hashing AND checksums.
        var hasher = std.hash.Fnv1a_128.init();
        hasher.update(std.mem.sliceAsBytes(locals));
        std.hash.autoHash(&hasher, frame.checksum);
        frame.function.hash(&hasher);
        std.hash.autoHash(&hasher, frame.signature);
        std.hash.autoHash(&hasher, frame.instantiate_flag);
        std.hash.autoHash(&hasher, @as(u32, frame.local_count.total));
        std.hash.autoHash(&hasher, frame.prev_frame);
        std.hash.autoHash(&hasher, frame.wasm); // TODO: See if IP and STP can be hashed
        hasher.update(std.mem.sliceAsBytes(values));
        const final = hasher.final();
        // std.debug.print("HASH RESULT = {X}\n", .{final});
        return final;
    }
};

/// Obtains a pointer to the stack frame at the given `offset`.
pub fn frameAt(stack: Stack, offset: Frame.Offset) ?*Frame {
    switch (offset) {
        .none => return null,
        else => {
            const base_idx = @intFromEnum(offset);
            const frame: *Frame = @ptrCast(
                @as(
                    []align(@sizeOf(Value)) Value,
                    stack.allocated[base_idx .. base_idx + Frame.size_in_values],
                ),
            );

            if (builtin.mode == .Debug) {
                switch (frame.function.expanded()) {
                    .wasm => |wasm| stack.assertSliceInBounds(
                        frame.valueStackBase()[0..wasm.code().inner.max_values],
                    ),
                    .host => {},
                }
            }

            return frame;
        },
    }
}

/// Allows restoring the stack to a previous state after popping values, and asserts that popped
/// values have not been modified.
pub const Saved = struct {
    pub const has_checksum = builtin.mode == .Debug;

    saved_top: Top,
    /// Tracks how many values are being restored.
    popped: u16,
    checksum: if (has_checksum) u64 else void,

    const Checksum = std.hash.Fnv1a_64;

    pub fn pop(values: Values, count: u16) Saved {
        const saved_top = values.top;
        const popped = values.topSlice(count);
        std.debug.assert(@intFromPtr(popped.ptr + count) == @intFromPtr(saved_top.ptr));
        return Saved{
            .saved_top = saved_top,
            .popped = count,
            .checksum = if (has_checksum) Checksum.hash(std.mem.sliceAsBytes(popped)),
        };
    }

    /// Gets a slice of all of the values that have been popped.
    pub fn poppedValues(self: *const Saved) []align(@sizeOf(Value)) const Value {
        return (self.saved_top.ptr - self.popped)[0..self.popped];
    }

    pub fn checkIntegrity(self: *const Saved) void {
        if (!has_checksum) {
            return;
        }

        const actual_checksum = Checksum.hash(std.mem.sliceAsBytes(self.poppedValues()));
        if (actual_checksum != self.checksum) {
            std.debug.panic( // bad restored SP checksum
                "bad restored stack checksum!\nexpected: {X:0>16}\n  actual: {X:0>16}",
                .{ self.checksum, actual_checksum },
            );
        }
    }
};

/// Used to walk the call stack, such as when generating stack traces.
pub const Walker = struct {
    stack: Stack,

    pub fn currentFrame(walker: *const Walker) ?*const Frame {
        return walker.stack.currentFrame();
    }

    /// Returns `true` if `currentFrame` had a previous stack frame.
    pub fn next(walker: *Walker) bool {
        if (walker.stack.call_depth == 0) {
            std.debug.assert(walker.stack.current_frame == .none); // call depth mismatch
            return false;
        } else {
            const current_frame = walker.currentFrame().?; // call_depth mismatch
            const prev_frame = current_frame.prev_frame;
            std.debug.assert( // previous frame must have lesser address
                prev_frame == .none or
                    @intFromEnum(prev_frame) < @intFromEnum(walker.stack.current_frame),
            );
            walker.stack.current_frame = prev_frame;
            walker.stack.call_depth -= 1;
            return true;
        }
    }

    fn FormatLowAddress(comptime P: type) type {
        return struct {
            ptr: P,

            comptime {
                std.debug.assert(@typeInfo(P) == .pointer);
            }

            pub fn format(self: @This(), writer: *Writer) Writer.Error!void {
                try writer.print("[*{X:0>6}]", .{@as(u24, @truncate(@intFromPtr(self.ptr)))});
            }
        };
    }

    fn formatLowAddress(ptr: anytype) FormatLowAddress(@TypeOf(ptr)) {
        return .{ .ptr = ptr };
    }

    pub fn formatIp(ip: Module.Code.Ip, writer: *Writer) Writer.Error!void {
        try writer.print("0x{X:0>2}", .{ip[0]});
        if (std.enums.fromInt(@import("../opcodes.zig").ByteOpcode, ip[0])) |opcode| {
            try writer.print("({t})", .{opcode});
        }
        try writer.print("@{X}", .{@intFromPtr(ip)});
    }

    pub fn format(initial_walker: Walker, writer: *Writer) Writer.Error!void {
        var walker = initial_walker;
        const n = walker.stack.call_depth;
        while (walker.currentFrame()) |frame| {
            defer _ = walker.next();
            try writer.print("#{[index]} {[addr]f} {[callee]f}", .{
                .index = n - walker.stack.call_depth,
                .addr = formatLowAddress(frame),
                .callee = frame.function,
            });

            switch (frame.function.expanded()) {
                .wasm => try writer.print(
                    " ip={[ip]f}",
                    .{ .ip = std.fmt.Alt(Module.Code.Ip, formatIp){ .data = frame.wasm.ip } },
                ),
                .host => {},
            }

            try writer.writeByte('\n');
        }
    }
};

pub fn deinit(stack: *Stack, alloca: Allocator) void {
    alloca.free(stack.allocated);
    stack.* = undefined;
}

const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const Writer = std.Io.Writer;
const Value = @import("value.zig").Value;
const SideTable = @import("side_table.zig").SideTable;
const runtime = @import("../runtime.zig");
const FuncAddr = runtime.FuncAddr;
const Module = @import("../Module.zig");
const coz = @import("coz");
