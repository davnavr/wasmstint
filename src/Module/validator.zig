//! Implements the WebAssembly [validation algorithm] and side-table generation
//! as described in Ben L. Titzer's ["A fast in-place interpreter for WebAssembly"].
//!
//! `wasmstint` is currently designed to lazily validate functions.
//! For more information, see <https://github.com/WebAssembly/design/issues/1464>.
//!
//! [validation algorithm]: https://webassembly.github.io/spec/core/appendix/algorithm.html
//! ["A fast in-place interpreter for WebAssembly"]: https://doi.org/10.48550/arXiv.2205.01183

const std = @import("std");
const Allocator = std.mem.Allocator;
const ArenaAllocator = std.heap.ArenaAllocator;

const Module = @import("../Module.zig");
const ValType = Module.ValType;
const opcodes = @import("../opcodes.zig");

pub const Error = error{InvalidWasm} ||
    Module.ReaderError ||
    Module.LimitError ||
    Allocator.Error;

/// Describes the changes to interpreter state should occur if its corresponding branch is taken.
pub const SideTableEntry = packed struct(u64) {
    delta_ip: i32,
    delta_stp: i16,
    copy_count: u8,
    pop_count: u8,
};

pub const End = enum(u8) { end = @intFromEnum(opcodes.ByteOpcode.end) };

pub const Ip = [*:@intFromEnum(opcodes.ByteOpcode.end)]const u8;

pub const State = struct {
    /// Pointer to the first byte of the first opcode.
    instructions: Ip = undefined,
    instructions_end: *const End = undefined,
    flag: std.atomic.Value(Flag) = .{ .raw = .init },
    side_table_len: u32 = undefined,
    side_table_ptr: [*]const SideTableEntry = undefined,
    @"error": ?Error = null,
    /// The maximum amount of space needed in the value stack for executing this function.
    max_values: u16 = undefined,
    /// The number of local variables, excluding parameters.
    local_values: u16 = undefined,
    /// Offset into the code bytes indicating where the error occurred.
    ///
    /// For example, `0` means the first byte of the LEB128-encoded count of the locals vector.
    error_offset: u32 = undefined,

    pub const Sizes = extern struct {
        /// The maximum amount of space needed in the value stack for executing this function.
        max_values: u32,
        /// The number of local variables, excluding parameters.
        local_values: u32,
    };

    /// 32-bit integer allows using `std.Thread.Futex` to wait for another thread that is currently
    /// validating the same code.
    pub const Flag = enum(u32) {
        init = 0,
        validating = 1,
        successful = 2,
        failed = 3,
    };

    pub fn isValidated(state: *State) bool {
        return switch (state.flag.load(.acquire)) {
            .init, .validating => false,
            .successful, .failed => true,
        };
    }

    /// Waits until validation in the other thread finishes.
    pub fn waitForValidation(state: *State, futex_timeout: std.Thread.Futex.Deadline) error{Timeout}!?Error {
        comptime std.debug.assert(@bitSizeOf(Flag) == 32);
        while (true) {
            try futex_timeout.wait(@ptrCast(&state.flag), @intFromEnum(Flag.validating));
            switch (state.flag.load(.acquire)) {
                .init, .validating => continue,
                .successful => return null,
                .failed => return state.@"error",
            }
        }
    }

    /// Returns `true` if validation succeeded, `false` if the current thread would block, or an
    /// error if validation failed.
    ///
    /// If `false` is returned, callers can wait for validation on the other thread to finish
    /// by calling `.waitForValidation()`.
    pub fn validate(
        state: *State,
        allocator: Allocator,
        module: *const Module,
        signature: Module.TypeIdx,
        code: Module.WasmSlice,
        scratch: *ArenaAllocator,
    ) Error!bool {
        check: {
            const current_flag = state.flag.cmpxchgWeak(
                Flag.init,
                Flag.validating,
                .acquire,
                .acquire,
            ) orelse break :check;

            return switch (current_flag) {
                .init => unreachable,
                .validating => false,
                .successful => true,
                .failed => state.@"error".?,
            };
        }

        // Now only this thread can modify `State`.
        std.debug.assert(code.size <= std.math.maxInt(u32));

        _ = scratch.reset(.retain_capacity);
        try doValidation(
            state,
            allocator,
            module,
            signature,
            code.slice(module.inner.code_section, module.wasm),
            scratch,
        );

        return true;
    }
};

const Val = @Type(std.builtin.Type{
    .@"enum" = std.builtin.Type.Enum{
        .tag_type = u8,
        .fields = fields: {
            const val_type_fields = @typeInfo(ValType).@"enum".fields;
            var fields: [val_type_fields.len + 1]std.builtin.Type.EnumField = undefined;
            fields[0] = .{ .name = "unknown", .value = 0 };
            @memcpy(fields[1..], val_type_fields);
            break :fields &fields;
        },
        .decls = &[0]std.builtin.Type.Declaration{},
        .is_exhaustive = false,
    },
});

inline fn valTypeToVal(val_type: ValType) Val {
    comptime {
        for (@typeInfo(ValType).@"enum".fields) |field| {
            std.debug.assert(@intFromEnum(@field(Val, field.name)) == @intFromEnum(@field(ValType, field.name)));
        }
    }

    return @enumFromInt(@intFromEnum(val_type));
}

const ValTypeBuf = std.SegmentedList(ValType, 128);

const BlockType = union(enum) {
    type: packed struct(u32) {
        results_only: bool = false,
        idx: Module.TypeIdx,
    },
    single_result: ValType,
    void,

    fn funcType(block_type: *const BlockType, module: *const Module) Module.FuncType {
        switch (block_type.*) {
            .type => |@"type"| {
                const copied = @"type".idx.funcType(module).*;
                return if (@"type".results_only) copied else .{
                    .param_count = 0,
                    .result_count = copied.result_count,
                    .types = copied.results().ptr,
                };
            },
            .single_result => |*ty| return .{
                .types = ty[0..1],
                .param_count = 0,
                .result_count = 1,
            },
            .void => return .empty,
        }
    }

    fn read(reader: Module.Reader, module: *const Module) Error!BlockType {
        var int_bytes = reader.bytes.*;
        const int_reader = Module.Reader{ .bytes = &int_bytes };
        const tag_int = try int_reader.readIleb128(i33);

        var byte_bytes = reader.bytes.*;
        const byte_reader = Module.Reader{ .bytes = &byte_bytes };
        const byte_tag = byte_reader.readByte() catch unreachable;

        if (byte_tag == 0x40) {
            reader.bytes.* = byte_bytes;
            return BlockType.void;
        } else if (tag_int >= 0) {
            const idx = std.math.cast(@typeInfo(Module.TypeIdx).@"enum".tag_type, tag_int) orelse
                return Error.WasmImplementationLimit;

            reader.bytes.* = int_bytes;
            return if (idx < module.inner.types_count)
                BlockType{ .type = .{ .idx = @enumFromInt(idx) } }
            else
                Error.InvalidWasm;
        } else {
            reader.bytes.* = byte_bytes;
            return BlockType{
                .single_result = std.meta.intToEnum(
                    ValType,
                    byte_tag,
                ) catch return Error.MalformedWasm,
            };
        }
    }

    comptime {
        std.debug.assert(@sizeOf(BlockType) == 8);
    }
};

const CtrlFrame = struct {
    types: BlockType,
    info: packed struct(u32) {
        height: Height,
        opcode: Opcode,
        @"unreachable": bool = false,
    },
    /// Offset from the first byte of the first instruction to the first byte of the block's `opcode`.
    offset: u32,
    /// The length of the side table when the block was entered.
    side_table_idx: u32,

    const Height = u28;

    const Opcode = enum(u3) {
        block,
        loop,
        @"if",
        @"else",
        end,
    };

    fn labelTypes(frame: *const CtrlFrame, module: *const Module) []const ValType {
        const types = frame.types.funcType(module);
        return if (frame.info.opcode != .loop) types.results() else types.parameters();
    }
};

const CtrlStack = std.SegmentedList(CtrlFrame, 16);

const ValStack = struct {
    buf: ValTypeBuf,
    max: u16 = 0,

    inline fn len(val_stack: *const ValStack) u16 {
        return @intCast(val_stack.buf.len);
    }

    fn push(val_stack: *ValStack, arena: *ArenaAllocator, val_type: ValType) Error!void {
        try val_stack.buf.append(arena.allocator(), val_type);
        val_stack.max = @max(val_stack.max, std.math.cast(u16, val_stack.buf.len) orelse return Error.WasmImplementationLimit);
    }

    /// Asserts that `types.len() <= std.math.maxInt(u16)`.
    fn pushMany(val_stack: *ValStack, arena: *ArenaAllocator, types: []const ValType) Error!void {
        const new_len = std.math.add(u16, val_stack.len(), @intCast(types.len)) catch
            return Error.WasmImplementationLimit;

        if (new_len > ValTypeBuf.prealloc_count) {
            try val_stack.buf.growCapacity(arena.allocator(), new_len);
        }

        for (types) |ty| val_stack.buf.append(undefined, ty) catch unreachable;
        val_stack.max = @max(new_len, val_stack.max);
    }

    fn popAny(val_stack: *ValStack, ctrl_stack: *const CtrlStack) Error!Val {
        const current_frame: *const CtrlFrame = ctrl_stack.at(ctrl_stack.len - 1);
        if (val_stack.len() == current_frame.info.height) {
            return if (current_frame.info.@"unreachable") Val.unknown else Error.InvalidWasm;
        }

        return valTypeToVal(val_stack.buf.pop().?);
    }

    fn popExpecting(val_stack: *ValStack, ctrl_stack: *const CtrlStack, expected: ValType) Error!void {
        const popped = try val_stack.popAny(ctrl_stack);
        if (popped != valTypeToVal(expected) and popped != .unknown)
            return Error.InvalidWasm;
    }

    fn popThenPushExpecting(
        val_stack: *ValStack,
        arena: *ArenaAllocator,
        ctrl_stack: *const CtrlStack,
        expected: ValType,
        replacement: ValType,
    ) Error!void {
        const current_frame: *const CtrlFrame = ctrl_stack.at(ctrl_stack.len - 1);
        if (val_stack.len() > current_frame.info.height) {
            const top: *ValType = val_stack.buf.at(val_stack.len() - 1);
            if (top.* != expected) return Error.InvalidWasm;
            top.* = replacement;
        } else if (current_frame.info.@"unreachable") {
            return val_stack.push(arena, replacement);
        } else {
            return Error.InvalidWasm;
        }
    }

    fn popManyExpecting(val_stack: *ValStack, ctrl_stack: *const CtrlStack, expected: []const ValType) Error!void {
        for (0..expected.len) |i| {
            try val_stack.popExpecting(ctrl_stack, expected[expected.len - 1 - i]);
        }
    }
};

fn readLocalIdx(reader: *Module.Reader, locals: []const ValType) Error!ValType {
    const idx = try reader.readUleb128(u32);
    return if (idx < locals.len) locals[idx] else Error.InvalidWasm;
}

const Label = struct {
    frame: *const CtrlFrame,
    idx: u32,
    copy_count: u8,
    pop_count: u8,

    fn read(reader: *Module.Reader, ctrl_stack: *const CtrlStack, module: *const Module) Error!Label {
        const idx = try reader.readUleb128(u32);
        const frame: *const CtrlFrame = if (idx < ctrl_stack.len)
            ctrl_stack.at(ctrl_stack.len - 1 - idx)
        else
            return Error.InvalidWasm;

        return Label{
            .frame = frame,
            .idx = idx,
            .copy_count = std.math.cast(u8, frame.labelTypes(module).len) orelse
                return Error.WasmImplementationLimit,
            .pop_count = std.math.cast(u8, ctrl_stack.at(ctrl_stack.len - 1).info.height - frame.info.height) orelse
                return Error.WasmImplementationLimit,
        };
    }
};

//fn readDataIdx(module: *const Module) // TODO: Check data count sec value

fn pushCtrlFrame(
    arena: *ArenaAllocator,
    ctrl_stack: *CtrlStack,
    val_stack: *ValStack,
    side_table: *const SideTableBuf,
    opcode: CtrlFrame.Opcode,
    offset: u32,
    block_type: BlockType,
    module: *const Module,
) Error!void {
    try ctrl_stack.append(
        arena.allocator(),
        CtrlFrame{
            .types = block_type,
            .info = .{
                .opcode = opcode,
                .height = std.math.cast(CtrlFrame.Height, val_stack.len()) orelse
                    return Error.WasmImplementationLimit,
            },
            .offset = offset,
            .side_table_idx = std.math.cast(u32, side_table.len) orelse
                return Error.WasmImplementationLimit,
        },
    );

    try val_stack.pushMany(arena, block_type.funcType(module).parameters());
}

fn popCtrlFrame(
    ctrl_stack: *CtrlStack,
    val_stack: *ValStack,
    module: *const Module,
) Error!CtrlFrame {
    if (ctrl_stack.len == 0) return Error.InvalidWasm;

    const frame = ctrl_stack.at(ctrl_stack.len - 1).*;
    try val_stack.popManyExpecting(ctrl_stack, frame.types.funcType(module).results());
    if (val_stack.len() != frame.info.height) return Error.InvalidWasm;
    ctrl_stack.len -= 1;
    return frame;
}

fn markUnreachable(val_stack: *ValStack, ctrl_stack: *CtrlStack) void {
    const current_frame: *CtrlFrame = ctrl_stack.at(ctrl_stack.len - 1);
    val_stack.buf.len = current_frame.info.height;
    current_frame.info.@"unreachable" = true;
}

const SideTableBuf = std.SegmentedList(SideTableEntry, 4);

const BranchFixup = packed struct(u64) {
    /// Offset from the first byte of the first instruction to the first byte of the
    /// branch instruction.
    origin: u32, // Could stash this field in the SideTableEntry.delta_ip instead, @bitCast-ed.
    entry_idx: u32,

    const List = std.SegmentedList(BranchFixup, 4);

    fn resolveList(fixups: *const List, end_offset: u32, entries: *SideTableBuf) Module.LimitError!void {
        const target_side_table_idx = std.math.cast(u32, entries.len) orelse
            return error.WasmImplementationLimit;

        var iter_fixups = fixups.constIterator(0);
        while (iter_fixups.next()) |fixup_entry| {
            const entry: *SideTableEntry = entries.at(fixup_entry.entry_idx);

            // TODO: +1 to go directly to the block body.
            entry.delta_ip = std.math.cast(i32, end_offset - fixup_entry.origin) orelse
                return error.WasmImplementationLimit;

            entry.delta_stp = std.math.cast(i16, target_side_table_idx - fixup_entry.entry_idx) orelse
                return error.WasmImplementationLimit;
        }
    }
};

const BranchFixupStack = struct {
    active: std.SegmentedList(BranchFixup.List, 4) = .{},
    free: std.SegmentedList(BranchFixup.List, 4) = .{},

    fn push(fixups: *BranchFixupStack, arena: *ArenaAllocator) Allocator.Error!void {
        const to_push = fixups.free.pop() orelse BranchFixup.List{};
        std.debug.assert(to_push.len == 0);
        try fixups.active.append(arena.allocator(), to_push);
    }

    fn append(fixups: *BranchFixupStack, arena: *ArenaAllocator, entry: BranchFixup) Allocator.Error!void {
        const current_list: *BranchFixup.List = fixups.active.at(fixups.active.len - 1);
        try current_list.append(arena.allocator(), entry);
    }

    /// Asserts that `active.len > 0`, and that all of the branch fixup entries correspond to branches
    /// that are placed before `end_offset`.
    fn popAndResolve(
        fixups: *BranchFixupStack,
        arena: *ArenaAllocator,
        end_offset: u32,
        entries: *SideTableBuf,
    ) Module.LimitError!void {
        var to_fixup: BranchFixup.List = fixups.active.pop().?;
        defer {
            to_fixup.clearRetainingCapacity();
            fixups.free.append(arena.allocator(), to_fixup) catch {};
        }

        try BranchFixup.resolveList(&to_fixup, end_offset, entries);
    }
};

fn appendSideTableEntry(
    arena: *ArenaAllocator,
    side_table: *SideTableBuf,
    branch_fixups: *BranchFixupStack,
    origin_offset: u32,
    target: Label,
) Error!void {
    const side_table_idx = std.math.cast(u32, side_table.len) orelse
        return Error.WasmImplementationLimit;

    const entry: *SideTableEntry = try side_table.addOne(arena.allocator());
    entry.* = .{
        .copy_count = target.copy_count,
        .pop_count = target.pop_count,
        .delta_ip = undefined,
        .delta_stp = undefined,
    };

    if (target.frame.info.opcode == .loop) {
        // TODO: +1 to go directly to the loop body.
        entry.delta_ip = std.math.negateCast(origin_offset - target.frame.offset) catch
            return Error.WasmImplementationLimit;

        const delta_stp = std.math.negateCast(side_table_idx - target.frame.side_table_idx) catch
            return Error.WasmImplementationLimit;

        entry.delta_stp = std.math.cast(i16, delta_stp) orelse
            return Error.WasmImplementationLimit;
    } else {
        try branch_fixups.append(arena, .{
            .origin = origin_offset,
            .entry_idx = side_table_idx,
        });
    }
}

fn doValidation(
    state: *State,
    allocator: Allocator,
    module: *const Module,
    signature: Module.TypeIdx,
    code: []const u8,
    scratch: *ArenaAllocator,
) Error!void {
    var code_ptr = code;
    var reader = Module.Reader.init(&code_ptr);

    errdefer |e| {
        state.@"error" = e;
        state.flag.store(State.Flag.failed, .release);
        state.error_offset = @intCast(code_ptr.ptr - code.ptr);
    }

    const func_type = signature.funcType(module);

    var val_stack: ValStack = undefined;
    const locals: []const ValType = locals: {
        const local_group_count = try reader.readUleb128(u32);
        var local_vars = ValTypeBuf{};

        const reserve_count = std.math.add(u32, func_type.param_count, local_group_count) catch
            return error.OutOfMemory;

        // if (local_group_count > ValTypeBuf.prealloc_count) {
        try local_vars.setCapacity(scratch.allocator(), reserve_count);
        //

        defer {
            local_vars.clearRetainingCapacity();
            val_stack = ValStack{ .buf = local_vars };
        }

        local_vars.appendSlice(undefined, func_type.parameters()) catch unreachable;

        for (0..local_group_count) |_| {
            const local_count = try reader.readUleb128(u32);
            const local_type = try reader.readValType();
            const new_local_len = std.math.add(u32, @intCast(local_vars.len), local_count) catch
                return error.WasmImplementationLimit;

            // if (new_local_len > ValTypeBuf.prealloc_count) {
            try local_vars.growCapacity(scratch.allocator(), new_local_len);
            // }

            for (0..local_count) |_| {
                local_vars.append(undefined, local_type) catch unreachable;
            }
        }

        state.local_values = @intCast(local_vars.len);

        const buf = try scratch.allocator().alloc(ValType, local_vars.len);
        local_vars.writeToSlice(buf, 0);
        break :locals buf;
    };

    var side_table = SideTableBuf{};
    _ = &side_table;

    var ctrl_stack = CtrlStack{};
    ctrl_stack.append(
        undefined,
        CtrlFrame{
            .types = .{ .type = .{ .idx = signature, .results_only = true } },
            .info = .{
                .height = 0,
                .opcode = .block,
            },
            .offset = 0,
            .side_table_idx = 0,
        },
    ) catch unreachable;

    var branch_fixups = BranchFixupStack{};
    branch_fixups.push(scratch) catch unreachable;

    state.instructions = @ptrCast(reader.bytes.ptr);

    var instr_offset: u32 = 0;
    while (ctrl_stack.len > 0) {
        // Offset from the first byte of the first instruction to the first byte of the instruction being parsed.
        instr_offset = @intCast(@intFromPtr(reader.bytes.ptr) - @intFromPtr(state.instructions));
        const byte_tag = try reader.readByteTag(opcodes.ByteOpcode);
        // std.debug.print("validate: {}\n", .{byte_tag});
        switch (byte_tag) {
            .@"unreachable" => markUnreachable(&val_stack, &ctrl_stack),
            .nop => {},
            .block => {
                const block_type = try BlockType.read(reader, module);
                try val_stack.popManyExpecting(&ctrl_stack, block_type.funcType(module).parameters());
                try pushCtrlFrame(
                    scratch,
                    &ctrl_stack,
                    &val_stack,
                    &side_table,
                    .block,
                    instr_offset,
                    block_type,
                    module,
                );

                // TODO: Skip branch fixup processing for unreachable code.
                try branch_fixups.push(scratch);
            },
            .loop => {
                const block_type = try BlockType.read(reader, module);
                try val_stack.popManyExpecting(&ctrl_stack, block_type.funcType(module).parameters());
                try pushCtrlFrame(
                    scratch,
                    &ctrl_stack,
                    &val_stack,
                    &side_table,
                    .loop,
                    instr_offset,
                    block_type,
                    module,
                );
            },
            .@"if" => {
                const block_type = try BlockType.read(reader, module);
                try val_stack.popExpecting(&ctrl_stack, .i32);
                try val_stack.popManyExpecting(&ctrl_stack, block_type.funcType(module).parameters());
                try pushCtrlFrame(
                    scratch,
                    &ctrl_stack,
                    &val_stack,
                    &side_table,
                    .@"if",
                    instr_offset,
                    block_type,
                    module,
                );
                // TODO: Skip branch fixup processing for unreachable code.
                try branch_fixups.push(scratch);
            },
            .@"else" => {
                const frame = try popCtrlFrame(&ctrl_stack, &val_stack, module);
                if (frame.info.opcode != .@"if")
                    return error.InvalidWasm;

                try pushCtrlFrame(
                    scratch,
                    &ctrl_stack,
                    &val_stack,
                    &side_table,
                    .@"else",
                    instr_offset,
                    frame.types,
                    module,
                );

                // No need to modify branch fixup table, branches to the `else` go to the same place as branches to the `if`.
            },
            .end => {
                const frame = try popCtrlFrame(&ctrl_stack, &val_stack, module);

                if (frame.info.opcode != .loop) {
                    // TODO: Skip branch fixup processing for unreachable code.
                    try branch_fixups.popAndResolve(scratch, instr_offset, &side_table);
                }

                try val_stack.pushMany(scratch, frame.types.funcType(module).results());
            },
            .br => {
                const label = try Label.read(&reader, &ctrl_stack, module);
                // TODO: Skip branch fixup processing for unreachable code.
                try appendSideTableEntry(scratch, &side_table, &branch_fixups, instr_offset, label);
                try val_stack.popManyExpecting(&ctrl_stack, label.frame.labelTypes(module));
            },
            .drop => _ = try val_stack.popAny(&ctrl_stack),
            .@"local.get" => {
                const local_type = try readLocalIdx(&reader, locals);
                try val_stack.push(scratch, local_type);
            },
            .@"local.set" => {
                const local_type = try readLocalIdx(&reader, locals);
                try val_stack.popExpecting(&ctrl_stack, local_type);
            },
            .@"local.tee" => {
                const local_type = try readLocalIdx(&reader, locals);
                try val_stack.popThenPushExpecting(scratch, &ctrl_stack, local_type, local_type);
            },
            .@"i32.const" => {
                _ = try reader.readIleb128(i32);
                try val_stack.push(scratch, .i32);
            },
            .@"i64.const" => {
                _ = try reader.readIleb128(i64);
                try val_stack.push(scratch, .i64);
            },
            .@"f32.const" => {
                _ = try reader.readArray(4);
                try val_stack.push(scratch, .f32);
            },
            .@"f64.const" => {
                _ = try reader.readArray(8);
                try val_stack.push(scratch, .f64);
            },
            .@"i32.eqz",
            .@"i32.clz",
            .@"i32.ctz",
            .@"i32.popcnt",
            .@"i32.extend8_s",
            .@"i32.extend16_s",
            => try val_stack.popThenPushExpecting(scratch, &ctrl_stack, .i32, .i32),
            .@"i32.eq",
            .@"i32.ne",
            .@"i32.lt_s",
            .@"i32.lt_u",
            .@"i32.gt_s",
            .@"i32.gt_u",
            .@"i32.le_s",
            .@"i32.le_u",
            .@"i32.ge_s",
            .@"i32.ge_u",
            .@"i32.add",
            .@"i32.sub",
            .@"i32.mul",
            .@"i32.div_s",
            .@"i32.div_u",
            .@"i32.rem_s",
            .@"i32.rem_u",
            .@"i32.and",
            .@"i32.or",
            .@"i32.xor",
            .@"i32.shl",
            .@"i32.shr_s",
            .@"i32.shr_u",
            .@"i32.rotl",
            .@"i32.rotr",
            => {
                try val_stack.popExpecting(&ctrl_stack, .i32);
                try val_stack.popThenPushExpecting(scratch, &ctrl_stack, .i32, .i32);
            },
            .@"i64.eq",
            .@"i64.ne",
            .@"i64.lt_s",
            .@"i64.lt_u",
            .@"i64.gt_s",
            .@"i64.gt_u",
            .@"i64.le_s",
            .@"i64.le_u",
            .@"i64.ge_s",
            .@"i64.ge_u",
            => {
                try val_stack.popExpecting(&ctrl_stack, .i64);
                try val_stack.popThenPushExpecting(scratch, &ctrl_stack, .i64, .i32);
            },
            .@"i64.clz",
            .@"i64.ctz",
            .@"i64.popcnt",
            .@"i64.extend8_s",
            .@"i64.extend16_s",
            .@"i64.extend32_s",
            => try val_stack.popThenPushExpecting(scratch, &ctrl_stack, .i64, .i64),
            .@"i64.add",
            .@"i64.sub",
            .@"i64.mul",
            .@"i64.div_s",
            .@"i64.div_u",
            .@"i64.rem_s",
            .@"i64.rem_u",
            .@"i64.and",
            .@"i64.or",
            .@"i64.xor",
            .@"i64.shl",
            .@"i64.shr_s",
            .@"i64.shr_u",
            .@"i64.rotl",
            .@"i64.rotr",
            => {
                try val_stack.popExpecting(&ctrl_stack, .i64);
                try val_stack.popThenPushExpecting(scratch, &ctrl_stack, .i64, .i64);
            },
            .@"i64.eqz",
            .@"i32.wrap_i64",
            => try val_stack.popThenPushExpecting(scratch, &ctrl_stack, .i64, .i32),
            .@"i32.trunc_f32_s",
            .@"i32.trunc_f32_u",
            .@"i32.reinterpret_f32",
            => try val_stack.popThenPushExpecting(scratch, &ctrl_stack, .f32, .i32),
            .@"i32.trunc_f64_s",
            .@"i32.trunc_f64_u",
            => try val_stack.popThenPushExpecting(scratch, &ctrl_stack, .f64, .i32),
            .@"i64.extend_i32_s",
            .@"i64.extend_i32_u",
            => try val_stack.popThenPushExpecting(scratch, &ctrl_stack, .i32, .i64),
            .@"i64.trunc_f32_s",
            .@"i64.trunc_f32_u",
            => try val_stack.popThenPushExpecting(scratch, &ctrl_stack, .f32, .i64),
            .@"i64.trunc_f64_s",
            .@"i64.trunc_f64_u",
            .@"i64.reinterpret_f64",
            => try val_stack.popThenPushExpecting(scratch, &ctrl_stack, .f64, .i64),
            .@"f32.convert_i32_s",
            .@"f32.convert_i32_u",
            .@"f32.reinterpret_i32",
            => try val_stack.popThenPushExpecting(scratch, &ctrl_stack, .i32, .f32),
            .@"f32.convert_i64_s",
            .@"f32.convert_i64_u",
            => try val_stack.popThenPushExpecting(scratch, &ctrl_stack, .i64, .f32),
            .@"f32.demote_f64" => try val_stack.popThenPushExpecting(scratch, &ctrl_stack, .f64, .f32),
            .@"f64.convert_i32_s",
            .@"f64.convert_i32_u",
            => try val_stack.popThenPushExpecting(scratch, &ctrl_stack, .i32, .f64),
            .@"f64.convert_i64_s",
            .@"f64.convert_i64_u",
            .@"f64.reinterpret_i64",
            => try val_stack.popThenPushExpecting(scratch, &ctrl_stack, .i64, .f64),
            .@"f64.promote_f32" => try val_stack.popThenPushExpecting(scratch, &ctrl_stack, .f32, .f64),
            .@"0xFC" => switch (try reader.readUleb128Enum(u32, opcodes.FCPrefixOpcode)) {
                .@"i32.trunc_sat_f32_s",
                .@"i32.trunc_sat_f32_u",
                => try val_stack.popThenPushExpecting(scratch, &ctrl_stack, .f32, .i32),
                .@"i32.trunc_sat_f64_s",
                .@"i32.trunc_sat_f64_u",
                => try val_stack.popThenPushExpecting(scratch, &ctrl_stack, .f64, .i32),
                .@"i64.trunc_sat_f32_s",
                .@"i64.trunc_sat_f32_u",
                => try val_stack.popThenPushExpecting(scratch, &ctrl_stack, .f32, .i64),
                .@"i64.trunc_sat_f64_s",
                .@"i64.trunc_sat_f64_u",
                => try val_stack.popThenPushExpecting(scratch, &ctrl_stack, .f64, .i64),
                else => |bad| std.debug.panic("TODO: handle 0xFC {s}\n", .{@tagName(bad)}),
            },
            else => |bad| std.debug.panic("TODO: handle {s} (0x{X:0>2})\n", .{ @tagName(bad), @intFromEnum(bad) }),
        }
    }

    try reader.expectEndOfStream();

    if (ctrl_stack.len != 0)
        return error.MalformedWasm;

    std.debug.assert(val_stack.len() == func_type.result_count);
    std.debug.assert(branch_fixups.active.len == 0);

    state.instructions_end = @ptrCast(state.instructions + instr_offset);
    state.max_values = val_stack.max;
    state.side_table_len = std.math.cast(u32, side_table.len) orelse return error.WasmImplementationLimit;
    state.side_table_ptr = side_table: {
        const copied = try allocator.alloc(SideTableEntry, side_table.len);
        side_table.writeToSlice(copied, 0);
        break :side_table @as([]const SideTableEntry, copied).ptr;
    };

    errdefer comptime unreachable;

    std.debug.assert(state.@"error" == null);
    state.flag.store(State.Flag.successful, .release);
}
