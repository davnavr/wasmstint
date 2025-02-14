//! Implements the WebAssembly [validation algorithm] and side-table generation
//! as described in Ben L. Titzer's ["A fast in-place interpreter for WebAssembly"].
//!
//! `wasmstint` is currently designed to lazily validate functions.
//! For more information, see <https://github.com/WebAssembly/design/issues/1464>.
//!
//! [validation algorithm]: https://webassembly.github.io/spec/core/appendix/algorithm.html
//! ["A fast in-place interpreter for WebAssembly"]: https://doi.org/10.48550/arXiv.2205.01183

const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const ArenaAllocator = std.heap.ArenaAllocator;

const Module = @import("../Module.zig");
const ValType = Module.ValType;
const opcodes = @import("../opcodes.zig");

const validator = @This();

pub const Error = error{InvalidWasm} ||
    Module.ReaderError ||
    Module.LimitError ||
    Allocator.Error;

const DebugSideTableEntry = struct {
    delta_ip: union {
        done: i32,
        /// Offset from the first byte of the first instruction to the first byte of the
        /// branch instruction.
        fixup_origin: u32,
    },
    delta_stp: i16,
    copy_count: u8,
    pop_count: u8,
    /// Set to the same value as `fixup_origin`.
    origin: u32,

    comptime {
        std.debug.assert(@sizeOf(DebugSideTableEntry) == 16);
    }
};

pub const ReleaseSideTableEntry = packed struct(u64) {
    delta_ip: packed union {
        done: i32,
        /// Offset from the first byte of the first instruction to the first byte of the
        /// branch instruction.
        fixup_origin: u32,
    },
    delta_stp: i16,
    copy_count: u8,
    pop_count: u8,
    origin: void = {},
};

pub const Code = extern struct {
    /// Code entries are stored in a separate array, optimizing for the case where `Code`
    /// has already been validated.
    pub const Entry = extern struct {
        /// The contents of the WASM function body, including its local variable declarations.
        ///
        /// The offset is relative to the first byte of the `Module`'s *code* section.
        ///
        /// This field must never be mutated.
        contents: Module.WasmSlice,
    };

    /// A 32-bit integer allows using `std.Thread.Futex` to wait for another thread that is
    /// currently validating the same code.
    pub const Status = enum(u32) {
        not_started = 0,
        in_progress = 1,
        finished = 2,
    };

    pub const End = enum(u8) { end = @intFromEnum(opcodes.ByteOpcode.end) };
    pub const Ip = [*:@intFromEnum(End.end)]const u8;

    /// Describes the changes to interpreter state should occur if its corresponding branch is taken.
    pub const SideTableEntry = if (builtin.mode == .Debug)
        DebugSideTableEntry
    else
        ReleaseSideTableEntry;

    pub const Inner = extern struct {
        instructions_start: Ip,
        instructions_end: *const End,
        side_table_ptr: [*]const SideTableEntry,
        side_table_len: u32,
        /// The maximum amount of space needed in the value stack for executing this function.
        max_values: u16,
        /// The number of local variables, excluding parameters.
        local_values: u16,
    };

    // TODO: See how struct size influences performance (false sharing? cache lines?)
    // - IndexedArena design doesn't allow large alignments required for padding!
    // TODO: Padding can be used to store inline []SideTableEntry
    inner: Inner,
    status: std.atomic.Value(Status) = .{ .raw = .not_started },

    const validation_failed_body = [_:@intFromEnum(End.end)]u8{
        @intFromEnum(opcodes.IllegalOpcode.@"wasmstint.validation_fail"),
    };

    pub const validation_failed = Inner{
        .instructions_start = &validation_failed_body,
        .instructions_end = @ptrCast(&validation_failed_body[validation_failed_body.len]),
        .side_table_ptr = &[0]SideTableEntry{},
        .side_table_len = 0,
        .max_values = 0,
        .local_values = 0,
    };

    pub inline fn isValidationFinished(code: *const Code) bool {
        return code.status.load(.acquire) == Status.finished;
    }

    // pub fn waitForValidation(state: *State, futex_timeout: std.Thread.Futex.Deadline) error{Timeout}!void {

    /// Returns `true` if validation succeeded, `false` if the current thread would block, or an
    /// error if validation failed.
    ///
    /// Callers should first check the status flag before calling this method to determine if
    /// validation has already occurred.
    ///
    /// If `false` is returned, callers can wait for validation on other threads to finish by
    /// waiting for the `status` flag to change.
    ///
    /// Note that due to API limitations, encountering an OOM condition during validation is
    /// treated as a validation failure. Attempting to interpret a function that failed validation
    /// is treated as a trap.
    ///
    /// Asserts that this `Code` belongs to the given `Module`.
    pub fn validate(
        code: *Code,
        allocator: Allocator,
        module: *const Module,
        scratch: *ArenaAllocator,
    ) Error!bool {
        check: {
            const current_flag = code.status.cmpxchgWeak(
                .not_started,
                .in_progress,
                .acq_rel,
                .acquire,
            ) orelse break :check;

            return switch (current_flag) {
                .not_started => unreachable,
                .in_progress => false,
                .finished => true,
            };
        }

        const code_addr = @intFromPtr(code);
        const code_sec_ptr = module.inner.code;
        std.debug.assert(@intFromPtr(code_sec_ptr) <= code_addr);
        std.debug.assert(code_addr < @intFromPtr(code_sec_ptr + module.inner.code_count));

        const func_idx: Module.FuncIdx = @enumFromInt(@as(
            @typeInfo(Module.FuncIdx).@"enum".tag_type,
            @intCast(
                module.inner.func_import_count + @divExact(
                    code_addr - @intFromPtr(code_sec_ptr),
                    @sizeOf(Code),
                ),
            ),
        ));

        defer code.status.store(.finished, .release);
        const result = rawValidate(
            allocator,
            module,
            module.funcTypeIdx(func_idx),
            module.codeEntries()[@intFromEnum(func_idx)].contents
                .slice(module.inner.code_section, module.wasm),
            scratch,
        );

        code.inner = result catch validation_failed;
        _ = result catch |err| return err;
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
        .is_exhaustive = true,
    },
});

fn isNumVal(val: Val) bool {
    return switch (val) {
        .i32, .i64, .f32, .f64, .unknown => true,
        .funcref, .externref, .v128 => false,
    };
}

inline fn isVecVal(val: Val) bool {
    return val == .unknown or val == .v128;
}

inline fn isRefVal(val: Val) bool {
    return switch (val) {
        .funcref, .externref, .unknown => true,
        .i32, .i64, .f32, .f64, .v128 => false,
    };
}

inline fn valTypeToVal(val_type: ValType) Val {
    comptime {
        for (@typeInfo(ValType).@"enum".fields) |field| {
            std.debug.assert(
                @intFromEnum(@field(Val, field.name)) ==
                    @intFromEnum(@field(ValType, field.name)),
            );
        }
    }

    return @enumFromInt(@intFromEnum(val_type));
}

const ValBuf = std.SegmentedList(Val, 128);

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
                return if (!@"type".results_only) copied else .{
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
        height: u16,
        opcode: Opcode,
        @"unreachable": bool = false,
    },
    /// Offset from the first byte of the first instruction to the first byte of the block's `opcode`.
    offset: u32,
    /// The length of the side table when the block was entered.
    side_table_idx: u32,

    const Opcode = enum(u15) {
        block,
        loop,
        @"if",
        @"else",
        //@"try",
        //@"catch",
    };

    fn labelTypes(frame: *const CtrlFrame, module: *const Module) []const ValType {
        const types = frame.types.funcType(module);
        return if (frame.info.opcode != .loop) types.results() else types.parameters();
    }
};

const CtrlStack = std.SegmentedList(CtrlFrame, 16);

const ValStack = struct {
    buf: ValBuf,
    max: u16 = 0,

    inline fn len(val_stack: *const ValStack) u16 {
        return @intCast(val_stack.buf.len);
    }

    fn pushAny(val_stack: *ValStack, arena: *ArenaAllocator, val: Val) Error!void {
        try val_stack.buf.append(arena.allocator(), val);
        // Note, if someone pushes a known value over an unknown, the max will grow anyway
        // TODO: check that current frame is reachable instead.
        // if (val != .unknown) {
        val_stack.max = @max(val_stack.max, std.math.cast(u16, val_stack.buf.len) orelse
            return Error.WasmImplementationLimit);
        // }
    }

    fn push(val_stack: *ValStack, arena: *ArenaAllocator, val_type: ValType) Error!void {
        return val_stack.pushAny(arena, valTypeToVal(val_type));
    }

    /// Asserts that `types.len() <= std.math.maxInt(u16)`.
    fn pushMany(val_stack: *ValStack, arena: *ArenaAllocator, types: []const ValType) Error!void {
        const new_len = std.math.add(u16, val_stack.len(), @intCast(types.len)) catch
            return Error.WasmImplementationLimit;

        if (new_len > ValBuf.prealloc_count) {
            try val_stack.buf.growCapacity(arena.allocator(), new_len);
        }

        for (types) |ty| {
            val_stack.buf.append(undefined, valTypeToVal(ty)) catch unreachable;
        }

        // TODO: check that current frame is reachable instead.
        val_stack.max = @max(new_len, val_stack.max);
    }

    fn popAny(val_stack: *ValStack, ctrl_stack: *const CtrlStack) Error!Val {
        const current_frame: *const CtrlFrame = ctrl_stack.at(ctrl_stack.len - 1);
        if (val_stack.len() == current_frame.info.height) {
            return if (current_frame.info.@"unreachable") Val.unknown else Error.InvalidWasm;
        }

        return val_stack.buf.pop().?;
    }

    fn popExpecting(val_stack: *ValStack, ctrl_stack: *const CtrlStack, expected: ValType) Error!void {
        const popped = try val_stack.popAny(ctrl_stack);
        // std.debug.print("wanted {}, got {}\n", .{ expected, popped });
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
            const top: *Val = val_stack.buf.at(val_stack.len() - 1);

            if (top.* != valTypeToVal(expected) and top.* != .unknown)
                return Error.InvalidWasm;

            top.* = valTypeToVal(replacement);
        } else if (current_frame.info.@"unreachable") {
            return val_stack.push(arena, replacement);
        } else {
            return Error.InvalidWasm;
        }
    }

    fn popManyExpecting(val_stack: *ValStack, ctrl_stack: *const CtrlStack, expected: []const ValType) Error!void {
        // std.debug.print("current height = {}, want to pop = {any}\n", .{ val_stack.len(), expected });
        for (0..expected.len) |i| {
            try val_stack.popExpecting(ctrl_stack, expected[expected.len - 1 - i]);
        }
    }

    /// Used to preserve `.unknown` stack values when popping and pushing the same types.
    fn popThenPushManyExpecting(
        val_stack: *ValStack,
        ctrl_stack: *const CtrlStack,
        expected: []const ValType,
    ) Error!void {
        const current_frame: *const CtrlFrame = ctrl_stack.at(ctrl_stack.len - 1);
        for (0..expected.len) |i| {
            const expected_type = valTypeToVal(expected[expected.len - 1 - i]);
            const current_height = val_stack.len() - i;
            const actual_type: Val = if (current_height == current_frame.info.height)
                if (current_frame.info.@"unreachable")
                    Val.unknown
                else
                    return Error.InvalidWasm
            else
                val_stack.buf.at(current_height - 1).*;

            if (actual_type != expected_type and actual_type != .unknown)
                return Error.InvalidWasm;
        }
    }
};

fn readMemIdx(reader: *Module.Reader, module: *const Module) Error!void {
    if (module.inner.mem_count == 0) return Error.InvalidWasm;
    const idx = try reader.readUleb128(u32);
    if (idx != 0) return Error.InvalidWasm;
}

fn readMemArg(
    reader: *Module.Reader,
    natural_alignment: u3,
    module: *const Module,
) Error!void {
    const a = try reader.readUleb128(u32);

    if (a > natural_alignment) return Error.InvalidWasm;
    if (module.inner.mem_count == 0) return Error.InvalidWasm;

    _ = try reader.readUleb128(u32); // offset
}

fn readTableIdx(reader: *Module.Reader, module: *const Module) Error!ValType {
    const idx = try reader.readUleb128(u32);
    return if (idx < module.tableTypes().len)
        module.tableTypes()[idx].elem_type
    else
        Error.InvalidWasm;
}

fn readDataIdx(reader: *Module.Reader, module: *const Module) Error!void {
    if (!module.inner.has_data_count_section) return Error.InvalidWasm;
    const idx = try reader.readUleb128(u32);
    if (idx >= module.inner.datas_count) return Error.InvalidWasm;
}

fn readElemIdx(reader: *Module.Reader, module: *const Module) Error!ValType {
    const idx = try reader.readUleb128(u32);
    return if (idx < module.elementSegments().len)
        module.elementSegments()[idx].elementType()
    else
        Error.InvalidWasm;
}

fn readLocalIdx(reader: *Module.Reader, locals: []const ValType) Error!ValType {
    const idx = try reader.readUleb128(u32);
    return if (idx < locals.len) locals[idx] else Error.InvalidWasm;
}

const Label = struct {
    frame: *const CtrlFrame,
    depth: u32,
    copy_count: u8,
    pop_count: u8,

    fn calculatePopCount(
        current_height: u16,
        target_frame_height: u16,
    ) Module.LimitError!u8 {
        return std.math.cast(u8, current_height - target_frame_height) orelse
            Error.WasmImplementationLimit;
    }

    fn init(depth: u32, ctrl_stack: *const CtrlStack, current_height: u16, module: *const Module) Error!Label {
        const frame: *const CtrlFrame = if (depth < ctrl_stack.len)
            ctrl_stack.at(ctrl_stack.len - 1 - depth)
        else
            return Error.InvalidWasm;

        // std.debug.print(
        //     " ? label at depth {} targets 0x{X} ({s})\n",
        //     .{ depth, frame.offset, @tagName(frame.info.opcode) },
        // );

        return Label{
            .frame = frame,
            .depth = depth,
            .copy_count = std.math.cast(u8, frame.labelTypes(module).len) orelse
                return Error.WasmImplementationLimit,
            .pop_count = try calculatePopCount(current_height, frame.info.height),
        };
    }

    fn read(
        reader: *Module.Reader,
        ctrl_stack: *const CtrlStack,
        current_height: u16,
        module: *const Module,
    ) Error!Label {
        const depth = try reader.readUleb128(u32);
        return Label.init(depth, ctrl_stack, current_height, module);
    }
};

//fn readDataIdx(module: *const Module) // TODO: Check data count sec value

fn pushCtrlFrame(
    arena: *ArenaAllocator,
    ctrl_stack: *CtrlStack,
    val_stack: *ValStack,
    side_table: *const SideTableBuilder,
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
                .height = val_stack.len(),
            },
            .offset = offset,
            .side_table_idx = try side_table.nextEntryIdx(),
        },
    );

    // std.debug.print("pushed {s} parameters = {any}\n", .{ @tagName(opcode), block_type.funcType(module).parameters() });
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

const BranchFixup = packed struct(u32) {
    entry_idx: u32,

    const List = extern struct {
        const Header = extern struct {
            prev: List,
            /// The number of entries in this list.
            len: u32,
            capacity: u32,

            const empty = Header{
                // Zig doesn't like `List.empty` here, "dependency loop detected"
                .prev = List{ .header = @constCast(&empty_fallback) },
                .len = 0,
                .capacity = 0,
            };

            const empty_fallback = Header{
                .prev = undefined,
                .len = 0,
                .capacity = 0,
            };
        };

        header: *Header,

        const header_size_in_elems = @divExact(@sizeOf(Header), @sizeOf(BranchFixup));

        const empty = List{ .header = @constCast(&Header.empty) };

        fn allocatedHeaderAndEntries(list: List) []align(@alignOf(Header)) BranchFixup {
            const base: [*]align(@alignOf(Header)) BranchFixup = @ptrCast(list.header);
            return base[0 .. header_size_in_elems + list.header.capacity];
        }

        inline fn allocatedEntries(list: List) []BranchFixup {
            std.debug.assert(list.header.len <= list.header.capacity);
            return list.allocatedHeaderAndEntries()[header_size_in_elems..];
        }

        inline fn entries(list: List) []BranchFixup {
            return list.allocatedEntries()[0..list.header.len];
        }

        fn append(list: *List, arena: *ArenaAllocator, fixup: BranchFixup) Allocator.Error!void {
            if (list.header.len == list.header.capacity) {
                @branchHint(.unlikely);

                const new_capacity: u32 = if (list.header.capacity == 0)
                    4
                else
                    std.math.mul(u32, @intCast(list.header.capacity), 2) catch
                        return error.OutOfMemory;

                const new_alloc_len = std.math.add(
                    usize,
                    header_size_in_elems,
                    new_capacity,
                ) catch return error.OutOfMemory;

                const old_alloc = list.allocatedHeaderAndEntries();
                std.debug.assert(old_alloc.len < new_alloc_len);
                if (list.header.capacity > 0 and arena.allocator().resize(old_alloc, new_alloc_len)) {
                    std.debug.assert(@intFromPtr(list.header) != @intFromPtr(List.empty.header));
                    list.header.capacity = new_capacity;
                } else {
                    // TODO: Reuse freed lists
                    @branchHint(.likely);
                    const new_alloc: []align(@alignOf(Header)) BranchFixup = try arena.allocator().alignedAlloc(
                        BranchFixup,
                        @alignOf(Header),
                        std.math.add(
                            usize,
                            header_size_in_elems,
                            new_capacity,
                        ) catch return error.OutOfMemory,
                    );

                    errdefer comptime unreachable;

                    const old_list: List = list.*;
                    const new_header: *Header = @ptrCast(new_alloc[0..header_size_in_elems]);
                    new_header.* = Header{
                        .prev = old_list,
                        .len = 0,
                        .capacity = new_capacity,
                    };

                    list.* = List{ .header = new_header };
                }

                @memset(list.allocatedEntries()[list.header.len..], undefined);
            }

            std.debug.assert(list.header.len <= list.header.capacity);

            const i = list.header.len;
            list.header.len = std.math.add(u32, i, 1) catch return error.OutOfMemory;
            list.entries()[i] = fixup;

            std.debug.assert(list.header.len <= list.header.capacity);
        }
    };
};

const SideTableBuilder = struct {
    const Entry = Code.SideTableEntry;
    const Entries = std.SegmentedList(Entry, 4);

    const ActiveList = struct {
        block_offset: BlockOffset,
        fixups: BranchFixup.List,

        const BlockOffset = if (builtin.mode == .Debug) u32 else void;
    };

    /// The contents of the side table, which contain branch targets inserted in increasing
    /// origin offset order.
    entries: Entries = .{},
    /// Maps pending fixups to each frame in the WebAssembly validation control stack.
    ///
    /// Since `loop`s never need fixups, they only push empty lists.
    active: std.SegmentedList(ActiveList, 4) = .{},
    /// Separate stack used to fixup branches in `if`/`else` blocks.
    alternate: std.SegmentedList(BranchFixup, 4) = .{},
    free: BranchFixup.List = BranchFixup.List.empty,

    fn nextEntryIdx(table: *const SideTableBuilder) Module.LimitError!u32 {
        return std.math.cast(u32, table.entries.len) orelse return error.WasmImplementationLimit;
    }

    fn pushFixupList(
        table: *SideTableBuilder,
        arena: *ArenaAllocator,
        block_offset: ActiveList.BlockOffset,
        allocation: enum { reuse, empty },
    ) Allocator.Error!void {
        const fixups = if (allocation == .reuse and table.free.header.capacity > 0) reused: {
            const used = table.free;
            std.debug.assert(used.header.capacity > 0);
            table.free = used.header.prev;
            std.debug.assert(@intFromPtr(used.header) != @intFromPtr(table.free.header));
            used.header.prev = BranchFixup.List.empty;
            break :reused used;
        } else BranchFixup.List.empty;

        std.debug.assert(fixups.header.len == 0);
        std.debug.assert(fixups.header.prev.header.capacity == 0);
        std.debug.assert(@intFromPtr(fixups.header) != @intFromPtr(&BranchFixup.List.Header.empty_fallback));

        try table.active.append(
            arena.allocator(),
            ActiveList{
                .block_offset = block_offset,
                .fixups = fixups,
            },
        );
    }

    fn appendAlternate(
        table: *SideTableBuilder,
        arena: *ArenaAllocator,
        origin: u32,
        copy_count: u8,
        pop_count: u8,
    ) (Module.LimitError || Allocator.Error)!void {
        const idx = try table.nextEntryIdx();
        const entry = try table.entries.addOne(arena.allocator());
        const fixup = try table.alternate.addOne(arena.allocator());

        fixup.* = .{ .entry_idx = idx };
        entry.* = Entry{
            .delta_ip = .{ .fixup_origin = origin },
            .delta_stp = undefined,
            .copy_count = copy_count,
            .pop_count = pop_count,
            .origin = if (builtin.mode == .Debug) origin else {},
        };

        // std.debug.print(" PLACED ALT FIXUP #{} originating from 0x{X}\n", .{ idx, origin });
    }

    const KnownTarget = struct {
        instr_offset: u32,
        side_table_idx: u32,
    };

    fn append(
        table: *SideTableBuilder,
        arena: *ArenaAllocator,
        origin: u32,
        known_target: ?KnownTarget,
        copy_count: u8,
        pop_count: u8,
        block_offset: ActiveList.BlockOffset,
        target_depth: u32,
    ) (Module.LimitError || Allocator.Error)!u32 {
        const idx = try table.nextEntryIdx();
        const entry = try table.entries.addOne(arena.allocator());
        entry.copy_count = copy_count;
        entry.pop_count = pop_count;
        entry.origin = if (builtin.mode == .Debug) origin else {};

        if (known_target) |target| {
            const delta_ip = std.math.negateCast(origin - target.instr_offset) catch
                return Error.WasmImplementationLimit;

            entry.delta_ip = .{ .done = delta_ip };

            const delta_stp = std.math.negateCast(idx - target.side_table_idx) catch
                return Error.WasmImplementationLimit;

            entry.delta_stp = std.math.cast(i16, delta_stp) orelse
                return Error.WasmImplementationLimit;
        } else {
            // std.debug.print(
            //     " PLACED FIXUP #{} originating from 0x{X} corresponding to block 0x{X} (copy={}, pop={})\n",
            //     .{ idx, origin, block_offset, copy_count, pop_count },
            // );

            entry.delta_ip = .{ .fixup_origin = origin };
            entry.delta_stp = undefined;

            const current_list: *ActiveList = table.active.at(table.active.len - 1 - target_depth);
            std.debug.assert(current_list.block_offset == block_offset);
            try current_list.fixups.append(arena, .{ .entry_idx = idx });
        }

        return idx;
    }

    fn resolveFixupEntry(
        table: *SideTableBuilder,
        fixup_entry: *const BranchFixup,
        target_side_table_idx: u32,
        end_offset: u32,
    ) Module.LimitError!void {
        const entry: *Entry = table.entries.at(fixup_entry.entry_idx);
        const origin = entry.delta_ip.fixup_origin;

        entry.delta_ip = .{
            .done = std.math.cast(i32, end_offset - origin) orelse
                return error.WasmImplementationLimit,
        };

        entry.delta_stp = std.math.cast(i16, target_side_table_idx - fixup_entry.entry_idx) orelse
            return error.WasmImplementationLimit;

        // std.debug.print(
        //     "FIXUP #{} targeting 0x{X} originating from 0x{X} (dip = {}, dstp = {}, target STP={})\n",
        //     .{
        //         fixup_entry.entry_idx,
        //         end_offset,
        //         origin,
        //         entry.delta_ip.done,
        //         entry.delta_stp,
        //         target_side_table_idx,
        //     },
        // );
    }

    /// Asserts that all of the branch fixup entries correspond to branches
    /// that are placed before `end_offset`.
    fn popAndResolveFixups(
        table: *SideTableBuilder,
        end_offset: u32,
        block_offset: ActiveList.BlockOffset,
    ) Module.LimitError!void {
        const target_side_table_idx = try table.nextEntryIdx();

        // std.debug.print(
        //     "RESOLVING FIXUPS targeting 0x{X} (introduced by 0x{X})\n",
        //     .{ end_offset, block_offset },
        // );

        const popped: ActiveList = table.active.pop().?;
        std.debug.assert(block_offset == popped.block_offset);

        const popped_header = popped.fixups.header;
        if (table.active.len > 0 and popped_header.capacity > 0) {
            const other: *ActiveList = table.active.at(table.active.len - 1);
            const other_header = other.fixups.header;
            if (@intFromPtr(popped_header) == @intFromPtr(other_header)) {
                if (builtin.mode != .Debug) unreachable;

                std.debug.panic(
                    "fixup list targeting 0x{X} {*} (len={}, cap={}) mustn't be the same " ++
                        "as list targeting 0x{X} {*} (len={}, cap={})",
                    .{
                        block_offset,       popped_header, popped_header.len, popped_header.capacity,
                        other.block_offset, other_header,  other_header.len,  other_header.capacity,
                    },
                );
            }
        }

        var remaining = popped.fixups;
        while (remaining.header.len > 0) {
            for (remaining.entries()) |*fixup_entry| {
                try table.resolveFixupEntry(
                    fixup_entry,
                    target_side_table_idx,
                    end_offset,
                );
            }

            const old_free = table.free;
            table.free = remaining;
            remaining = remaining.header.prev;

            table.free.header.len = 0;
            table.free.header.prev = old_free;
            @memset(table.free.allocatedEntries(), undefined);
        }
    }

    fn popAndResolveAlternate(
        table: *SideTableBuilder,
        end_offset: u32,
    ) Module.LimitError!void {
        const target_side_table_idx = try table.nextEntryIdx();
        const fixup: *const BranchFixup = table.alternate.at(table.alternate.len - 1);
        defer _ = table.alternate.pop();
        try table.resolveFixupEntry(
            fixup,
            target_side_table_idx,
            end_offset,
        );
    }
};

fn appendSideTableEntry(
    arena: *ArenaAllocator,
    side_table: *SideTableBuilder,
    origin_offset: u32,
    target: Label,
) Error!void {
    const loop_target = target.frame.info.opcode == .loop;
    // if (loop_target)
    //     std.debug.print("BRNCH targeting 0x{X} (loop) originating from 0x{X}\n", .{ target.frame.offset, origin_offset });

    // TODO: Fix, this needs to specify in which list it wants to append the fixup!
    _ = try side_table.append(
        arena,
        origin_offset,
        if (loop_target)
            .{
                // TODO: Can do +1 to go straight to loop body.
                .instr_offset = target.frame.offset,
                .side_table_idx = target.frame.side_table_idx,
            }
        else
            null,
        target.copy_count,
        target.pop_count,
        if (builtin.mode == .Debug) target.frame.offset,
        target.depth,
    );
}

fn validateLoadInstr(
    reader: *Module.Reader,
    val_stack: *ValStack,
    ctrl_stack: *const CtrlStack,
    natural_alignment: u3,
    loaded: ValType,
    module: *const Module,
    arena: *ArenaAllocator,
) Error!void {
    // Pop index, push loaded value.
    try val_stack.popThenPushExpecting(arena, ctrl_stack, .i32, loaded);
    try readMemArg(reader, natural_alignment, module);
}

fn validateStoreInstr(
    reader: *Module.Reader,
    val_stack: *ValStack,
    ctrl_stack: *const CtrlStack,
    natural_alignment: u3,
    stored: ValType,
    module: *const Module,
) Error!void {
    try val_stack.popManyExpecting(ctrl_stack, &[_]ValType{ .i32, stored });
    try readMemArg(reader, natural_alignment, module);
}

pub fn rawValidate(
    allocator: Allocator,
    module: *const Module,
    signature: Module.TypeIdx,
    code: []const u8,
    scratch: *ArenaAllocator,
    // diagnostics: ?*ValidationDiagnostics,
) Error!Code.Inner {
    _ = scratch.reset(.retain_capacity);

    var code_ptr = code;
    var reader = Module.Reader.init(&code_ptr);

    const func_type = signature.funcType(module);

    var val_stack: ValStack = undefined;
    const locals: struct { types: []const ValType, count: u16 } = locals: {
        const local_group_count = try reader.readUleb128(u32);
        var local_vars = ValBuf{};

        const reserve_count = std.math.add(u32, func_type.param_count, local_group_count) catch
            return error.OutOfMemory;

        // if (local_group_count > Valbuf.prealloc_count) {
        try local_vars.setCapacity(scratch.allocator(), reserve_count);
        // }

        defer {
            local_vars.clearRetainingCapacity();
            val_stack = ValStack{ .buf = local_vars };
        }

        local_vars.appendSlice(
            undefined,
            @ptrCast(func_type.parameters()),
        ) catch unreachable;

        for (0..local_group_count) |_| {
            const local_count = try reader.readUleb128(u32);
            const local_type = try reader.readValType();
            const new_local_len = std.math.add(u32, @intCast(local_vars.len), local_count) catch
                return error.WasmImplementationLimit;

            if (new_local_len > ValBuf.prealloc_count) {
                try local_vars.growCapacity(scratch.allocator(), new_local_len);
            }

            for (0..local_count) |_| {
                local_vars.append(undefined, valTypeToVal(local_type)) catch unreachable;
            }
        }

        const count: u16 = @intCast(local_vars.len - func_type.param_count);

        const buf = try scratch.allocator().alloc(ValType, local_vars.len);
        local_vars.writeToSlice(@ptrCast(buf), 0);
        break :locals .{ .types = buf, .count = count };
    };

    var side_table = SideTableBuilder{};
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

    side_table.pushFixupList(
        scratch,
        if (builtin.mode == .Debug) 0,
        .reuse,
    ) catch unreachable;

    const instructions: Code.Ip = @ptrCast(reader.bytes.ptr);

    var per_instr_arena = ArenaAllocator.init(scratch.allocator());

    var instr_offset: u32 = 0;
    while (ctrl_stack.len > 0) {
        _ = per_instr_arena.reset(.retain_capacity);

        // Offset from the first byte of the first instruction to the first byte of the instruction being parsed.
        instr_offset = @intCast(@intFromPtr(reader.bytes.ptr) - @intFromPtr(instructions));

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
                try side_table.pushFixupList(
                    scratch,
                    if (builtin.mode == .Debug) instr_offset,
                    .reuse,
                );
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

                // Destination of a branch to a loop is already known, so an empty fixup list is appended.
                // An entry is required anyway to keep the mapping from WASM label depths to fixup lists.
                try side_table.pushFixupList(
                    scratch,
                    if (builtin.mode == .Debug) instr_offset,
                    .empty,
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
                try side_table.appendAlternate( // going to `else` or `end`
                    scratch,
                    instr_offset,
                    0,
                    0,
                );

                try side_table.pushFixupList(
                    scratch,
                    if (builtin.mode == .Debug) instr_offset,
                    .reuse,
                ); // going to 'end'
            },
            .@"else" => {
                const current_height = val_stack.len();

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

                // going to 'end'
                const block_type = frame.types.funcType(module);
                _ = try side_table.append(
                    scratch,
                    instr_offset,
                    null,
                    std.math.cast(u8, block_type.result_count) orelse
                        return error.WasmImplementationLimit,
                    try Label.calculatePopCount(current_height, frame.info.height),
                    if (builtin.mode == .Debug) frame.offset,
                    0,
                );

                // Interpreter's `else` handler jumps to the `end`, so failing branch in `if` should be redirected to `else` body.
                try side_table.popAndResolveAlternate(instr_offset + 1);

                if (builtin.mode == .Debug)
                    side_table.active.at(side_table.active.len - 1).block_offset = instr_offset;
            },
            .end => {
                const frame = try popCtrlFrame(&ctrl_stack, &val_stack, module);

                // TODO: Skip branch fixup processing for unreachable code.

                const current_list = side_table.active.at(side_table.active.len - 1);
                if (builtin.mode == .Debug) {
                    std.debug.assert(frame.offset == current_list.block_offset);
                }

                if (frame.info.opcode == .loop) {
                    std.debug.assert(current_list.fixups.header.capacity == 0);
                }

                // Possible optimization, target the instruction after the branch only if this is not the last `end` instruction
                // - This would mess up the Interpreter's fuel counting.
                try side_table.popAndResolveFixups(
                    instr_offset,
                    if (builtin.mode == .Debug) frame.offset,
                );

                if (frame.info.opcode == .@"if") {
                    try side_table.popAndResolveAlternate(instr_offset);
                }

                try val_stack.pushMany(scratch, frame.types.funcType(module).results());
            },
            .br => {
                const label = try Label.read(
                    &reader,
                    &ctrl_stack,
                    val_stack.len(),
                    module,
                );

                // TODO: Skip branch fixup processing for unreachable code.
                try appendSideTableEntry(scratch, &side_table, instr_offset, label);

                try val_stack.popManyExpecting(&ctrl_stack, label.frame.labelTypes(module));
                markUnreachable(&val_stack, &ctrl_stack);
            },
            .br_if => {
                try val_stack.popExpecting(&ctrl_stack, .i32);

                const label = try Label.read(
                    &reader,
                    &ctrl_stack,
                    val_stack.len(),
                    module,
                );

                // TODO: Skip branch fixup processing for unreachable code.
                try appendSideTableEntry(scratch, &side_table, instr_offset, label);

                try val_stack.popThenPushManyExpecting(
                    &ctrl_stack,
                    label.frame.labelTypes(module),
                );
            },
            .br_table => {
                try val_stack.popExpecting(&ctrl_stack, .i32);

                const current_height = val_stack.len();

                const label_count = try reader.readUleb128(u32);
                const labels = try per_instr_arena.allocator().alloc(u32, label_count);

                // Reserve space for the new side table entries.
                {
                    const grow_side_table = std.math.add(
                        usize,
                        std.math.add(usize, 1, labels.len) catch
                            return error.OutOfMemory,
                        side_table.entries.len,
                    ) catch return error.OutOfMemory;

                    if (grow_side_table > SideTableBuilder.Entries.prealloc_count)
                        try side_table.entries.growCapacity(scratch.allocator(), grow_side_table);
                }

                // Validation bases the "arity" on the default branch, so all labels must be parsed to get to the
                // default label.
                for (labels) |*n| n.* = try reader.readUleb128(u32);

                // TODO: Skip branch fixup processing for unreachable code.
                const last_label = try Label.read(
                    &reader,
                    &ctrl_stack,
                    current_height,
                    module,
                );

                const last_label_types = last_label.frame.labelTypes(module);
                const arity: u32 = @intCast(last_label_types.len);

                // std.debug.print("BEGIN BR_TABLE\n", .{});

                for (labels) |n| {
                    const l = try Label.init(
                        n,
                        &ctrl_stack,
                        current_height,
                        module,
                    );

                    try appendSideTableEntry(scratch, &side_table, instr_offset, l);

                    const l_types = l.frame.labelTypes(module);
                    if (l_types.len != arity) return error.InvalidWasm;

                    try val_stack.popThenPushManyExpecting(&ctrl_stack, l_types);
                }

                try appendSideTableEntry(scratch, &side_table, instr_offset, last_label);

                // std.debug.print("END BR_TABLE\n", .{});

                try val_stack.popManyExpecting(&ctrl_stack, last_label_types);
                markUnreachable(&val_stack, &ctrl_stack);
            },
            .@"return" => {
                try val_stack.popManyExpecting(&ctrl_stack, func_type.results());
                markUnreachable(&val_stack, &ctrl_stack);
            },
            .call => {
                const callee = try reader.readIdx(Module.FuncIdx, module.funcTypes().len);
                const callee_signature = module.funcTypes()[@intFromEnum(callee)];

                try val_stack.popManyExpecting(&ctrl_stack, callee_signature.parameters());
                try val_stack.pushMany(scratch, callee_signature.results());
            },
            .call_indirect => {
                const type_idx = try reader.readUleb128Casted(
                    u32,
                    @typeInfo(Module.TypeIdx).@"enum".tag_type,
                );

                const callee_signature: *const Module.FuncType = if (type_idx < module.types().len)
                    &module.types()[type_idx]
                else
                    return error.InvalidWasm;

                // std.debug.print(
                //     "CHECK call_indirect ({}) {any} -> {any}\n",
                //     .{ type_idx, callee_signature.parameters(), callee_signature.results() },
                // );

                const table_idx = try reader.readUleb128Casted(
                    u32,
                    @typeInfo(Module.TableIdx).@"enum".tag_type,
                );

                const table_type: *const Module.TableType = if (table_idx < module.tableTypes().len)
                    &module.tableTypes()[table_idx]
                else
                    return error.InvalidWasm;

                if (table_type.elem_type != .funcref)
                    return error.InvalidWasm;

                try val_stack.popExpecting(&ctrl_stack, .i32);
                try val_stack.popManyExpecting(&ctrl_stack, callee_signature.parameters());
                try val_stack.pushMany(scratch, callee_signature.results());
            },

            .drop => _ = try val_stack.popAny(&ctrl_stack),
            .select => {
                try val_stack.popExpecting(&ctrl_stack, .i32);
                const t_1: Val = try val_stack.popAny(&ctrl_stack);
                const t_2: Val = try val_stack.popAny(&ctrl_stack);

                const both_num_types = isNumVal(t_1) and isNumVal(t_2);
                const both_vec_types = isVecVal(t_1) and isVecVal(t_2);
                if (!(both_num_types or both_vec_types))
                    return error.InvalidWasm;

                if (t_1 != t_2 and t_1 != .unknown and t_2 != .unknown)
                    return error.InvalidWasm;

                val_stack.pushAny(
                    undefined,
                    if (t_1 == .unknown) t_2 else t_1,
                ) catch unreachable;
            },

            .@"local.get" => {
                const local_type = try readLocalIdx(&reader, locals.types);
                try val_stack.push(scratch, local_type);
            },
            .@"local.set" => {
                const local_type = try readLocalIdx(&reader, locals.types);
                try val_stack.popExpecting(&ctrl_stack, local_type);
            },
            .@"local.tee" => {
                const local_type = try readLocalIdx(&reader, locals.types);
                try val_stack.popThenPushExpecting(scratch, &ctrl_stack, local_type, local_type);
            },
            .@"global.get" => {
                const global_idx = try reader.readUleb128Casted(
                    u32,
                    @typeInfo(Module.GlobalIdx).@"enum".tag_type,
                );

                try val_stack.push(
                    scratch,
                    if (global_idx < module.globalTypes().len)
                        module.globalTypes()[global_idx].val_type
                    else
                        return error.InvalidWasm,
                );
            },
            .@"global.set" => {
                const global_idx = try reader.readUleb128Casted(
                    u32,
                    @typeInfo(Module.GlobalIdx).@"enum".tag_type,
                );

                const global_type: *const Module.GlobalType = if (global_idx < module.globalTypes().len)
                    &module.globalTypes()[global_idx]
                else
                    return error.InvalidWasm;

                if (global_type.mut != .@"var") return error.InvalidWasm;

                try val_stack.popExpecting(&ctrl_stack, global_type.val_type);
            },

            .@"table.get" => {
                const table_type = try readTableIdx(&reader, module);
                try val_stack.popThenPushExpecting(
                    scratch,
                    &ctrl_stack,
                    .i32,
                    table_type,
                );
            },
            .@"table.set" => {
                const table_type = try readTableIdx(&reader, module);
                try val_stack.popManyExpecting(
                    &ctrl_stack,
                    &[_]ValType{ .i32, table_type },
                );
            },

            .@"i32.load" => try validateLoadInstr(
                &reader,
                &val_stack,
                &ctrl_stack,
                std.math.log2(4),
                .i32,
                module,
                scratch,
            ),
            .@"i64.load" => try validateLoadInstr(
                &reader,
                &val_stack,
                &ctrl_stack,
                std.math.log2(8),
                .i64,
                module,
                scratch,
            ),
            .@"f32.load" => try validateLoadInstr(
                &reader,
                &val_stack,
                &ctrl_stack,
                std.math.log2(4),
                .f32,
                module,
                scratch,
            ),
            .@"f64.load" => try validateLoadInstr(
                &reader,
                &val_stack,
                &ctrl_stack,
                std.math.log2(8),
                .f64,
                module,
                scratch,
            ),
            .@"i32.load8_s", .@"i32.load8_u" => try validateLoadInstr(
                &reader,
                &val_stack,
                &ctrl_stack,
                std.math.log2(1),
                .i32,
                module,
                scratch,
            ),
            .@"i32.load16_s", .@"i32.load16_u" => try validateLoadInstr(
                &reader,
                &val_stack,
                &ctrl_stack,
                std.math.log2(2),
                .i32,
                module,
                scratch,
            ),
            .@"i64.load8_s", .@"i64.load8_u" => try validateLoadInstr(
                &reader,
                &val_stack,
                &ctrl_stack,
                std.math.log2(1),
                .i64,
                module,
                scratch,
            ),
            .@"i64.load16_s", .@"i64.load16_u" => try validateLoadInstr(
                &reader,
                &val_stack,
                &ctrl_stack,
                std.math.log2(2),
                .i64,
                module,
                scratch,
            ),
            .@"i64.load32_s", .@"i64.load32_u" => try validateLoadInstr(
                &reader,
                &val_stack,
                &ctrl_stack,
                std.math.log2(4),
                .i64,
                module,
                scratch,
            ),
            .@"i32.store" => try validateStoreInstr(
                &reader,
                &val_stack,
                &ctrl_stack,
                std.math.log2(4),
                .i32,
                module,
            ),
            .@"i64.store" => try validateStoreInstr(
                &reader,
                &val_stack,
                &ctrl_stack,
                std.math.log2(8),
                .i64,
                module,
            ),
            .@"f32.store" => try validateStoreInstr(
                &reader,
                &val_stack,
                &ctrl_stack,
                std.math.log2(4),
                .f32,
                module,
            ),
            .@"f64.store" => try validateStoreInstr(
                &reader,
                &val_stack,
                &ctrl_stack,
                std.math.log2(8),
                .f64,
                module,
            ),
            .@"i32.store8" => try validateStoreInstr(
                &reader,
                &val_stack,
                &ctrl_stack,
                std.math.log2(1),
                .i32,
                module,
            ),
            .@"i32.store16" => try validateStoreInstr(
                &reader,
                &val_stack,
                &ctrl_stack,
                std.math.log2(2),
                .i32,
                module,
            ),
            .@"i64.store8" => try validateStoreInstr(
                &reader,
                &val_stack,
                &ctrl_stack,
                std.math.log2(1),
                .i64,
                module,
            ),
            .@"i64.store16" => try validateStoreInstr(
                &reader,
                &val_stack,
                &ctrl_stack,
                std.math.log2(2),
                .i64,
                module,
            ),
            .@"i64.store32" => try validateStoreInstr(
                &reader,
                &val_stack,
                &ctrl_stack,
                std.math.log2(4),
                .i64,
                module,
            ),
            .@"memory.size" => {
                try readMemIdx(&reader, module);
                try val_stack.push(scratch, .i32);
            },
            .@"memory.grow" => {
                try readMemIdx(&reader, module);
                try val_stack.popThenPushExpecting(scratch, &ctrl_stack, .i32, .i32);
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
            .@"i64.eqz",
            .@"i32.wrap_i64",
            => try val_stack.popThenPushExpecting(scratch, &ctrl_stack, .i64, .i32),
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
            .@"f32.eq",
            .@"f32.ne",
            .@"f32.lt",
            .@"f32.gt",
            .@"f32.le",
            .@"f32.ge",
            => {
                try val_stack.popExpecting(&ctrl_stack, .f32);
                try val_stack.popThenPushExpecting(scratch, &ctrl_stack, .f32, .i32);
            },
            .@"f64.eq",
            .@"f64.ne",
            .@"f64.lt",
            .@"f64.gt",
            .@"f64.le",
            .@"f64.ge",
            => {
                try val_stack.popExpecting(&ctrl_stack, .f64);
                try val_stack.popThenPushExpecting(scratch, &ctrl_stack, .f64, .i32);
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
            .@"f32.abs",
            .@"f32.neg",
            .@"f32.ceil",
            .@"f32.floor",
            .@"f32.trunc",
            .@"f32.nearest",
            .@"f32.sqrt",
            => try val_stack.popThenPushExpecting(scratch, &ctrl_stack, .f32, .f32),
            .@"f32.add",
            .@"f32.sub",
            .@"f32.mul",
            .@"f32.div",
            .@"f32.min",
            .@"f32.max",
            .@"f32.copysign",
            => {
                try val_stack.popExpecting(&ctrl_stack, .f32);
                try val_stack.popThenPushExpecting(scratch, &ctrl_stack, .f32, .f32);
            },
            .@"f64.abs",
            .@"f64.neg",
            .@"f64.ceil",
            .@"f64.floor",
            .@"f64.trunc",
            .@"f64.nearest",
            .@"f64.sqrt",
            => try val_stack.popThenPushExpecting(scratch, &ctrl_stack, .f64, .f64),
            .@"f64.add",
            .@"f64.sub",
            .@"f64.mul",
            .@"f64.div",
            .@"f64.min",
            .@"f64.max",
            .@"f64.copysign",
            => {
                try val_stack.popExpecting(&ctrl_stack, .f64);
                try val_stack.popThenPushExpecting(scratch, &ctrl_stack, .f64, .f64);
            },
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

            .@"ref.null" => {
                const ref_type = try reader.readValType();
                if (!ref_type.isRefType()) return error.InvalidWasm;
                try val_stack.push(scratch, ref_type);
            },
            .@"ref.is_null" => {
                const ref_type = try val_stack.popAny(&ctrl_stack);
                if (!isRefVal(ref_type)) return error.InvalidWasm;
                try val_stack.push(scratch, .i32);
            },
            .@"ref.func" => {
                _ = try reader.readIdx(Module.FuncIdx, module.funcTypes().len);
                try val_stack.push(scratch, ValType.funcref);
            },

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

                .@"memory.init" => {
                    try readDataIdx(&reader, module);
                    try readMemIdx(&reader, module);
                    try val_stack.popManyExpecting(&ctrl_stack, &[_]ValType{.i32} ** 3);
                },
                .@"data.drop" => try readDataIdx(&reader, module),
                .@"memory.copy" => {
                    try readMemIdx(&reader, module);
                    try readMemIdx(&reader, module);
                    try val_stack.popManyExpecting(&ctrl_stack, &[_]ValType{.i32} ** 3);
                },
                .@"memory.fill" => {
                    try readMemIdx(&reader, module);
                    try val_stack.popManyExpecting(&ctrl_stack, &[_]ValType{.i32} ** 3);
                },

                .@"table.init" => {
                    const elem_type = try readElemIdx(&reader, module);
                    const table_type = try readTableIdx(&reader, module);
                    if (elem_type != table_type) return error.InvalidWasm;
                    try val_stack.popManyExpecting(&ctrl_stack, &[_]ValType{.i32} ** 3);
                },
                .@"elem.drop" => _ = try readElemIdx(&reader, module),
                .@"table.copy" => {
                    const dst_type = try readTableIdx(&reader, module);
                    const src_type = try readTableIdx(&reader, module);
                    if (dst_type != src_type) return error.InvalidWasm;
                    try val_stack.popManyExpecting(&ctrl_stack, &[_]ValType{.i32} ** 3);
                },
                .@"table.grow" => {
                    const elem_type = try readTableIdx(&reader, module);
                    try val_stack.popExpecting(&ctrl_stack, .i32);
                    try val_stack.popThenPushExpecting(
                        scratch,
                        &ctrl_stack,
                        elem_type,
                        .i32,
                    );
                },
                .@"table.size" => {
                    _ = try readTableIdx(&reader, module);
                    try val_stack.push(scratch, .i32);
                },
                .@"table.fill" => {
                    const elem_type = try readTableIdx(&reader, module);
                    try val_stack.popManyExpecting(
                        &ctrl_stack,
                        &[3]ValType{ .i32, elem_type, .i32 },
                    );
                },

                // else => |bad| std.debug.panic("TODO: handle 0xFC {s}\n", .{@tagName(bad)}),
            },

            else => |bad| std.debug.panic("TODO: handle {s} (0x{X:0>2})\n", .{ @tagName(bad), @intFromEnum(bad) }),
        }
    }

    try reader.expectEndOfStream();

    if (ctrl_stack.len != 0)
        return error.MalformedWasm;

    std.debug.assert(val_stack.len() == func_type.result_count);
    std.debug.assert(side_table.active.len == 0);
    std.debug.assert(side_table.alternate.len == 0);

    const eip: *const Code.End = @ptrCast(instructions + instr_offset);
    const max_values: u16 = val_stack.max;
    const final_side_table: []const Code.SideTableEntry = side_table: {
        const copied = try allocator.alloc(Code.SideTableEntry, side_table.entries.len);
        side_table.entries.writeToSlice(copied, 0);
        break :side_table copied;
    };

    errdefer comptime unreachable;

    for (final_side_table, 0..) |*entry, i| {
        // Catch any entries that were not fixed up when safety checks are enabled.
        _ = entry.delta_ip.done;
        _ = i;

        //std.debug.print(
        //    "#{}: delta_ip = {}, delta_stp = {}, copied = {}, popped = {}\n",
        //    .{
        //        i,
        //        entry.delta_ip.done,
        //        entry.delta_stp,
        //        entry.copy_count,
        //        entry.pop_count,
        //    },
        //);
    }

    return .{
        .instructions_start = instructions,
        .instructions_end = eip,
        .max_values = max_values,
        .local_values = locals.count,
        .side_table_len = @intCast(final_side_table.len),
        .side_table_ptr = final_side_table.ptr,
    };
}
