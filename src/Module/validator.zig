//! Implements the WebAssembly [validation algorithm] and side-table generation
//! as described in Ben L. Titzer's ["A fast in-place interpreter for WebAssembly"].
//!
//! `wasmstint` is currently designed to lazily validate functions.
//! For more information, see <https://github.com/WebAssembly/design/issues/1464>.
//!
//! [validation algorithm]: https://webassembly.github.io/spec/core/appendix/algorithm.html
//! ["A fast in-place interpreter for WebAssembly"]: https://doi.org/10.48550/arXiv.2205.01183

pub const Error = Module.ParseError;

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
    pub const SideTableEntry = packed struct(if (builtin.mode == .Debug) u128 else u64) {
        delta_ip: packed union {
            done: i32,
            /// Offset from the first byte of the first instruction to the first byte of the
            /// branch instruction.
            fixup_origin: u32,
        },
        delta_stp: i16,
        copy_count: u8,
        pop_count: u8,
        /// Set to the same value as `fixup_origin` to catch bugs during side table construction.
        origin: if (builtin.mode == .Debug) u32 else void,
        padding: if (builtin.mode == .Debug) u32 else u0 = undefined,
    };

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
        @intFromEnum(opcodes.ByteOpcode.@"unreachable"),
        // The `0xFF` opcode is currently used by some engines for private opcodes.
        //
        // See <https://github.com/WebAssembly/design/issues/1539> for more information.
        //
        // This is here more to catch bugs. The handler for `unreachable` checks if
        // `@intFromPtr(ip) == @intFromPtr(&validation_failed_body)` to determine if validation
        // failure actually occurred.
        0xFF,
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
    /// Attempting to interpret a function that failed validation is treated as a trap. Note that
    /// due to API limitations, encountering an OOM condition during validation is treated as a
    /// validation failure.
    ///
    /// Asserts that this `Code` belongs to the given `Module`.
    pub fn validate(
        code: *Code,
        allocator: Allocator,
        module: Module,
        scratch: *ArenaAllocator,
        diag: Diagnostics,
    ) Error!bool {
        check: {
            // TODO: Should this be cmpxchgStrong? or maybe fetchMax should be used instead?
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
        const code_sec_ptr = module.inner.raw.code;
        std.debug.assert(@intFromPtr(code_sec_ptr) <= code_addr);
        std.debug.assert(code_addr < @intFromPtr(code_sec_ptr + module.inner.raw.code_count));

        const func_idx: Module.FuncIdx = @enumFromInt(@as(
            @typeInfo(Module.FuncIdx).@"enum".tag_type,
            @intCast(
                module.inner.raw.func_import_count + @divExact(
                    code_addr - @intFromPtr(code_sec_ptr),
                    @sizeOf(Code),
                ),
            ),
        ));

        // std.debug.print("validating {}\n", .{@intFromEnum(func_idx)});

        defer code.status.store(.finished, .release);
        const result = rawValidate(
            allocator,
            module,
            module.funcTypeIdx(func_idx),
            module.codeEntries()[@intFromEnum(func_idx) - module.inner.raw.func_import_count]
                .contents.slice(module.inner.raw.code_section, module.inner.wasm),
            scratch,
            diag,
        );

        // std.debug.print("validation finished {!any}\n", .{result});

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

    fn funcType(block_type: *const BlockType, module: Module) Module.FuncType {
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

    fn parse(reader: Reader, module: Module, diag: Diagnostics) Error!BlockType {
        var int_bytes = reader.bytes.*;
        const int_reader = Reader{ .bytes = &int_bytes };
        const tag_int = try int_reader.readIleb128(i33, diag, "block type");

        var byte_bytes = reader.bytes.*;
        const byte_reader = Reader{ .bytes = &byte_bytes };
        const byte_tag = byte_reader.readAssumeLength(1)[0];

        if (byte_tag == 0x40) {
            reader.bytes.* = byte_bytes;
            return BlockType.void;
        } else if (tag_int >= 0) {
            reader.bytes.* = int_bytes;
            return if (tag_int < module.inner.raw.types_count)
                BlockType{
                    .type = .{
                        .idx = @enumFromInt(
                            @as(
                                @typeInfo(Module.TypeIdx).@"enum".tag_type,
                                @intCast(tag_int),
                            ),
                        ),
                    },
                }
            else
                diag.print(.validation, "unknown type {} in block type", .{tag_int});
        } else {
            reader.bytes.* = byte_bytes;
            return BlockType{
                .single_result = std.meta.intToEnum(
                    ValType,
                    byte_tag,
                ) catch return diag.print(
                    .parse,
                    "malformed valtype in block type 0x{X:0>2}",
                    .{byte_tag},
                ),
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

    fn labelTypes(frame: *const CtrlFrame, module: Module) []const ValType {
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

    fn pushAny(val_stack: *ValStack, arena: *ArenaAllocator, val: Val) !void {
        try val_stack.buf.append(arena.allocator(), val);
        // Note, if someone pushes a known value over an unknown, the max will grow anyway
        // TODO: check that current frame is reachable instead.
        // if (val != .unknown) {
        val_stack.max = @max(val_stack.max, std.math.cast(u16, val_stack.buf.len) orelse
            return Error.WasmImplementationLimit);
        // }
    }

    fn push(val_stack: *ValStack, arena: *ArenaAllocator, val_type: ValType) !void {
        return val_stack.pushAny(arena, valTypeToVal(val_type));
    }

    /// Asserts that `types.len() <= std.math.maxInt(u16)`.
    fn pushMany(val_stack: *ValStack, arena: *ArenaAllocator, types: []const ValType) !void {
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

    fn errorValueStackUnderflow(height: u16, diag: Diagnostics) Reader.ValidationError {
        return diag.print(
            .validation,
            "type mismatch: value stack underflows at height {}",
            .{height},
        );
    }

    fn popAny(val_stack: *ValStack, ctrl_stack: *const CtrlStack, diag: Diagnostics) !Val {
        const current_frame: *const CtrlFrame = ctrl_stack.at(ctrl_stack.len - 1);
        return if (val_stack.len() == current_frame.info.height)
            if (current_frame.info.@"unreachable")
                Val.unknown
            else
                errorValueStackUnderflow(current_frame.info.height, diag)
        else
            val_stack.buf.pop().?;
    }

    fn popExpecting(
        val_stack: *ValStack,
        ctrl_stack: *const CtrlStack,
        expected: ValType,
        diag: Diagnostics,
    ) Error!void {
        const popped = try val_stack.popAny(ctrl_stack, diag);
        // std.debug.print("wanted {}, got {}\n", .{ expected, popped });
        if (popped != valTypeToVal(expected) and popped != .unknown) {
            return diag.print(
                .validation,
                "type mismatch, expected {t} but got {t}",
                .{ expected, popped },
            );
        }
    }

    fn popThenPushExpecting(
        val_stack: *ValStack,
        arena: *ArenaAllocator,
        ctrl_stack: *const CtrlStack,
        expected: ValType,
        replacement: ValType,
        diag: Diagnostics,
    ) !void {
        const current_frame: *const CtrlFrame = ctrl_stack.at(ctrl_stack.len - 1);
        if (val_stack.len() > current_frame.info.height) {
            const top: *Val = val_stack.buf.at(val_stack.len() - 1);

            if (top.* != valTypeToVal(expected) and top.* != .unknown) {
                return diag.print(
                    .validation,
                    "type mismatch, expected {t} but got {t}",
                    .{ expected, top.* },
                );
            }

            top.* = valTypeToVal(replacement);
        } else if (current_frame.info.@"unreachable") {
            try val_stack.push(arena, replacement);
        } else {
            return errorValueStackUnderflow(current_frame.info.height, diag);
        }
    }

    fn popManyExpecting(
        val_stack: *ValStack,
        ctrl_stack: *const CtrlStack,
        expected: []const ValType,
        diag: Diagnostics,
    ) !void {
        // std.debug.print("current height = {}, want to pop = {any}\n", .{ val_stack.len(), expected });
        for (0..expected.len) |i| {
            try val_stack.popExpecting(ctrl_stack, expected[expected.len - 1 - i], diag);
        }
    }

    /// Used to preserve `.unknown` stack values when popping and pushing the same types.
    fn popThenPushManyExpectingPreserveUnknown(
        val_stack: *ValStack,
        ctrl_stack: *const CtrlStack,
        expected: []const ValType,
        diag: Diagnostics,
    ) !void {
        const current_frame: *const CtrlFrame = ctrl_stack.at(ctrl_stack.len - 1);
        for (0..expected.len) |i| {
            const expected_type = valTypeToVal(expected[expected.len - 1 - i]);
            const current_height = val_stack.len() - i;
            const actual_type: Val = if (current_height == current_frame.info.height)
                if (current_frame.info.@"unreachable")
                    Val.unknown
                else
                    return errorValueStackUnderflow(current_frame.info.height, diag)
            else
                val_stack.buf.at(current_height - 1).*;

            if (actual_type != expected_type and actual_type != .unknown) {
                return diag.print(
                    .validation,
                    "type mismatch, expected {t} but got {t}",
                    .{ expected_type, actual_type },
                );
            }
        }
    }
};

fn readMemIdx(reader: *Reader, module: Module, diag: Diagnostics) !void {
    const msg = "memory index zero byte expected";
    const idx = try reader.readByte(diag, msg);
    if (idx != 0) {
        return diag.writeAll(.parse, msg);
    }

    if (module.inner.raw.mem_count == 0) {
        return diag.print(.validation, "unknown memory {}", .{idx});
    }
}

fn readMemArg(
    reader: *Reader,
    natural_alignment: u3,
    module: Module,
    diag: Diagnostics,
) !void {
    const a = try reader.readUleb128(u32, diag, "memarg alignment");

    if (a > natural_alignment) {
        return if (a < 32)
            diag.writeAll(.validation, "alignment must not be larger than natural")
        else
            diag.writeAll(.parse, "malformed memop flags, alignment overflow");
    }

    if (module.inner.raw.mem_count == 0) {
        return diag.writeAll(.validation, "unknown memory in memarg");
    }

    _ = try reader.readUleb128(u32, diag, "memarg offset");
}

fn readTableIdx(reader: *Reader, module: Module, diag: Diagnostics) !ValType {
    const table_types = module.tableTypes();
    const idx = try reader.readIdx(
        Module.TableIdx,
        table_types.len,
        diag,
        &.{ "table", "in code" },
    );
    return module.tableTypes()[@intFromEnum(idx)].elem_type;
}

const ReadDataIdx = struct {
    idx: u32,

    fn begin(reader: *Reader, diag: Diagnostics) !ReadDataIdx {
        return .{
            .idx = try reader.readUleb128Casted(
                u32,
                @typeInfo(Module.DataIdx).@"enum".tag_type,
                diag,
                "data segment index",
            ),
        };
    }

    fn boundsCheck(self: ReadDataIdx, module: Module, diag: Diagnostics) !void {
        // spec first checks OOB index
        if (self.idx >= module.inner.raw.datas_count) {
            return diag.print(.validation, "unknown data segment {}, in code", .{self.idx});
        }

        if (!module.inner.raw.has_data_count_section) {
            return diag.writeAll(.parse, "data count section required");
        }
    }
};

fn readElemIdx(reader: *Reader, module: Module, diag: Diagnostics) !ValType {
    const idx = try reader.readIdx(
        Module.ElemIdx,
        module.inner.raw.elems_count,
        diag,
        &.{ "elem segment", "in code" },
    );
    return module.elementSegments()[@intFromEnum(idx)].elementType();
}

fn readLocalIdx(reader: *Reader, locals: []const ValType, diag: Diagnostics) !ValType {
    const idx = try reader.readUleb128(u32, diag, "local index");
    return if (idx < locals.len) locals[idx] else diag.print(
        .validation,
        "unknown local {}",
        .{idx},
    );
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

    fn init(
        depth: u32,
        ctrl_stack: *const CtrlStack,
        current_height: u16,
        module: Module,
        diag: Diagnostics,
    ) !Label {
        const frame: *const CtrlFrame = if (depth < ctrl_stack.len)
            ctrl_stack.at(ctrl_stack.len - 1 - depth)
        else
            return diag.print(.validation, "unknown label {}", .{depth});

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
        reader: *Reader,
        ctrl_stack: *const CtrlStack,
        current_height: u16,
        module: Module,
        diag: Diagnostics,
    ) !Label {
        const depth = try reader.readUleb128(u32, diag, "label depth");
        return Label.init(depth, ctrl_stack, current_height, module, diag);
    }
};

fn pushCtrlFrame(
    arena: *ArenaAllocator,
    ctrl_stack: *CtrlStack,
    val_stack: *ValStack,
    side_table: *const SideTableBuilder,
    opcode: CtrlFrame.Opcode,
    offset: u32,
    block_type: BlockType,
    module: Module,
) !void {
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
    module: Module,
    diag: Diagnostics,
) !CtrlFrame {
    if (ctrl_stack.len == 0) {
        return diag.writeAll(.validation, "control stack underflow");
    }

    const frame: CtrlFrame = ctrl_stack.at(ctrl_stack.len - 1).*;
    const result_types = frame.types.funcType(module).results();
    // std.debug.print("processing {t} {any}\n", .{ frame.info.opcode, result_types });

    try val_stack.popManyExpecting(ctrl_stack, result_types, diag);
    if (val_stack.len() != frame.info.height) {
        return diag.print(
            .validation,
            "type mismatch: expected value stack height to be {}, was {}",
            .{ frame.info.height, val_stack.len() },
        );
    }

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

            const empty: Header = .{
                .prev = List.empty,
                .len = 0,
                .capacity = 0,
            };
        };

        header: *Header,

        const header_size_in_elems = @divExact(@sizeOf(Header), @sizeOf(BranchFixup));

        const empty: List = .{ .header = @constCast(&Header.empty) };

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
                        .fromByteUnits(@alignOf(Header)),
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
    free: BranchFixup.List = .empty,

    fn nextEntryIdx(table: *const SideTableBuilder) Module.LimitError!u32 {
        return std.math.cast(u32, table.entries.len) orelse return error.WasmImplementationLimit;
    }

    fn pushFixupList(
        table: *SideTableBuilder,
        arena: *ArenaAllocator,
        block_offset: ActiveList.BlockOffset,
        allocation: enum { reuse, empty },
    ) Allocator.Error!void {
        const fixups: BranchFixup.List = switch (allocation) {
            .reuse => reused: {
                const used = table.free;
                table.free = table.free.header.prev;
                if (used.header.capacity > 0) {
                    used.header.prev = .empty;
                }

                break :reused used;
            },
            .empty => .empty,
        };

        std.debug.assert(fixups.header.len == 0);
        std.debug.assert(fixups.header.prev.header.capacity == 0);

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
) !void {
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
    reader: *Reader,
    val_stack: *ValStack,
    ctrl_stack: *const CtrlStack,
    natural_alignment: u3,
    loaded: ValType,
    module: Module,
    arena: *ArenaAllocator,
    diag: Diagnostics,
) Error!void {
    // Pop index, push loaded value.
    try val_stack.popThenPushExpecting(arena, ctrl_stack, .i32, loaded, diag);
    try readMemArg(reader, natural_alignment, module, diag);
}

fn validateStoreInstr(
    reader: *Reader,
    val_stack: *ValStack,
    ctrl_stack: *const CtrlStack,
    natural_alignment: u3,
    stored: ValType,
    module: Module,
    diag: Diagnostics,
) Error!void {
    try val_stack.popManyExpecting(ctrl_stack, &[_]ValType{ .i32, stored }, diag);
    try readMemArg(reader, natural_alignment, module, diag);
}

pub fn rawValidate(
    allocator: Allocator,
    module: Module,
    signature: Module.TypeIdx,
    code: []const u8,
    scratch: *ArenaAllocator,
    diag: Reader.Diagnostics,
) Error!Code.Inner {
    _ = scratch.reset(.retain_capacity);
    var per_instr_arena = ArenaAllocator.init(scratch.allocator());

    var code_ptr = code;
    var reader = Reader.init(&code_ptr);

    const func_type = signature.funcType(module);

    var val_stack: ValStack = undefined;
    const locals: struct { types: []const ValType, count: u16 } = locals: {
        const local_group_count = try reader.readUleb128(u32, diag, "locals count");

        const LocalGroup = struct { type: ValType, count: u32 };

        // Since std.SegmentedList is buggy when faced with OOMs, and a parser error
        // (not an OOM) should happen if # locals exceeds what is allowed by the spec (2^32 - 1),
        // this allows determining the total # of all locals beforehand
        const local_groups = try per_instr_arena.allocator().alloc(LocalGroup, local_group_count);
        var total_locals_count: u32 = func_type.param_count;
        for (local_groups) |*group| {
            const local_count = try reader.readUleb128(u32, diag, "locals count");
            const local_type = try ValType.parse(reader, diag);
            total_locals_count = std.math.add(u32, total_locals_count, local_count) catch
                return diag.writeAll(.parse, "too many locals");
            group.* = .{ .type = local_type, .count = local_count };
        }

        if (total_locals_count > std.math.maxInt(u16)) {
            return error.WasmImplementationLimit; // too many locals
        }

        const buf = try scratch.allocator().alloc(ValType, total_locals_count);
        @memcpy(buf[0..func_type.param_count], func_type.parameters());
        var local_vars = ValBuf{};
        const locals_only_count = total_locals_count - func_type.param_count;
        if (locals_only_count > ValBuf.prealloc_count) {
            // TODO(Zig): handle OOMs properly for std.SegmentedList
            // https://github.com/ziglang/zig/issues/23027
            try local_vars.growCapacity(scratch.allocator(), locals_only_count);
        }

        errdefer comptime unreachable;

        var local_idx: u16 = func_type.param_count;
        for (local_groups) |*group| {
            for (0..group.count) |_| {
                local_vars.append(undefined, valTypeToVal(group.type)) catch unreachable;
                buf[local_idx] = group.type;
                local_idx += 1;
            }
        }

        std.debug.assert(local_idx == buf.len);
        local_vars.clearRetainingCapacity();
        val_stack = ValStack{ .buf = local_vars };
        break :locals .{ .types = buf, .count = @intCast(total_locals_count) };
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

    var instr_offset: u32 = 0;
    while (ctrl_stack.len > 0) {
        _ = per_instr_arena.reset(.retain_capacity);

        // Offset from the first byte of the first instruction to the first
        // byte of the instruction being parsed.
        instr_offset = @intCast(@intFromPtr(reader.bytes.ptr) - @intFromPtr(instructions));

        if (reader.isEmpty()) {
            // Spec test is based on spec interpreter, which does weird things like
            // start consuming the data section even when the length of the code section says
            // to stop
            return diag.writeAll(
                .parse,
                "unexpected end of section or function: END opcode expected or section size mismatch",
            );
        }

        const opcode_byte = reader.readAssumeLength(1)[0];
        const opcode_tag = std.meta.intToEnum(opcodes.ByteOpcode, opcode_byte) catch
            return diag.print(.parse, "illegal opcode 0x{X:0>2}", .{opcode_byte});

        // std.debug.print("validate: {} 0x{X:0>2}\n", .{ opcode_tag, opcode_byte });
        switch (opcode_tag) {
            .@"unreachable" => markUnreachable(&val_stack, &ctrl_stack),
            .nop => {},
            .block => {
                const block_type = try BlockType.parse(reader, module, diag);
                try val_stack.popManyExpecting(
                    &ctrl_stack,
                    block_type.funcType(module).parameters(),
                    diag,
                );
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
                const block_type = try BlockType.parse(reader, module, diag);
                try val_stack.popManyExpecting(
                    &ctrl_stack,
                    block_type.funcType(module).parameters(),
                    diag,
                );
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
                const block_type = try BlockType.parse(reader, module, diag);
                try val_stack.popExpecting(&ctrl_stack, .i32, diag);
                try val_stack.popManyExpecting(
                    &ctrl_stack,
                    block_type.funcType(module).parameters(),
                    diag,
                );
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

                const frame = try popCtrlFrame(&ctrl_stack, &val_stack, module, diag);
                if (frame.info.opcode != .@"if") {
                    return diag.print(
                        .validation,
                        "expected 'if' opcode, got '{t}'",
                        .{frame.info.opcode},
                    );
                }

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

                if (builtin.mode == .Debug) {
                    side_table.active.at(side_table.active.len - 1).block_offset = instr_offset;
                }
            },
            .end => {
                // std.debug.print("PROCESSING END\n", .{});
                const frame = try popCtrlFrame(&ctrl_stack, &val_stack, module, diag);

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

                const frame_types = frame.types.funcType(module);
                const result_types = frame_types.results();
                if (frame.info.opcode == .@"if") {
                    // Check that param types satisfy the results
                    try val_stack.pushMany(scratch, frame_types.parameters());
                    try val_stack.popManyExpecting(&ctrl_stack, result_types, diag);

                    // No `else` branch exists, so there are no fixups for it
                    try side_table.popAndResolveAlternate(instr_offset);
                }

                try val_stack.pushMany(scratch, result_types);
            },
            .br => {
                const label = try Label.read(
                    &reader,
                    &ctrl_stack,
                    val_stack.len(),
                    module,
                    diag,
                );

                // TODO: Skip branch fixup processing for unreachable code.
                try appendSideTableEntry(scratch, &side_table, instr_offset, label);

                try val_stack.popManyExpecting(&ctrl_stack, label.frame.labelTypes(module), diag);
                markUnreachable(&val_stack, &ctrl_stack);
            },
            .br_if => {
                try val_stack.popExpecting(&ctrl_stack, .i32, diag);

                const label = try Label.read(
                    &reader,
                    &ctrl_stack,
                    val_stack.len(),
                    module,
                    diag,
                );

                // TODO: Skip branch fixup processing for unreachable code.
                try appendSideTableEntry(scratch, &side_table, instr_offset, label);

                const label_types = label.frame.labelTypes(module);
                try val_stack.popManyExpecting(&ctrl_stack, label_types, diag);
                try val_stack.pushMany(scratch, label_types);
            },
            .br_table => {
                try val_stack.popExpecting(&ctrl_stack, .i32, diag);

                const current_height = val_stack.len();

                const label_count = try reader.readUleb128(u32, diag, "br_table label count");
                const labels = try per_instr_arena.allocator().alloc(u32, label_count);

                // Reserve space for the new side table entries.
                {
                    const grow_side_table = std.math.add(
                        usize,
                        std.math.add(usize, 1, labels.len) catch
                            return error.OutOfMemory,
                        side_table.entries.len,
                    ) catch return error.OutOfMemory;

                    if (grow_side_table > SideTableBuilder.Entries.prealloc_count) {
                        try side_table.entries.growCapacity(scratch.allocator(), grow_side_table);
                    }
                }

                // Validation bases the "arity" on the default branch, so all labels must be parsed
                // to get to the default label.
                for (labels) |*n| n.* = try reader.readUleb128(u32, diag, "br_table label");

                // TODO: Skip branch fixup processing for unreachable code.
                const last_label = try Label.read(
                    &reader,
                    &ctrl_stack,
                    current_height,
                    module,
                    diag,
                );

                const last_label_types = last_label.frame.labelTypes(module);
                const arity: u32 = @intCast(last_label_types.len);

                // std.debug.print(
                //     "BEGIN BR_TABLE WITH {}+1 LABELS (was {} side table entries)\n",
                //     .{ label_count, side_table.entries.len },
                // );

                for (labels) |n| {
                    const l = try Label.init(
                        n,
                        &ctrl_stack,
                        current_height,
                        module,
                        diag,
                    );

                    try appendSideTableEntry(scratch, &side_table, instr_offset, l);

                    const l_types = l.frame.labelTypes(module);
                    if (l_types.len != arity) {
                        return diag.print(
                            .validation,
                            "type mismatch, br_table label has arity {}, expected {}",
                            .{ l_types.len, arity },
                        );
                    }

                    try val_stack.popThenPushManyExpectingPreserveUnknown(
                        &ctrl_stack,
                        l_types,
                        diag,
                    );
                }

                try appendSideTableEntry(scratch, &side_table, instr_offset, last_label);

                // std.debug.print(
                //     "END BR_TABLE (now {} side table entries)\n",
                //     .{side_table.entries.len},
                // );

                try val_stack.popManyExpecting(&ctrl_stack, last_label_types, diag);
                markUnreachable(&val_stack, &ctrl_stack);
            },
            .@"return" => {
                try val_stack.popManyExpecting(&ctrl_stack, func_type.results(), diag);
                markUnreachable(&val_stack, &ctrl_stack);
            },
            .call => {
                const callee = try reader.readIdx(
                    Module.FuncIdx,
                    module.funcTypes().len,
                    diag,
                    &.{ "function", "in call" },
                );
                const callee_signature = module.funcTypes()[@intFromEnum(callee)];

                try val_stack.popManyExpecting(&ctrl_stack, callee_signature.parameters(), diag);
                try val_stack.pushMany(scratch, callee_signature.results());
            },
            .call_indirect => {
                const module_types = module.types();
                const type_idx = try reader.readIdx(
                    Module.TypeIdx,
                    module_types.len,
                    diag,
                    &.{ "type", "in call_indirect" },
                );

                const callee_signature: *const Module.FuncType =
                    &module_types[@intFromEnum(type_idx)];

                // std.debug.print(
                //     "CHECK call_indirect ({}) {any} -> {any}\n",
                //     .{ type_idx, callee_signature.parameters(), callee_signature.results() },
                // );

                const table_types = module.tableTypes();
                const table_idx = try reader.readIdx(
                    Module.TableIdx,
                    table_types.len,
                    diag,
                    &.{ "table", "in call_indirect" },
                );
                const table_type: *const Module.TableType = &table_types[@intFromEnum(table_idx)];

                if (table_type.elem_type != .funcref) {
                    return diag.print(
                        .validation,
                        "type mismatch: call_indirect expects funcref, but type of table {} is {f}",
                        .{ @intFromEnum(table_idx), table_type },
                    );
                }

                try val_stack.popExpecting(&ctrl_stack, .i32, diag);
                try val_stack.popManyExpecting(&ctrl_stack, callee_signature.parameters(), diag);
                try val_stack.pushMany(scratch, callee_signature.results());
            },

            .drop => _ = try val_stack.popAny(&ctrl_stack, diag),
            .select => {
                try val_stack.popExpecting(&ctrl_stack, .i32, diag);

                const current_frame: *const CtrlFrame = ctrl_stack.at(ctrl_stack.len - 1);
                if (val_stack.len() == current_frame.info.height and
                    !current_frame.info.@"unreachable")
                {
                    return diag.print(
                        .validation,
                        "type mismatch or invalid result arity: value stack underflows at height {}",
                        .{current_frame.info.height},
                    );
                }

                const t_1: Val = val_stack.popAny(&ctrl_stack, diag) catch
                    unreachable; // check occurs above
                const t_2: Val = try val_stack.popAny(&ctrl_stack, diag);

                const both_num_types = isNumVal(t_1) and isNumVal(t_2);
                const both_vec_types = isVecVal(t_1) and isVecVal(t_2);
                if (!(both_num_types or both_vec_types)) {
                    return diag.print(
                        .validation,
                        "type mismatch: expected matching numeric/vector types, got {t} vs {t}",
                        .{ t_1, t_2 },
                    );
                }

                if (t_1 != t_2 and t_1 != .unknown and t_2 != .unknown) {
                    return diag.print(.validation, "type mismatch: {t} != {t}", .{ t_1, t_2 });
                }

                val_stack.pushAny(
                    undefined,
                    if (t_1 == .unknown) t_2 else t_1,
                ) catch unreachable;
            },
            .@"select t" => {
                const type_count = try reader.readUleb128(u32, diag, "select arity");
                if (type_count != 1) {
                    return diag.print(
                        .validation,
                        "invalid result arity, expected 1 but got {}",
                        .{type_count},
                    );
                }

                const t = try ValType.parse(reader, diag);
                try val_stack.popManyExpecting(&ctrl_stack, &.{ t, t, .i32 }, diag);
                try val_stack.push(undefined, t);
            },

            .@"local.get" => {
                const local_type = try readLocalIdx(&reader, locals.types, diag);
                try val_stack.push(scratch, local_type);
            },
            .@"local.set" => {
                const local_type = try readLocalIdx(&reader, locals.types, diag);
                try val_stack.popExpecting(&ctrl_stack, local_type, diag);
            },
            .@"local.tee" => {
                const local_type = try readLocalIdx(&reader, locals.types, diag);
                try val_stack.popThenPushExpecting(
                    scratch,
                    &ctrl_stack,
                    local_type,
                    local_type,
                    diag,
                );
            },
            .@"global.get" => {
                const global_idx = try reader.readIdx(
                    Module.GlobalIdx,
                    module.globalTypes().len,
                    diag,
                    &.{ "global", "in global.get" },
                );

                try val_stack.push(
                    scratch,
                    module.globalTypes()[@intFromEnum(global_idx)].val_type,
                );
            },
            .@"global.set" => {
                const global_idx = try reader.readIdx(
                    Module.GlobalIdx,
                    module.globalTypes().len,
                    diag,
                    &.{ "global", "in global.get" },
                );

                const global_type: *const Module.GlobalType =
                    &module.globalTypes()[@intFromEnum(global_idx)];

                if (global_type.mut != .@"var") {
                    return diag.writeAll(.validation, "global is immutable");
                }

                try val_stack.popExpecting(&ctrl_stack, global_type.val_type, diag);
            },

            .@"table.get" => {
                const table_type = try readTableIdx(&reader, module, diag);
                try val_stack.popThenPushExpecting(
                    scratch,
                    &ctrl_stack,
                    .i32,
                    table_type,
                    diag,
                );
            },
            .@"table.set" => {
                const table_type = try readTableIdx(&reader, module, diag);
                try val_stack.popManyExpecting(
                    &ctrl_stack,
                    &[_]ValType{ .i32, table_type },
                    diag,
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
                diag,
            ),
            .@"i64.load" => try validateLoadInstr(
                &reader,
                &val_stack,
                &ctrl_stack,
                std.math.log2(8),
                .i64,
                module,
                scratch,
                diag,
            ),
            .@"f32.load" => try validateLoadInstr(
                &reader,
                &val_stack,
                &ctrl_stack,
                std.math.log2(4),
                .f32,
                module,
                scratch,
                diag,
            ),
            .@"f64.load" => try validateLoadInstr(
                &reader,
                &val_stack,
                &ctrl_stack,
                std.math.log2(8),
                .f64,
                module,
                scratch,
                diag,
            ),
            .@"i32.load8_s", .@"i32.load8_u" => try validateLoadInstr(
                &reader,
                &val_stack,
                &ctrl_stack,
                std.math.log2(1),
                .i32,
                module,
                scratch,
                diag,
            ),
            .@"i32.load16_s", .@"i32.load16_u" => try validateLoadInstr(
                &reader,
                &val_stack,
                &ctrl_stack,
                std.math.log2(2),
                .i32,
                module,
                scratch,
                diag,
            ),
            .@"i64.load8_s", .@"i64.load8_u" => try validateLoadInstr(
                &reader,
                &val_stack,
                &ctrl_stack,
                std.math.log2(1),
                .i64,
                module,
                scratch,
                diag,
            ),
            .@"i64.load16_s", .@"i64.load16_u" => try validateLoadInstr(
                &reader,
                &val_stack,
                &ctrl_stack,
                std.math.log2(2),
                .i64,
                module,
                scratch,
                diag,
            ),
            .@"i64.load32_s", .@"i64.load32_u" => try validateLoadInstr(
                &reader,
                &val_stack,
                &ctrl_stack,
                std.math.log2(4),
                .i64,
                module,
                scratch,
                diag,
            ),
            .@"i32.store" => try validateStoreInstr(
                &reader,
                &val_stack,
                &ctrl_stack,
                std.math.log2(4),
                .i32,
                module,
                diag,
            ),
            .@"i64.store" => try validateStoreInstr(
                &reader,
                &val_stack,
                &ctrl_stack,
                std.math.log2(8),
                .i64,
                module,
                diag,
            ),
            .@"f32.store" => try validateStoreInstr(
                &reader,
                &val_stack,
                &ctrl_stack,
                std.math.log2(4),
                .f32,
                module,
                diag,
            ),
            .@"f64.store" => try validateStoreInstr(
                &reader,
                &val_stack,
                &ctrl_stack,
                std.math.log2(8),
                .f64,
                module,
                diag,
            ),
            .@"i32.store8" => try validateStoreInstr(
                &reader,
                &val_stack,
                &ctrl_stack,
                std.math.log2(1),
                .i32,
                module,
                diag,
            ),
            .@"i32.store16" => try validateStoreInstr(
                &reader,
                &val_stack,
                &ctrl_stack,
                std.math.log2(2),
                .i32,
                module,
                diag,
            ),
            .@"i64.store8" => try validateStoreInstr(
                &reader,
                &val_stack,
                &ctrl_stack,
                std.math.log2(1),
                .i64,
                module,
                diag,
            ),
            .@"i64.store16" => try validateStoreInstr(
                &reader,
                &val_stack,
                &ctrl_stack,
                std.math.log2(2),
                .i64,
                module,
                diag,
            ),
            .@"i64.store32" => try validateStoreInstr(
                &reader,
                &val_stack,
                &ctrl_stack,
                std.math.log2(4),
                .i64,
                module,
                diag,
            ),
            .@"memory.size" => {
                try readMemIdx(&reader, module, diag);
                try val_stack.push(scratch, .i32);
            },
            .@"memory.grow" => {
                try readMemIdx(&reader, module, diag);
                try val_stack.popThenPushExpecting(scratch, &ctrl_stack, .i32, .i32, diag);
            },

            .@"i32.const" => {
                _ = try reader.readIleb128(i32, diag, "i32.const");
                try val_stack.push(scratch, .i32);
            },
            .@"i64.const" => {
                _ = try reader.readIleb128(i64, diag, "i64.const");
                try val_stack.push(scratch, .i64);
            },
            .@"f32.const" => {
                _ = try reader.readArray(4, diag, "f32.const");
                try val_stack.push(scratch, .f32);
            },
            .@"f64.const" => {
                _ = try reader.readArray(8, diag, "f64.const");
                try val_stack.push(scratch, .f64);
            },
            .@"i32.eqz",
            .@"i32.clz",
            .@"i32.ctz",
            .@"i32.popcnt",
            .@"i32.extend8_s",
            .@"i32.extend16_s",
            => try val_stack.popThenPushExpecting(scratch, &ctrl_stack, .i32, .i32, diag),
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
                try val_stack.popExpecting(&ctrl_stack, .i32, diag);
                try val_stack.popThenPushExpecting(scratch, &ctrl_stack, .i32, .i32, diag);
            },
            .@"i64.eqz",
            .@"i32.wrap_i64",
            => try val_stack.popThenPushExpecting(scratch, &ctrl_stack, .i64, .i32, diag),
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
                try val_stack.popExpecting(&ctrl_stack, .i64, diag);
                try val_stack.popThenPushExpecting(scratch, &ctrl_stack, .i64, .i32, diag);
            },
            .@"f32.eq",
            .@"f32.ne",
            .@"f32.lt",
            .@"f32.gt",
            .@"f32.le",
            .@"f32.ge",
            => {
                try val_stack.popExpecting(&ctrl_stack, .f32, diag);
                try val_stack.popThenPushExpecting(scratch, &ctrl_stack, .f32, .i32, diag);
            },
            .@"f64.eq",
            .@"f64.ne",
            .@"f64.lt",
            .@"f64.gt",
            .@"f64.le",
            .@"f64.ge",
            => {
                try val_stack.popExpecting(&ctrl_stack, .f64, diag);
                try val_stack.popThenPushExpecting(scratch, &ctrl_stack, .f64, .i32, diag);
            },
            .@"i64.clz",
            .@"i64.ctz",
            .@"i64.popcnt",
            .@"i64.extend8_s",
            .@"i64.extend16_s",
            .@"i64.extend32_s",
            => try val_stack.popThenPushExpecting(scratch, &ctrl_stack, .i64, .i64, diag),
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
                try val_stack.popExpecting(&ctrl_stack, .i64, diag);
                try val_stack.popThenPushExpecting(scratch, &ctrl_stack, .i64, .i64, diag);
            },
            .@"f32.abs",
            .@"f32.neg",
            .@"f32.ceil",
            .@"f32.floor",
            .@"f32.trunc",
            .@"f32.nearest",
            .@"f32.sqrt",
            => try val_stack.popThenPushExpecting(scratch, &ctrl_stack, .f32, .f32, diag),
            .@"f32.add",
            .@"f32.sub",
            .@"f32.mul",
            .@"f32.div",
            .@"f32.min",
            .@"f32.max",
            .@"f32.copysign",
            => {
                try val_stack.popExpecting(&ctrl_stack, .f32, diag);
                try val_stack.popThenPushExpecting(scratch, &ctrl_stack, .f32, .f32, diag);
            },
            .@"f64.abs",
            .@"f64.neg",
            .@"f64.ceil",
            .@"f64.floor",
            .@"f64.trunc",
            .@"f64.nearest",
            .@"f64.sqrt",
            => try val_stack.popThenPushExpecting(scratch, &ctrl_stack, .f64, .f64, diag),
            .@"f64.add",
            .@"f64.sub",
            .@"f64.mul",
            .@"f64.div",
            .@"f64.min",
            .@"f64.max",
            .@"f64.copysign",
            => {
                try val_stack.popExpecting(&ctrl_stack, .f64, diag);
                try val_stack.popThenPushExpecting(scratch, &ctrl_stack, .f64, .f64, diag);
            },
            .@"i32.trunc_f32_s",
            .@"i32.trunc_f32_u",
            .@"i32.reinterpret_f32",
            => try val_stack.popThenPushExpecting(scratch, &ctrl_stack, .f32, .i32, diag),
            .@"i32.trunc_f64_s",
            .@"i32.trunc_f64_u",
            => try val_stack.popThenPushExpecting(scratch, &ctrl_stack, .f64, .i32, diag),
            .@"i64.extend_i32_s",
            .@"i64.extend_i32_u",
            => try val_stack.popThenPushExpecting(scratch, &ctrl_stack, .i32, .i64, diag),
            .@"i64.trunc_f32_s",
            .@"i64.trunc_f32_u",
            => try val_stack.popThenPushExpecting(scratch, &ctrl_stack, .f32, .i64, diag),
            .@"i64.trunc_f64_s",
            .@"i64.trunc_f64_u",
            .@"i64.reinterpret_f64",
            => try val_stack.popThenPushExpecting(scratch, &ctrl_stack, .f64, .i64, diag),
            .@"f32.convert_i32_s",
            .@"f32.convert_i32_u",
            .@"f32.reinterpret_i32",
            => try val_stack.popThenPushExpecting(scratch, &ctrl_stack, .i32, .f32, diag),
            .@"f32.convert_i64_s",
            .@"f32.convert_i64_u",
            => try val_stack.popThenPushExpecting(scratch, &ctrl_stack, .i64, .f32, diag),
            .@"f32.demote_f64" => try val_stack.popThenPushExpecting(
                scratch,
                &ctrl_stack,
                .f64,
                .f32,
                diag,
            ),
            .@"f64.convert_i32_s",
            .@"f64.convert_i32_u",
            => try val_stack.popThenPushExpecting(scratch, &ctrl_stack, .i32, .f64, diag),
            .@"f64.convert_i64_s",
            .@"f64.convert_i64_u",
            .@"f64.reinterpret_i64",
            => try val_stack.popThenPushExpecting(scratch, &ctrl_stack, .i64, .f64, diag),
            .@"f64.promote_f32" => try val_stack.popThenPushExpecting(
                scratch,
                &ctrl_stack,
                .f32,
                .f64,
                diag,
            ),

            .@"ref.null" => {
                const ref_type = try ValType.parse(reader, diag);
                if (!ref_type.isRefType()) {
                    return diag.writeAll(.parse, "malformed reference type in ref.null");
                }

                try val_stack.push(scratch, ref_type);
            },
            .@"ref.is_null" => {
                const ref_type = try val_stack.popAny(&ctrl_stack, diag);
                if (!isRefVal(ref_type)) {
                    return diag.print(
                        .validation,
                        "type mismatch: ref.is_null expected reference type, got {t}",
                        .{ref_type},
                    );
                }

                try val_stack.push(scratch, .i32);
            },
            .@"ref.func" => {
                const func_idx = try reader.readIdx(
                    Module.FuncIdx,
                    module.funcTypes().len,
                    diag,
                    &.{ "function", "in ref.func" },
                );

                if (!module.funcIsReferenceable(func_idx)) {
                    return diag.print(
                        .validation,
                        "undeclared function reference {} in ref.func",
                        .{@intFromEnum(func_idx)},
                    );
                }

                try val_stack.push(scratch, ValType.funcref);
            },

            .@"0xFC" => switch (try reader.readUleb128Enum(
                u32,
                opcodes.FCPrefixOpcode,
                diag,
                "0xFC prefixed opcode",
            )) {
                .@"i32.trunc_sat_f32_s",
                .@"i32.trunc_sat_f32_u",
                => try val_stack.popThenPushExpecting(scratch, &ctrl_stack, .f32, .i32, diag),
                .@"i32.trunc_sat_f64_s",
                .@"i32.trunc_sat_f64_u",
                => try val_stack.popThenPushExpecting(scratch, &ctrl_stack, .f64, .i32, diag),
                .@"i64.trunc_sat_f32_s",
                .@"i64.trunc_sat_f32_u",
                => try val_stack.popThenPushExpecting(scratch, &ctrl_stack, .f32, .i64, diag),
                .@"i64.trunc_sat_f64_s",
                .@"i64.trunc_sat_f64_u",
                => try val_stack.popThenPushExpecting(scratch, &ctrl_stack, .f64, .i64, diag),

                .@"memory.init" => {
                    const data_idx = try ReadDataIdx.begin(&reader, diag);
                    try readMemIdx(&reader, module, diag);
                    try data_idx.boundsCheck(module, diag);
                    try val_stack.popManyExpecting(&ctrl_stack, &[_]ValType{.i32} ** 3, diag);
                },
                .@"data.drop" => {
                    try (try ReadDataIdx.begin(&reader, diag)).boundsCheck(module, diag);
                },
                .@"memory.copy" => {
                    try readMemIdx(&reader, module, diag);
                    try readMemIdx(&reader, module, diag);
                    try val_stack.popManyExpecting(&ctrl_stack, &[_]ValType{.i32} ** 3, diag);
                },
                .@"memory.fill" => {
                    try readMemIdx(&reader, module, diag);
                    try val_stack.popManyExpecting(&ctrl_stack, &[_]ValType{.i32} ** 3, diag);
                },

                .@"table.init" => {
                    // const elem_type = try readElemIdx(&reader, module, diag);
                    // Spectests require first checking the table index
                    const elem_idx = try reader.readUleb128(u32, diag, "elemidx in table.init");
                    const table_type = try readTableIdx(&reader, module, diag);
                    const elem_type = if (elem_idx < module.elementSegments().len)
                        module.elementSegments()[elem_idx].elementType()
                    else
                        return diag.print(
                            .validation,
                            "unknown element segment {} in table.init",
                            .{elem_idx},
                        );

                    if (elem_type != table_type) {
                        return diag.print(
                            .validation,
                            "type mismatch: element segment has type {t}, but table has type {t}",
                            .{ elem_type, table_type },
                        );
                    }

                    try val_stack.popManyExpecting(&ctrl_stack, &[_]ValType{.i32} ** 3, diag);
                },
                .@"elem.drop" => _ = try readElemIdx(&reader, module, diag),
                .@"table.copy" => {
                    const dst_type = try readTableIdx(&reader, module, diag);
                    const src_type = try readTableIdx(&reader, module, diag);
                    if (dst_type != src_type) {
                        return diag.print(
                            .validation,
                            "type mismatch: source table type {t} does not match destination " ++
                                "table type {t}",
                            .{ src_type, dst_type },
                        );
                    }

                    try val_stack.popManyExpecting(&ctrl_stack, &[_]ValType{.i32} ** 3, diag);
                },
                .@"table.grow" => {
                    const elem_type = try readTableIdx(&reader, module, diag);
                    try val_stack.popExpecting(&ctrl_stack, .i32, diag);
                    try val_stack.popThenPushExpecting(
                        scratch,
                        &ctrl_stack,
                        elem_type,
                        .i32,
                        diag,
                    );
                },
                .@"table.size" => {
                    _ = try readTableIdx(&reader, module, diag);
                    try val_stack.push(scratch, .i32);
                },
                .@"table.fill" => {
                    const elem_type = try readTableIdx(&reader, module, diag);
                    try val_stack.popManyExpecting(
                        &ctrl_stack,
                        &[3]ValType{ .i32, elem_type, .i32 },
                        diag,
                    );
                },

                // else => |bad| std.debug.panic("TODO: handle 0xFC {s}\n", .{@tagName(bad)}),
            },

            // else => |bad| {
            //     std.debug.panic(
            //         "TODO: handle {s} (0x{X:0>2})\n",
            //         .{ @tagName(bad), @intFromEnum(bad) },
            //     );
            // },
        }
    }

    try reader.expectEnd(diag, "END opcode expected as last byte");

    if (ctrl_stack.len != 0) {
        return diag.writeAll(.parse, "END opcode expected, but control stack was not empty");
    }

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
        .local_values = locals.count - func_type.param_count,
        .side_table_len = @intCast(final_side_table.len),
        .side_table_ptr = final_side_table.ptr,
    };
}

const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const ArenaAllocator = std.heap.ArenaAllocator;
const Module = @import("../Module.zig");
const Reader = @import("Reader.zig");
const Diagnostics = Reader.Diagnostics;
const ValType = Module.ValType;
const opcodes = @import("../opcodes.zig");
