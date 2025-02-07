const std = @import("std");
const Allocator = std.mem.Allocator;
const ArenaAllocator = std.heap.ArenaAllocator;
const IndexedArena = @import("IndexedArena.zig");
const opcodes = @import("opcodes.zig");
const validator = @import("Module/validator.zig");

pub const ValType = @import("Module/val_type.zig").ValType;
pub const FuncType = @import("Module/func_type.zig").FuncType;

pub const TypeIdx = enum(u31) {
    _,

    pub fn funcType(idx: TypeIdx, module: *const Module) *const FuncType {
        return &module.types()[@intFromEnum(idx)];
    }
};

pub const FuncIdx = enum(u31) {
    _,

    pub inline fn signature(idx: FuncIdx, module: *const Module) *const FuncType {
        return module.func_types()[@intFromEnum(idx)];
    }

    pub fn code(idx: FuncIdx, module: *const Module) ?*Code {
        const i = std.math.sub(u32, @intFromEnum(idx), module.inner.func_import_count) catch return null;
        return &module.code()[i];
    }
};

pub const GlobalIdx = enum(u31) { _ };

// A 7-bit index allows parsing a byte instead of a LEB128 index.
pub const TableIdx = enum(u7) { _ };
pub const MemIdx = enum(u7) {
    default = 0,
    _,
};

const Module = @This();

wasm: []const u8,
inner: extern struct {
    types: [*]const FuncType,
    types_count: u32,

    func_count: u32,
    func_types: [*]const *const FuncType, // Using TypeIdx would introduce another indirection

    func_import_count: u32,
    code_count: u32,

    /// Not set if `code_count == 0`.
    code_section: [*]const u8,
    code_entries: [*]Code,

    global_exprs: [*]ConstExpr,
    global_types: [*]const GlobalType,
    table_types: [*]const TableType,
    mem_types: [*]const MemType,
    table_count: u8,
    table_import_count: u8,
    mem_count: u8,
    mem_import_count: u8,
    global_count: u32,
    global_import_count: u32,
    datas_count: packed struct(u32) {
        count: u31,
        has_count_section: bool,
    },

    /// Not set if the total # of imports is zero.
    import_section: [*]const u8,
    func_imports: [*]const ImportName,
    table_imports: [*]const ImportName,
    mem_imports: [*]const ImportName,
    global_imports: [*]const ImportName,

    export_section: [*]const u8,
    exports: [*]align(4) const Export,
    export_count: u32,

    start: Start,
},
custom_sections: []const CustomSection,
arena_data: IndexedArena.ConstData,

pub inline fn customSections(module: *const Module) []const CustomSection {
    return module.custom_sections.items(module.data);
}

pub inline fn types(module: *const Module) []const FuncType {
    return module.inner.types[0..module.inner.types_count];
}

pub inline fn funcTypes(module: *const Module) []const *const FuncType {
    return module.inner.func_types[0..module.inner.func_count];
}

pub inline fn funcTypeIdx(module: *const Module, func: FuncIdx) TypeIdx {
    const func_idx: @typeInfo(FuncIdx).@"enum".tag_type = @intFromEnum(func);
    std.debug.assert(func_idx < module.inner.func_count);

    const type_ptr = @intFromPtr(@as(*const FuncType, module.funcTypes()[func_idx]));
    std.debug.assert(type_ptr < @intFromPtr(@as(*const FuncType, &module.inner.types[module.inner.types_count])));
    return @enumFromInt((type_ptr - @intFromPtr(module.inner.types)) / @sizeOf(FuncType));
}

pub inline fn funcImportNames(module: *const Module) []const ImportName {
    return module.inner.func_imports[0..module.inner.func_import_count];
}

pub inline fn funcImportTypes(module: *const Module) []const *const FuncType {
    return module.funcTypes()[0..module.inner.func_import_count];
}

pub inline fn tableTypes(module: *const Module) []const TableType {
    return module.inner.table_types[0..module.inner.table_count];
}

pub inline fn tableImportNames(module: *const Module) []const ImportName {
    return module.inner.table_imports[0..module.inner.table_import_count];
}

pub inline fn tableImportTypes(module: *const Module) []const TableType {
    return module.tableTypes()[0..module.inner.table_import_count];
}

pub inline fn memTypes(module: *const Module) []const MemType {
    return module.inner.mem_types[0..module.inner.mem_count];
}

pub inline fn memImportNames(module: *const Module) []const ImportName {
    return module.inner.mem_imports[0..module.inner.mem_import_count];
}

pub inline fn memImportTypes(module: *const Module) []const MemType {
    return module.memTypes()[0..module.inner.mem_import_count];
}

pub fn globalTypes(module: *const Module) []const GlobalType {
    return module.inner.global_types[0..module.inner.global_count];
}

pub inline fn globalImportNames(module: *const Module) []const ImportName {
    return module.inner.global_imports[0..module.inner.global_import_count];
}

pub inline fn globalImportTypes(module: *const Module) []const GlobalType {
    return module.globalTypes()[0..module.inner.global_import_count];
}

pub inline fn code(module: *const Module) []Code {
    return module.inner.code_entries[0..module.inner.code_count];
}

pub inline fn exports(module: *const Module) []align(4) const Export {
    return module.inner.exports[0..module.inner.export_count];
}

pub const Start = packed struct(u32) {
    exists: bool = false,
    idx: FuncIdx = undefined,

    pub const none = Start{ .exists = false, .idx = @enumFromInt(0) };

    fn init(idx: ?FuncIdx) Start {
        return .{
            .exists = idx != null,
            .idx = idx orelse undefined,
        };
    }

    pub fn get(start: Start) ?FuncIdx {
        return if (start.exists) start.idx else null;
    }
};

pub const WasmSlice = extern struct {
    offset: u32,
    size: u32,

    pub fn slice(s: WasmSlice, base: [*]const u8, bounds: []const u8) []const u8 {
        const calculated = base[s.offset .. s.offset + s.size];
        std.debug.assert(@intFromPtr(calculated.ptr) + calculated.len <= @intFromPtr(bounds.ptr) + bounds.len);
        return calculated;
    }
};

pub const ImportName = struct {
    name_offset: u16,
    name_size: u16,

    module_offset: u16,
    module_size: u16,

    pub inline fn desc_name(self: ImportName, module: *const Module) std.unicode.Utf8View {
        const name_slice = WasmSlice{ .offset = self.name_offset, .size = self.name_size };
        return .{ .bytes = name_slice.slice(module.inner.import_section, module.wasm) };
    }

    pub inline fn module_name(self: ImportName, module: *const Module) std.unicode.Utf8View {
        const name_slice = WasmSlice{ .offset = self.module_offset, .size = self.module_size };
        return .{ .bytes = name_slice.slice(module.inner.import_section, module.wasm) };
    }
};

pub const Export = packed struct(u64) {
    desc: Desc,
    desc_tag: std.meta.FieldEnum(Desc),
    name_size: u15,
    name_offset: u16,

    pub const Desc = packed union {
        func: FuncIdx,
        table: TableIdx,
        mem: MemIdx,
        global: GlobalIdx,
    };

    pub inline fn name(self: Export, module: *const Module) std.unicode.Utf8View {
        const name_slice = WasmSlice{ .offset = self.name_offset, .size = self.name_size };
        const bytes = name_slice.slice(module.inner.export_section, module.wasm);
        return switch (@import("builtin").mode) {
            .Debug, .ReleaseSafe => std.unicode.Utf8View.init(bytes) catch unreachable,
            .ReleaseFast, .ReleaseSmall => .{ .bytes = name_slice.slice(module.inner.export_section, module.wasm) },
        };
    }
};

pub const Limits = extern struct {
    min: usize,
    max: usize,

    pub inline fn matches(a: *const Limits, b: *const Limits) bool {
        return a.min >= b.min and a.max <= b.max;
    }
};

pub const TableType = extern struct {
    /// Until a `RefType` type is added, it is an invariant that `element_type.isRefType()`.
    elem_type: ValType,
    /// The minimum and maximum number of elements.
    limits: Limits,
    // flags: packed struct { index_type: IndexType, },

    pub fn matches(a: *const TableType, b: *const TableType) bool {
        return a.limits.matches(&b.limits) and a.elem_type.eql(b.elem_type);
    }
};

pub const MemType = extern struct {
    /// The minimum and maximum number of pages.
    limits: Limits,
    // flags: packed struct(u32) {
    //     log2_page_size: u5 = std.math.log2_int(u17, 65536),
    //     // index_type: IndexType,
    //     padding: u27 = 0,
    // } = .{},

    pub fn matches(a: *const MemType, b: *const MemType) bool {
        return a.limits.matches(&b.limits);
    }
};

pub const GlobalType = extern struct {
    val_type: ValType,
    mut: Mut,

    pub const Mut = enum(u8) {
        @"const" = 0,
        @"var" = 1,
    };

    pub inline fn isVar(ty: *const GlobalType) bool {
        return switch (ty.mut) {
            .@"const" => false,
            .@"var" => true,
        };
    }

    pub fn matches(a: *const GlobalType, b: *const GlobalType) bool {
        return a.val_type.eql(b.val_type) and a.mut == b.mut;
    }
};

pub const Code = struct {
    contents: WasmSlice,
    state: validator.State = .{},

    pub const SideTableEntry = validator.SideTableEntry;
    pub const Ip = validator.Ip;
    pub const End = validator.End;
};

pub const ConstExpr = union(enum) {
    i32_or_f32: u32,
    i64_or_f64: IndexedArena.Idx(u64),
    @"ref.null": ValType,
    @"ref.func": FuncIdx,
    @"global.get": GlobalIdx,

    comptime {
        std.debug.assert(@sizeOf(ConstExpr) == 8);
    }
};

pub const CustomSection = struct {
    name_ptr: [*]const u8,
    name_len: u32,
    contents_ptr: [*]const u8,
    contents_len: u32,

    comptime {
        std.debug.assert(@sizeOf(CustomSection) <= 24);
    }

    pub inline fn name(sec: *CustomSection) std.unicode.Utf8View {
        return .{ .bytes = sec.name_ptr[0..sec.name_len] };
    }

    pub inline fn contents(sec: *CustomSection) []const u8 {
        return sec.contents_ptr[0..sec.contents_len];
    }
};

const wasm_preamble = "\x00asm\x01\x00\x00\x00";

const ImportExportDesc = enum(u8) {
    func = 0,
    table = 1,
    mem = 2,
    global = 3,
};

pub const NoEofError = error{EndOfStream};

pub const ReaderError = error{
    /// An error occurred while parsing the WebAssembly module.
    MalformedWasm,
} || NoEofError;

pub const LimitError = error{
    /// See <https://webassembly.github.io/spec/core/appendix/implementation.html>.
    WasmImplementationLimit,
};

pub const ParseError = error{
    /// The input did not start with the WebAssembly preamble.
    NotWasm,
    InvalidWasm,
} || ReaderError || LimitError || Allocator.Error;

pub const Reader = struct {
    bytes: *[]const u8,

    const Error = ReaderError;

    pub fn init(bytes: *[]const u8) Reader {
        return .{ .bytes = bytes };
    }

    pub fn isEmpty(reader: Reader) bool {
        return reader.bytes.len == 0;
    }

    pub fn expectEndOfStream(reader: Reader) ReaderError!void {
        if (!reader.isEmpty()) return error.MalformedWasm;
    }

    pub fn readAssumeLength(reader: Reader, len: usize) []const u8 {
        const skipped = reader.bytes.*[0..len];
        reader.bytes.* = reader.bytes.*[len..];
        return skipped;
    }

    pub fn read(reader: Reader, len: usize) NoEofError![]const u8 {
        if (reader.bytes.len < len) return error.EndOfStream;
        return reader.readAssumeLength(len);
    }

    pub fn readArray(reader: Reader, comptime len: usize) NoEofError!*const [len]u8 {
        const s = try reader.read(len);
        return s[0..len];
    }

    pub fn readByte(reader: Reader) NoEofError!u8 {
        if (reader.isEmpty()) return error.EndOfStream;
        return (try reader.readArray(1))[0];
    }

    pub fn readByteTag(reader: Reader, comptime Tag: type) Error!Tag {
        comptime {
            std.debug.assert(@bitSizeOf(@typeInfo(Tag).@"enum".tag_type) <= 8);
        }

        return std.meta.intToEnum(Tag, try reader.readByte()) catch |e| switch (e) {
            std.meta.IntToEnumError.InvalidEnumTag => return error.MalformedWasm,
        };
    }

    pub fn readUleb128(reader: Reader, comptime T: type) Error!T {
        return std.leb.readUleb128(T, reader) catch |e| switch (e) {
            error.Overflow => ReaderError.MalformedWasm,
            NoEofError.EndOfStream => |eof| eof,
        };
    }

    pub fn readUleb128Casted(reader: Reader, comptime T: type, comptime U: type) (Error || LimitError)!U {
        comptime std.debug.assert(@bitSizeOf(U) < @bitSizeOf(T));
        return std.math.cast(U, try reader.readUleb128(T)) orelse LimitError.WasmImplementationLimit;
    }

    pub fn readUleb128Enum(reader: Reader, comptime T: type, comptime E: type) Error!E {
        return std.meta.intToEnum(E, try reader.readUleb128(T)) catch |e| switch (e) {
            std.meta.IntToEnumError.InvalidEnumTag => return error.MalformedWasm,
        };
    }

    pub fn readIleb128(reader: Reader, comptime T: type) Error!T {
        return std.leb.readIleb128(T, reader) catch |e| switch (e) {
            error.Overflow => ReaderError.MalformedWasm,
            NoEofError.EndOfStream => |eof| eof,
        };
    }

    pub fn readByteVec(reader: Reader) Error![]const u8 {
        const len = try reader.readUleb128(u32);
        return reader.read(len);
    }

    pub fn readName(reader: Reader) Error!std.unicode.Utf8View {
        const contents = try reader.readByteVec();
        return if (std.unicode.utf8ValidateSlice(contents))
            .{ .bytes = contents }
        else
            error.MalformedWasm;
    }

    pub fn readValType(reader: Reader) Error!ValType {
        // Code has to change if ValType becomes a pointer to support typed function references/GC proposal.
        comptime std.debug.assert(@typeInfo(ValType).@"enum".tag_type == u8);

        return reader.readByteTag(ValType);
    }

    fn readLimits(reader: Reader) ParseError!Limits {
        const LimitsFlag = enum(u8) {
            no_maximum = 0x00,
            has_maximum = 0x01,
        };

        const flag = try reader.readByteTag(LimitsFlag);

        // When 64-bit memories are supported, parsed type needs to conditionally change to u64.
        const min = try reader.readUleb128(u32);
        const max: u32 = switch (flag) {
            .no_maximum => std.math.maxInt(u32),
            .has_maximum => try reader.readUleb128(u32),
        };

        return if (min <= max)
            .{ .min = min, .max = max }
        else
            error.InvalidWasm;
    }

    fn readTableType(reader: Reader) ParseError!TableType {
        const elem_type = try reader.readValType();
        if (!elem_type.isRefType()) return error.MalformedWasm;
        return .{
            .elem_type = elem_type,
            .limits = try reader.readLimits(),
        };
    }

    fn readMemType(reader: Reader) ParseError!MemType {
        const limits = try reader.readLimits();
        return .{ .limits = limits };
    }

    fn readGlobalType(reader: Reader) Error!GlobalType {
        const val_type = try reader.readValType();
        return .{
            .val_type = val_type,
            .mut = try reader.readByteTag(GlobalType.Mut),
        };
    }

    pub fn readIdx(reader: Reader, comptime I: type, bounds: anytype) ParseError!I {
        const idx = try reader.readUleb128(u32);
        const len = switch (@typeInfo(@TypeOf(bounds))) {
            .@"struct" => bounds.len,
            .int => bounds,
            else => unreachable,
        };

        return if (idx < len)
            @enumFromInt(std.math.cast(@typeInfo(I).@"enum".tag_type, idx) orelse return error.WasmImplementationLimit)
        else
            error.InvalidWasm;
    }

    fn readConstExpr(
        reader: Reader,
        expected_type: ValType,
        func_count: u32,
        /// Should refer to global imports only.
        global_types: IndexedArena.Slice(GlobalType),
        arena: *IndexedArena,
    ) ParseError!ConstExpr {
        const const_opcode = try reader.readByteTag(opcodes.ByteOpcode);
        const expr: ConstExpr = expr: switch (const_opcode) {
            .@"i32.const" => {
                if (!expected_type.eql(ValType.i32)) return error.InvalidWasm;
                break :expr .{ .i32_or_f32 = @bitCast(try reader.readIleb128(i32)) };
            },
            .@"f32.const" => {
                if (!expected_type.eql(ValType.f32)) return error.InvalidWasm;
                break :expr .{ .i32_or_f32 = std.mem.readInt(u32, try reader.readArray(4), .little) };
            },
            .@"i64.const" => {
                const n = try arena.create(u64);
                n.set(arena, @bitCast(try reader.readIleb128(i64)));
                break :expr .{ .i64_or_f64 = n };
            },
            .@"f64.const" => {
                const n = try arena.create(u64);
                n.set(arena, std.mem.readInt(u64, try reader.readArray(8), .little));
                break :expr .{ .i64_or_f64 = n };
            },
            .@"ref.null" => .{ .@"ref.null" = expected_type },
            .@"ref.func" => .{ .@"ref.func" = try reader.readIdx(FuncIdx, func_count) },
            .@"global.get" => {
                const global_idx = try reader.readIdx(GlobalIdx, global_types);
                const actual_type: *const GlobalType = global_types.ptrAt(@intFromEnum(global_idx), arena);
                if (!actual_type.val_type.eql(expected_type) or actual_type.isVar())
                    return error.InvalidWasm;

                break :expr .{ .@"global.get" = global_idx };
            },
            else => return ParseError.InvalidWasm,
        };

        const end_opcode = try reader.readByteTag(opcodes.ByteOpcode);
        if (end_opcode != .end) return ParseError.InvalidWasm;

        return expr;
    }
};

pub const ParseOptions = struct {
    /// If true, module data is initially allocated in a scratch allocator as it is resized.
    ///
    /// This reduces the final memory usage at the cost of doubling the peak memory usage. Setting this
    /// option is useful when parsing many modules, as the scratch allocator allows reusing memory
    /// needed while parsing.
    realloc_contents: bool = false,
    keep_custom_sections: bool = false,
};

pub fn parse(
    gpa: Allocator,
    wasm: *[]const u8,
    alloca: *ArenaAllocator,
    rng: std.Random,
    options: ParseOptions,
) ParseError!Module {
    const original_wasm = wasm.*;

    // Allocations that live for the rest of this function call.
    _ = alloca.reset(.retain_capacity);

    if (!std.mem.startsWith(u8, wasm.*, wasm_preamble))
        return ParseError.NotWasm;

    var wasm_reader = Reader.init(wasm);
    _ = try wasm_reader.readArray(wasm_preamble.len);

    const SectionId = enum(u8) {
        type = 1,
        import = 2,
        func = 3,
        table = 4,
        mem = 5,
        global = 6,
        @"export" = 7,
        start = 8,
        elem = 9,
        data_count = 12,
        code = 10,
        data = 11,
        custom = 0,
    };

    const SectionOrder: type = comptime order: {
        var fields: [@typeInfo(SectionId).@"enum".fields.len + 1]std.builtin.Type.EnumField = undefined;
        fields[0] = .{ .name = "any", .value = 0 };
        for (@typeInfo(SectionId).@"enum".fields, 1..) |f, i| {
            fields[i] = .{ .name = f.name, .value = i };
        }

        break :order @Type(.{
            .@"enum" = std.builtin.Type.Enum{
                .tag_type = std.math.IntFittingRange(0, fields.len),
                .is_exhaustive = true,
                .decls = &[0]std.builtin.Type.Declaration{},
                .fields = &fields,
            },
        });
    };

    const KnownSections: type = @Type(.{
        .@"struct" = std.builtin.Type.Struct{
            .layout = .auto,
            .decls = &[0]std.builtin.Type.Declaration{},
            .is_tuple = false,
            .fields = comptime fields: {
                const empty: []const u8 = &[0]u8{};
                var fields: [@typeInfo(SectionId).@"enum".fields.len - 1]std.builtin.Type.StructField = undefined;
                for (@typeInfo(SectionId).@"enum".fields[0..fields.len], 0..) |f, i| {
                    std.debug.assert(!std.mem.eql(u8, f.name, "custom"));
                    fields[i] = std.builtin.Type.StructField{
                        .name = f.name,
                        .type = []const u8,
                        .default_value_ptr = @ptrCast(@as(*const []const u8, &empty)),
                        .is_comptime = false,
                        .alignment = 0,
                    };
                }
                break :fields &fields;
            },
        },
    });

    var section_order = SectionOrder.any;
    var known_sections = KnownSections{};

    var scratch = ArenaAllocator.init(alloca.allocator());
    defer scratch.deinit();

    var custom_sections_buf = std.SegmentedList(CustomSection, 1){}; // in `scratch`

    while (@as(?u8, wasm_reader.readByte() catch null)) |id_byte| {
        const id = std.meta.intToEnum(SectionId, id_byte) catch |e| switch (e) {
            std.meta.IntToEnumError.InvalidEnumTag => return error.MalformedWasm,
        };

        const section_contents = try wasm_reader.readByteVec();

        switch (id) {
            .custom => {
                var custom_sec_contents = section_contents;
                errdefer wasm.* = custom_sec_contents;
                const custom_sec = Reader.init(&custom_sec_contents);
                const section_name = try custom_sec.readName();

                if (options.keep_custom_sections)
                    try custom_sections_buf.append(
                        scratch.allocator(),
                        CustomSection{
                            .name_ptr = section_name.bytes.ptr,
                            .name_len = @intCast(section_name.bytes.len),
                            .contents_ptr = custom_sec_contents.ptr,
                            .contents_len = @intCast(custom_sec_contents.len),
                        },
                    );
            },
            inline else => |known_id| {
                if (@intFromEnum(section_order) >= @intFromEnum(@field(SectionOrder, @tagName(known_id)))) {
                    return error.MalformedWasm;
                }

                section_order = @enumFromInt(@intFromEnum(section_order) + 1);
                @field(known_sections, @tagName(known_id)) = section_contents;
            },
        }
    }

    std.debug.assert(wasm_reader.isEmpty());
    wasm_reader = undefined;

    var arena = IndexedArena.init(if (options.realloc_contents) alloca.allocator() else gpa);
    defer arena.deinit();

    const custom_sections = try arena.dupeSegmentedList(CustomSection, 1, &custom_sections_buf);
    custom_sections_buf = undefined;

    const TypeSecEntry = extern union {
        fixup: extern struct {
            types: packed struct(u32) {
                idx: IndexedArena.Idx(ValType),
                padding: u1 = 0,
            },
            param_count: u16,
            result_count: u16,
        },
        final: FuncType,
    };

    const type_sec: IndexedArena.Slice(TypeSecEntry) = if (known_sections.type.len > 0) types: {
        const type_reader = Reader.init(&known_sections.type);
        errdefer wasm.* = type_reader.bytes.*;
        const type_len = try type_reader.readUleb128(u32);
        const type_sec = try arena.alloc(TypeSecEntry, type_len);
        // Can't iterate over slice as result type slices must be allocated
        for (0..type_len) |type_i| {
            _ = scratch.reset(.retain_capacity);

            _ = try type_reader.readByteTag(enum(u8) { func = 0x60 });

            const param_count = try type_reader.readUleb128Casted(u32, u16);
            const param_types = try scratch.allocator().alloc(ValType, param_count);
            for (param_types) |*param_ty| {
                param_ty.* = try type_reader.readValType();
            }

            const result_count = try type_reader.readUleb128Casted(u32, u16);
            const types_buf = try arena.alloc(ValType, param_count + result_count);
            @memcpy(types_buf.items(&arena)[0..param_count], param_types);

            for (param_count..(param_count + result_count)) |result_i| {
                types_buf.setAt(result_i, &arena, try type_reader.readValType());
            }

            type_sec.setAt(
                type_i,
                &arena,
                TypeSecEntry{
                    .fixup = .{
                        .types = .{ .idx = types_buf.idx },
                        .param_count = param_count,
                        .result_count = result_count,
                    },
                },
            );
        }

        try type_reader.expectEndOfStream();
        known_sections.type = undefined;
        break :types type_sec;
    } else .empty;

    const definition = struct {
        fn Class(comptime T: type) type {
            return extern union {
                fixup: packed struct(u32) {
                    idx: IndexedArena.Idx(T),
                    padding: u1 = 0,
                },
                final: *const T,
            };
        }
    };

    const FuncSecEntry = definition.Class(FuncType);

    // Allocated in `alloca`.
    var func_import_types = std.SegmentedList(FuncSecEntry, 8){};
    var table_import_types = std.SegmentedList(TableType, 1){};
    var mem_import_types = std.SegmentedList(MemType, 1){};
    var global_import_types = std.SegmentedList(GlobalType, 4){};

    const ImportSec = struct {
        start: [*]const u8 = undefined,
        funcs: IndexedArena.Slice(ImportName) = .empty,
        tables: IndexedArena.Slice(ImportName) = .empty,
        mems: IndexedArena.Slice(ImportName) = .empty,
        globals: IndexedArena.Slice(ImportName) = .empty,
    };

    const import_sec: ImportSec = if (known_sections.import.len > 0) imports: {
        const import_reader = Reader.init(&known_sections.import);
        errdefer wasm.* = import_reader.bytes.*;
        const import_len = try import_reader.readUleb128(u32);
        const imports_start = import_reader.bytes.*.ptr;

        // Allocated in `scratch`.
        var func_imports = std.SegmentedList(ImportName, 8){};
        var table_imports = std.SegmentedList(ImportName, 1){};
        var mem_imports = std.SegmentedList(ImportName, 1){};
        var global_imports = std.SegmentedList(ImportName, 4){};

        // Reserve space for all of the names.
        {
            _ = scratch.reset(.retain_capacity);
            _ = try scratch.allocator().alloc(
                ImportName,
                std.math.add(usize, import_len, import_len / 2) catch return error.OutOfMemory,
            );
            _ = scratch.reset(.retain_capacity);
        }

        for (0..import_len) |_| {
            const mod = try import_reader.readName();
            const name = try import_reader.readName();
            const import_name = ImportName{
                .module_offset = std.math.cast(u16, @intFromPtr(mod.bytes.ptr) - @intFromPtr(imports_start)) orelse
                    return error.WasmImplementationLimit,
                .module_size = std.math.cast(u16, mod.bytes.len) orelse
                    return error.WasmImplementationLimit,

                .name_offset = std.math.cast(u16, @intFromPtr(name.bytes.ptr) - @intFromPtr(imports_start)) orelse
                    return error.WasmImplementationLimit,
                .name_size = std.math.cast(u16, name.bytes.len) orelse
                    return error.WasmImplementationLimit,
            };

            switch (try import_reader.readByteTag(ImportExportDesc)) {
                .func => {
                    try func_imports.append(scratch.allocator(), import_name);

                    const type_idx = try import_reader.readIdx(TypeIdx, type_sec);
                    const type_ptr = type_sec.at(@intFromEnum(type_idx));
                    try func_import_types.append(
                        scratch.allocator(),
                        .{ .fixup = .{ .idx = type_ptr.ptrCast(FuncType) } },
                    );
                },
                .table => {
                    try table_imports.append(scratch.allocator(), import_name);
                    try table_import_types.append(
                        scratch.allocator(),
                        try import_reader.readTableType(),
                    );
                },
                .mem => {
                    try mem_imports.append(scratch.allocator(), import_name);
                    try mem_import_types.append(
                        scratch.allocator(),
                        try import_reader.readMemType(),
                    );
                },
                .global => {
                    try global_imports.append(scratch.allocator(), import_name);
                    try global_import_types.append(
                        scratch.allocator(),
                        try import_reader.readGlobalType(),
                    );
                },
            }
        }

        try import_reader.expectEndOfStream();
        known_sections.import = undefined;

        // Detect if code above accidentally added to the wrong name list.
        std.debug.assert(func_import_types.len == func_imports.len);
        std.debug.assert(table_import_types.len == table_imports.len);
        std.debug.assert(mem_import_types.len == mem_imports.len);
        std.debug.assert(global_import_types.len == global_imports.len);

        break :imports ImportSec{
            .start = imports_start,
            .funcs = try arena.dupeSegmentedList(ImportName, 8, &func_imports),
            .tables = try arena.dupeSegmentedList(ImportName, 1, &table_imports),
            .mems = try arena.dupeSegmentedList(ImportName, 1, &mem_imports),
            .globals = try arena.dupeSegmentedList(ImportName, 4, &global_imports),
        };
    } else .{};

    const func_types: IndexedArena.Slice(FuncSecEntry) = if (known_sections.func.len > 0) funcs: {
        const func_reader = Reader.init(&known_sections.func);
        errdefer wasm.* = func_reader.bytes.*;

        const func_len = try func_reader.readUleb128(u32);
        const func_import_len: u32 = @intCast(func_import_types.len);

        const func_types = try arena.alloc(
            FuncSecEntry,
            std.math.add(u32, func_import_len, func_len) catch return error.InvalidWasm,
        );

        if (func_types.len > std.math.maxInt(@typeInfo(FuncIdx).@"enum".tag_type))
            return error.WasmImplementationLimit;

        const func_types_dst: []FuncSecEntry = func_types.items(&arena);

        // Cannot use `alloca` until this runs.
        func_import_types.writeToSlice(func_types_dst[0..func_import_len], 0);

        for (func_types_dst[func_import_len..]) |*f| {
            const type_idx = try func_reader.readIdx(TypeIdx, type_sec);
            f.* = FuncSecEntry{
                .fixup = .{ .idx = (type_sec.at(@intFromEnum(type_idx))).ptrCast(FuncType) },
            };
        }

        try func_reader.expectEndOfStream();
        known_sections.func = undefined;
        break :funcs func_types;
    } else try arena.dupeSegmentedList(FuncSecEntry, 8, &func_import_types);

    std.debug.assert(func_types.len >= func_import_types.len);
    func_import_types = undefined;

    const table_types: IndexedArena.Slice(TableType) = if (known_sections.table.len > 0) tables: {
        const table_reader = Reader.init(&known_sections.table);
        errdefer wasm.* = table_reader.bytes.*;

        const table_len = try table_reader.readUleb128(u32);
        const table_import_len: u32 = @intCast(table_import_types.len);

        const table_types = try arena.alloc(
            TableType,
            std.math.add(u32, table_import_len, table_len) catch return error.InvalidWasm,
        );

        if (table_types.len > std.math.maxInt(@typeInfo(TableIdx).@"enum".tag_type))
            return error.WasmImplementationLimit;

        const table_types_dst: []TableType = table_types.items(&arena);

        // Cannot use `alloca` until this runs.
        table_import_types.writeToSlice(table_types_dst[0..table_import_len], 0);

        for (table_types_dst[table_import_len..]) |*tt|
            tt.* = try table_reader.readTableType();

        try table_reader.expectEndOfStream();
        known_sections.table = undefined;
        break :tables table_types;
    } else try arena.dupeSegmentedList(TableType, 1, &table_import_types);

    std.debug.assert(table_types.len >= table_import_types.len);
    table_import_types = undefined;

    const mem_types: IndexedArena.Slice(MemType) = if (known_sections.mem.len > 0) mems: {
        const mem_reader = Reader.init(&known_sections.mem);
        errdefer wasm.* = mem_reader.bytes.*;

        const mem_len = try mem_reader.readUleb128(u32);
        const mem_import_len: u32 = @intCast(mem_import_types.len);

        const mem_types = try arena.alloc(
            MemType,
            std.math.add(u32, mem_import_len, mem_len) catch return error.InvalidWasm,
        );

        // std.math.maxInt(@typeInfo(MemIdx).@"enum".tag_type)
        if (mem_types.len > 1) return error.WasmImplementationLimit; // Pending multi-memory support.

        const mem_types_dst: []MemType = mem_types.items(&arena);

        // Cannot use `alloca` until this runs.
        mem_import_types.writeToSlice(mem_types_dst[0..mem_import_len], 0);

        for (mem_types_dst[mem_import_len..]) |*mem|
            mem.* = try mem_reader.readMemType();

        try mem_reader.expectEndOfStream();
        known_sections.mem = undefined;
        break :mems mem_types;
    } else try arena.dupeSegmentedList(MemType, 1, &mem_import_types);

    std.debug.assert(mem_types.len >= mem_import_types.len);
    mem_import_types = undefined;

    const GlobalSec = struct {
        types: IndexedArena.Slice(GlobalType),
        exprs: IndexedArena.Slice(ConstExpr),
    };

    const global_sec: GlobalSec = if (known_sections.global.len > 0) globals: {
        const global_reader = Reader.init(&known_sections.global);
        errdefer wasm.* = global_reader.bytes.*;

        const global_len = try global_reader.readUleb128(u32);
        const global_import_len: u32 = @intCast(global_import_types.len);

        const globals = GlobalSec{
            .types = try arena.alloc(
                GlobalType,
                std.math.add(u32, global_import_len, global_len) catch return error.InvalidWasm,
            ),
            .exprs = try arena.alloc(ConstExpr, global_len),
        };

        if (globals.types.len > std.math.maxInt(@typeInfo(GlobalIdx).@"enum".tag_type))
            return error.WasmImplementationLimit;

        const import_types_slice = globals.types.slice(0, global_import_len);
        global_import_types.writeToSlice(import_types_slice.items(&arena), 0);

        for (0..global_len) |i| {
            const ty = try global_reader.readGlobalType();
            const expr = try global_reader.readConstExpr(
                ty.val_type,
                func_types.len,
                globals.types.slice(0, global_import_len),
                &arena,
            );

            globals.types.setAt(i, &arena, ty);
            globals.exprs.setAt(i, &arena, expr);
        }

        try global_reader.expectEndOfStream();
        known_sections.global = undefined;
        break :globals globals;
    } else GlobalSec{
        .types = try arena.dupeSegmentedList(GlobalType, 4, &global_import_types),
        .exprs = .empty,
    };

    std.debug.assert(global_sec.types.len >= global_import_types.len);
    std.debug.assert(global_sec.types.len >= global_sec.exprs.len);
    global_import_types = undefined;

    const ExportSec = struct {
        start: [*]const u8 = undefined,
        descs: IndexedArena.SliceAligned(Export, 4) = .empty,
    };

    const export_sec: ExportSec = if (known_sections.@"export".len > 0) exports: {
        const export_reader = Reader.init(&known_sections.@"export");
        errdefer wasm.* = export_reader.bytes.*;
        const export_len = try export_reader.readUleb128(u32);
        const export_sec = ExportSec{
            .start = export_reader.bytes.*.ptr,
            .descs = try arena.alignedAlloc(Export, 4, export_len),
        };

        const ExportDedupContext = struct {
            seed: u64,

            pub fn eql(_: @This(), a: []const u8, b: []const u8) bool {
                return std.mem.eql(u8, a, b);
            }

            pub fn hash(ctx: @This(), name: []const u8) u64 {
                return std.hash.Wyhash.hash(ctx.seed, name);
            }
        };

        var export_dedup = std.HashMapUnmanaged(
            []const u8,
            void,
            ExportDedupContext,
            std.hash_map.default_max_load_percentage,
        ).empty;

        const export_dedup_context = ExportDedupContext{ .seed = rng.int(u64) };

        _ = scratch.reset(.retain_capacity);
        comptime std.debug.assert(std.hash_map.default_max_load_percentage > 75);
        try export_dedup.ensureTotalCapacityContext(
            scratch.allocator(),
            // Prevent regrowth even with high load factor.
            std.math.add(u32, export_len, export_len / 4) catch return error.OutOfMemory,
            export_dedup_context,
        );

        for (export_sec.descs.items(&arena)) |*ex| {
            const name = try export_reader.readName();
            if (export_dedup.getOrPutAssumeCapacityContext(name.bytes, export_dedup_context).found_existing)
                return ParseError.InvalidWasm;

            const tag = try export_reader.readByteTag(ImportExportDesc);

            ex.* = Export{
                .name_size = std.math.cast(u15, name.bytes.len) orelse
                    return error.WasmImplementationLimit,
                .name_offset = std.math.cast(u16, @intFromPtr(name.bytes.ptr) - @intFromPtr(export_sec.start)) orelse
                    return error.WasmImplementationLimit,
                .desc_tag = switch (tag) {
                    inline else => |desc_tag| @field(
                        std.meta.FieldEnum(Export.Desc),
                        @tagName(desc_tag),
                    ),
                },
                .desc = switch (tag) {
                    .func => .{ .func = try export_reader.readIdx(FuncIdx, func_types) },
                    .table => .{ .table = try export_reader.readIdx(TableIdx, table_types) },
                    .mem => .{ .mem = try export_reader.readIdx(MemIdx, mem_types) },
                    .global => .{ .global = try export_reader.readIdx(GlobalIdx, global_sec.types) },
                },
            };
        }

        try export_reader.expectEndOfStream();
        known_sections.@"export" = undefined;
        break :exports export_sec;
    } else .{};

    const start: Start = if (known_sections.start.len > 0) start: {
        const start_reader = Reader.init(&known_sections.start);
        errdefer wasm.* = start_reader.bytes.*;

        const func_idx = try start_reader.readIdx(FuncIdx, func_types);

        try start_reader.expectEndOfStream();
        known_sections.start = undefined;

        break :start Start.init(func_idx);
    } else .none;

    const CodeSec = struct {
        start: [*]const u8 = undefined,
        entries: IndexedArena.Slice(Code) = .empty,
    };

    const defined_func_count = func_types.len - import_sec.funcs.len;
    const code_sec: CodeSec = if (known_sections.code.len > 0) code: {
        const code_reader = Reader.init(&known_sections.code);
        errdefer wasm.* = code_reader.bytes.*;

        const code_len = try code_reader.readUleb128(u32);
        if (code_len != defined_func_count) {
            // std.debug.print("expected {} but got {}\n", .{ defined_func_count, code_len });
            return error.MalformedWasm;
        }

        const code_sec = CodeSec{
            .start = code_reader.bytes.*.ptr,
            .entries = try arena.alloc(Code, code_len),
        };

        for (code_sec.entries.items(&arena)) |*code_entry| {
            const contents = try code_reader.readByteVec();
            code_entry.* = Code{
                .contents = .{
                    .size = @intCast(contents.len),
                    .offset = @intCast(@intFromPtr(contents.ptr) - @intFromPtr(code_sec.start)),
                },
            };
        }

        try code_reader.expectEndOfStream();
        known_sections.code = undefined;
        break :code code_sec;
    } else if (defined_func_count > 0) return error.MalformedWasm else .{};

    const arena_data = if (options.realloc_contents) realloc: {
        const src = arena.data.items;
        const dupe = try gpa.alignedAlloc(IndexedArena.Word, IndexedArena.max_alignment, src.len);
        @memcpy(dupe, src);
        break :realloc dupe;
    } else contents: {
        const desired_len = arena.data.items.len;
        if (gpa.resize(arena.data.allocatedSlice(), desired_len)) {
            arena.data.capacity = desired_len;
        } else {
            arena.data.expandToCapacity();
        }

        break :contents arena.data.toOwnedSlice() catch unreachable;
    };

    errdefer comptime unreachable;

    for (type_sec.items(arena_data)) |*ty| {
        const fixup = ty.*.fixup;
        const type_slice = IndexedArena.Slice(ValType){
            .idx = fixup.types.idx,
            .len = fixup.param_count + fixup.result_count,
        };

        ty.* = TypeSecEntry{
            .final = FuncType{
                .types = type_slice.items(arena_data).ptr,
                .param_count = fixup.param_count,
                .result_count = fixup.result_count,
            },
        };
    }

    for (func_types.items(arena_data)) |*ty| {
        const func_type_idx: IndexedArena.Idx(FuncType) = ty.*.fixup.idx;
        ty.* = FuncSecEntry{ .final = func_type_idx.getPtr(arena_data) };
    }

    return Module{
        .wasm = original_wasm,
        .arena_data = arena_data,
        .inner = .{
            .types = @ptrCast(type_sec.items(arena_data)),
            .types_count = type_sec.len,

            .func_types = @ptrCast(func_types.items(arena_data)),
            .func_count = func_types.len,

            .code_section = code_sec.start,
            .code_entries = @ptrCast(code_sec.entries.items(arena_data)),
            .code_count = code_sec.entries.len,

            .table_types = table_types.items(arena_data).ptr,
            .table_count = @intCast(table_types.len),

            .mem_types = mem_types.items(arena_data).ptr,
            .mem_count = @intCast(mem_types.len),

            .global_types = global_sec.types.items(arena_data).ptr,
            .global_exprs = global_sec.exprs.items(arena_data).ptr,
            .global_count = global_sec.types.len,

            .import_section = import_sec.start,
            .func_import_count = import_sec.funcs.len,
            .func_imports = import_sec.funcs.items(arena_data).ptr,
            .table_import_count = @intCast(import_sec.tables.len),
            .table_imports = import_sec.tables.items(arena_data).ptr,
            .mem_import_count = @intCast(import_sec.mems.len),
            .mem_imports = import_sec.mems.items(arena_data).ptr,
            .global_import_count = @intCast(import_sec.globals.len),
            .global_imports = import_sec.globals.items(arena_data).ptr,

            .export_section = export_sec.start,
            .exports = export_sec.descs.items(arena_data).ptr,
            .export_count = export_sec.descs.len,

            // TODO
            .datas_count = .{ .has_count_section = false, .count = 0 },

            .start = start,
        },
        .custom_sections = custom_sections.items(arena_data),
    };
}

/// Returns `false` if validation of one of the functions began in another thread and did not yet finish.
pub fn finishCodeValidation(module: *Module, allocator: Allocator, scratch: *ArenaAllocator) validator.Error!bool {
    var allValidated = true;
    for (
        module.inner.func_import_count..module.inner.func_count,
        module.code(),
    ) |func_idx, *code_entry| {
        _ = scratch.reset(.retain_capacity);
        allValidated = allValidated and try code_entry.state.validate(
            allocator,
            module,
            module.funcTypeIdx(@enumFromInt(@as(@typeInfo(FuncIdx).@"enum".tag_type, @intCast(func_idx)))),
            code_entry.contents,
            scratch,
        );
    }

    // unreachable; // allows print debugging in validation code when interpreter also has print statements
    return allValidated;
}

pub fn deinit(module: *Module, gpa: Allocator) void {
    gpa.free(module.arena_data);
    module.* = undefined;
}
