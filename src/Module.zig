const std = @import("std");
const Allocator = std.mem.Allocator;
const ArenaAllocator = std.heap.ArenaAllocator;
const IndexedArena = @import("IndexedArena.zig");

const Module = @This();

pub const ValType = @import("Module/val_type.zig").ValType;
pub const FuncType = @import("Module/func_type.zig").FuncType;

pub const TypeIdx = enum(u31) {
    _,
};

pub const FuncIdx = enum(u31) {
    _,

    pub fn signature(idx: FuncIdx, module: *const Module) *const FuncType {
        return module.func_types.ptrAt(@intFromEnum(idx), module.data);
    }
};

pub const TableIdx = enum(u8) { _ };

/// A 7-bit index allows faster parsing and interpretation of memory instructions which would other
/// be slowed by LEB128 parsing.
pub const MemIdx = enum(u7) { _ };

wasm: []const u8,
inner: extern struct {
    types: [*]const FuncType,
    types_count: u32,

    func_count: u32,
    func_types: [*]const *const FuncType, // Using TypeIdx would introduce another indirection

    /// Not set if `code_count == 0`.
    code_section: [*]const u8,
    code_entries: [*]const Code,
    code_count: u32,

    func_import_count: u32,
    global_count: u32,

    // global_types: [*]const GlobalType,
    table_types: [*]const TableType,
    mem_types: [*]const MemType,
    table_count: u8,
    table_import_count: u8,
    mem_count: u8,
    mem_import_count: u8,
    global_import_count: u32,

    /// Not set if the total # of imports is zero.
    import_section: [*]const u8,
    func_imports: [*]const ImportName,
    // global_imports: [*]const ImportName,
    table_imports: [*]const ImportName,
    memory_imports: [*]const ImportName,

    export_section: [*]const u8,
    exports: [*]const Export,
    export_count: u32,

    start: Start,
},
custom_sections: []const CustomSection,
arena_data: IndexedArena.ConstData,

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

pub const ImportName = struct {
    name_offset: u32,
    name_len: u16,

    module_offset: u32,
    module_len: u16,

    //pub inline fn name()
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

pub const Export = struct {
    name_slice: WasmSlice,
    desc: Desc,

    pub const Desc = union(enum(u2)) {
        func: FuncIdx,
        table: TableIdx,
        mem: MemIdx,
    };

    pub inline fn name(self: Export, module: *const Module) std.unicode.Utf8View {
        return .{ .bytes = self.name_slice.slice(module.inner.export_section, module.wasm) };
    }
};

pub const Limits = extern struct {
    min: usize,
    max: usize,
};

pub const TableType = extern struct {
    /// Until a `RefType` type is added, it is an invariant that `element_type.isRefType()`.
    elem_type: ValType,
    /// The minimum and maximum number of elements.
    limits: Limits,
    // flags: packed struct { index_type: IndexType, },
};

pub const MemType = extern struct {
    /// The minimum and maximum number of pages.
    limits: Limits,
    flags: packed struct(u32) {
        log2_page_size: u5 = std.math.log2_int(u17, 65536),
        // index_type: IndexType,
        padding: u27 = 0,
    } = .{},
};

pub const Code = extern struct {
    contents: WasmSlice,
    // TODO: Ptr to side table
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

pub inline fn customSections(module: *const Module) []const CustomSection {
    return module.custom_sections.items(module.data);
}

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

const Reader = struct {
    bytes: *[]const u8,

    const Error = ReaderError;

    fn init(bytes: *[]const u8) Reader {
        return .{ .bytes = bytes };
    }

    fn isEmpty(reader: Reader) bool {
        return reader.bytes.len == 0;
    }

    fn expectEndOfStream(reader: Reader) ReaderError!void {
        if (!reader.isEmpty()) return error.MalformedWasm;
    }

    fn readAssumeLength(reader: Reader, len: usize) []const u8 {
        const skipped = reader.bytes.*[0..len];
        reader.bytes.* = reader.bytes.*[len..];
        return skipped;
    }

    fn read(reader: Reader, len: usize) NoEofError![]const u8 {
        if (reader.bytes.len < len) return error.EndOfStream;
        return reader.readAssumeLength(len);
    }

    fn readArray(reader: Reader, comptime len: usize) NoEofError!*const [len]u8 {
        const s = try reader.read(len);
        return s[0..len];
    }

    pub fn readByte(reader: Reader) NoEofError!u8 {
        if (reader.isEmpty()) return error.EndOfStream;
        return (try reader.readArray(1))[0];
    }

    fn readByteTag(reader: Reader, comptime Tag: type) Error!Tag {
        comptime {
            std.debug.assert(@bitSizeOf(@typeInfo(Tag).@"enum".tag_type) <= 8);
        }

        return std.meta.intToEnum(Tag, try reader.readByte()) catch |e| switch (e) {
            std.meta.IntToEnumError.InvalidEnumTag => return error.MalformedWasm,
        };
    }

    fn readUleb128(reader: Reader, comptime T: type) Error!T {
        return std.leb.readUleb128(T, reader) catch |e| switch (e) {
            error.Overflow => ReaderError.MalformedWasm,
            NoEofError.EndOfStream => |eof| eof,
        };
    }

    fn readUleb128Casted(reader: Reader, comptime T: type, comptime U: type) (Error || LimitError)!U {
        comptime std.debug.assert(@bitSizeOf(U) < @bitSizeOf(T));
        return std.math.cast(U, try reader.readUleb128(T)) orelse LimitError.WasmImplementationLimit;
    }

    fn readByteVec(reader: Reader) Error![]const u8 {
        const len = try reader.readUleb128(u32);
        return reader.read(len);
    }

    fn readName(reader: Reader) Error!std.unicode.Utf8View {
        const contents = try reader.readByteVec();
        return if (std.unicode.utf8ValidateSlice(contents))
            .{ .bytes = contents }
        else
            error.MalformedWasm;
    }

    fn readValType(reader: Reader) Error!ValType {
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

    fn readIdx(reader: Reader, comptime I: type, slice: anytype) ParseError!I {
        const idx = try reader.readUleb128(u32);
        return if (idx < slice.len)
            @enumFromInt(std.math.cast(@typeInfo(I).@"enum".tag_type, idx) orelse return error.WasmImplementationLimit)
        else
            error.InvalidWasm;
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

fn resolveIdx(slice: anytype, idx: u32) error{InvalidWasm}!@TypeOf(slice).ElemIdx {
    return if (idx >= slice.len)
        error.InvalidWasm
    else
        slice.at(idx);
}

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
                        .default_value = @ptrCast(@as(*const []const u8, &empty)),
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
        const types = try arena.alloc(TypeSecEntry, type_len);
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

            types.setAt(
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
        break :types types;
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

    const ImportSec = struct {
        start: [*]const u8 = undefined,
        funcs: IndexedArena.Slice(ImportName) = .empty,
        tables: IndexedArena.Slice(ImportName) = .empty,
        mems: IndexedArena.Slice(ImportName) = .empty,
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
                .module_offset = @intCast(@intFromPtr(mod.bytes.ptr) - @intFromPtr(imports_start)),
                .module_len = std.math.cast(u16, mod.bytes.len) orelse return error.WasmImplementationLimit,

                .name_offset = @intCast(@intFromPtr(name.bytes.ptr) - @intFromPtr(imports_start)),
                .name_len = std.math.cast(u16, name.bytes.len) orelse return error.WasmImplementationLimit,
            };

            switch (try import_reader.readByteTag(ImportExportDesc)) {
                .func => {
                    try func_imports.append(scratch.allocator(), import_name);

                    const type_idx = try import_reader.readIdx(TypeIdx, type_sec);
                    const type_ptr = try resolveIdx(type_sec, @intFromEnum(type_idx));
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
                else => unreachable, // TODO
            }
        }

        try import_reader.expectEndOfStream();
        known_sections.import = undefined;

        // Detect if code above accidentally added to the wrong name list.
        std.debug.assert(func_import_types.len == func_imports.len);
        std.debug.assert(table_import_types.len == table_imports.len);
        std.debug.assert(mem_import_types.len == mem_imports.len);

        break :imports ImportSec{
            .start = imports_start,
            .funcs = try arena.dupeSegmentedList(ImportName, 8, &func_imports),
            .tables = try arena.dupeSegmentedList(ImportName, 1, &table_imports),
            .mems = try arena.dupeSegmentedList(ImportName, 1, &mem_imports),
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
            const type_idx = try func_reader.readUleb128(u32);
            f.* = FuncSecEntry{
                .fixup = .{ .idx = (try resolveIdx(type_sec, type_idx)).ptrCast(FuncType) },
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

    const ExportSec = struct {
        start: [*]const u8 = undefined,
        descs: IndexedArena.Slice(Export) = .empty,
    };

    const export_sec: ExportSec = if (known_sections.@"export".len > 0) exports: {
        const export_reader = Reader.init(&known_sections.@"export");
        errdefer wasm.* = export_reader.bytes.*;
        const export_len = try export_reader.readUleb128(u32);
        const exports = ExportSec{
            .start = export_reader.bytes.*.ptr,
            .descs = try arena.alloc(Export, export_len),
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

        for (exports.descs.items(&arena)) |*ex| {
            const name = try export_reader.readName();
            if (export_dedup.getOrPutAssumeCapacityContext(name.bytes, export_dedup_context).found_existing)
                return ParseError.InvalidWasm;

            ex.* = Export{
                .name_slice = .{
                    .size = @intCast(name.bytes.len),
                    .offset = @intCast(@intFromPtr(name.bytes.ptr) - @intFromPtr(exports.start)),
                },
                .desc = switch (try export_reader.readByteTag(ImportExportDesc)) {
                    .func => .{ .func = try export_reader.readIdx(FuncIdx, func_types) },
                    .table => .{ .table = try export_reader.readIdx(TableIdx, table_types) },
                    .mem => .{ .mem = try export_reader.readIdx(MemIdx, mem_types) },
                    else => unreachable, // TODO
                },
            };
        }

        try export_reader.expectEndOfStream();
        known_sections.@"export" = undefined;
        break :exports exports;
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
        if (code_len != defined_func_count) return error.MalformedWasm;

        const code_sec = CodeSec{
            .start = code_reader.bytes.*.ptr,
            .entries = try arena.alloc(Code, code_len),
        };

        for (code_sec.entries.items(&arena)) |*code| {
            const contents = try code_reader.readByteVec();
            code.* = Code{
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
        const types = IndexedArena.Slice(ValType){
            .idx = fixup.types.idx,
            .len = fixup.param_count + fixup.result_count,
        };

        ty.* = TypeSecEntry{
            .final = FuncType{
                .types = types.items(arena_data).ptr,
                .param_count = fixup.param_count,
                .result_count = fixup.result_count,
            },
        };
    }

    for (func_types.items(arena_data)) |*ty| {
        const func_type_idx: IndexedArena.Idx(FuncType) = ty.*.fixup.idx;
        ty.* = FuncSecEntry{ .final = func_type_idx.getPtr(arena_data) };
    }

    for (code_sec.entries.items(arena_data)) |*code| {
        // TODO: Allocate side table information for code entries.
        _ = code;
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
            .mem_count = 0,

            .import_section = import_sec.start,
            .func_import_count = import_sec.funcs.len,
            .func_imports = import_sec.funcs.items(arena_data).ptr,
            .table_import_count = @intCast(import_sec.tables.len),
            .table_imports = import_sec.tables.items(arena_data).ptr,
            .mem_import_count = @intCast(import_sec.mems.len),
            .memory_imports = import_sec.mems.items(arena_data).ptr,

            .export_section = export_sec.start,
            .exports = export_sec.descs.items(arena_data).ptr,
            .export_count = export_sec.descs.len,

            .start = start,

            // TODO:
            .global_count = 0,
            .global_import_count = 0,
        },
        .custom_sections = custom_sections.items(arena_data),
    };
}

pub fn deinit(module: *Module, gpa: Allocator) void {
    gpa.free(module.arena_data);
    module.* = undefined;
}
