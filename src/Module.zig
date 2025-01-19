const std = @import("std");
const Allocator = std.mem.Allocator;
const ArenaAllocator = std.heap.ArenaAllocator;
const IndexedArena = @import("IndexedArena.zig");

const Module = @This();

pub const ValType = @import("Module/val_type.zig").ValType;
pub const FuncType = @import("Module/FuncType.zig");

pub const TypeIdx = enum(u31) {
    _,
};

pub const FuncIdx = enum(u31) {
    _,

    pub fn signature(idx: FuncIdx, module: *const Module) *const FuncType {
        return module.func_types.ptrAt(@intFromEnum(idx), module.data);
    }
};

wasm: []const u8,
types: IndexedArena.Slice(FuncType) = .empty,
func_types: IndexedArena.Slice(IndexedArena.Idx(FuncType)) = .empty,
code: struct {
    section_start: [*]const u8 = undefined,
    entries: IndexedArena.Slice(Code) = .empty,
} = .{},
imports_start: [*]const u8 = undefined,
func_imports: IndexedArena.Slice(ImportName) = .empty,
exports: struct {
    section_start: [*]const u8 = undefined,
    descs: IndexedArena.Slice(Export) = .empty,
} = .{},
custom_sections: IndexedArena.Slice(CustomSection) = .empty,
start: packed struct(u32) { exists: bool = false, idx: FuncIdx = undefined } = .{},
data: IndexedArena.ConstData = &[0]IndexedArena.Word{},

pub const ImportName = struct {
    name_offset: u32,
    name_len: u16,

    module_offset: u32,
    module_len: u16,

    //pub inline fn name()
};

pub const Export = struct {
    name_offset: u32,
    name_len: u32,
    desc: Desc,

    pub const Desc = union(enum(u2)) {
        func: FuncIdx,
    };

    pub inline fn name(self: Export, module: *const Module) std.unicode.Utf8View {
        return .{ .bytes = module.exports.section_start[self.name_offset .. self.name_offset + self.name_len] };
    }
};

pub const Code = struct {
    offset: u32,
    size: u32,
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

    fn readIdx(reader: Reader, comptime I: type, slice: anytype) ParseError!I {
        const idx = try reader.readUleb128(u32);
        return if (idx < slice.len)
            @enumFromInt(std.math.cast(@typeInfo(I).@"enum".tag_type, idx) orelse return error.WasmImplementationLimit)
        else
            error.InvalidWasm;
    }
};

pub const ParseOptions = struct {
    /// If true, module data is initially allocated in a `scratch` allocator as it is resized.
    ///
    /// This reduces the final memory usage at the cost of doubling the peak memory usage. Setting this
    /// option is useful when parsing many modules, as the `scratch` allocator allows reusing memory
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
    allocator: Allocator,
    wasm: *[]const u8,
    scratch: Allocator,
    rng: std.Random,
    options: ParseOptions,
) ParseError!Module {
    var module = Module{ .wasm = wasm.* };

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

    var temporary = ArenaAllocator.init(scratch);
    defer temporary.deinit();

    // Allocated in `temporary`.
    var custom_sections = std.SegmentedList(CustomSection, 1){};

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
                    try custom_sections.append(
                        temporary.allocator(),
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

    var arena = IndexedArena.init(if (options.realloc_contents) scratch else allocator);
    defer if (options.realloc_contents) arena.deinit();

    module.custom_sections = try arena.dupeSegmentedList(CustomSection, 1, &custom_sections);

    if (known_sections.type.len > 0) {
        const type_reader = Reader.init(&known_sections.type);
        errdefer wasm.* = type_reader.bytes.*;
        const type_len = try type_reader.readUleb128(u32);
        const types = try arena.alloc(FuncType, type_len);
        module.types = types;
        for (0..type_len) |type_i| {
            _ = temporary.reset(.retain_capacity);

            _ = try type_reader.readByteTag(enum(u8) { func = 0x60 });

            const param_count = try type_reader.readUleb128Casted(u32, u16);
            const param_types = try temporary.allocator().alloc(ValType, param_count);
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
                FuncType{
                    .types = types_buf.idx,
                    .param_count = param_count,
                    .result_count = result_count,
                },
            );
        }

        try type_reader.expectEndOfStream();
        known_sections.type = undefined;
    }

    // Allocated in `temporary`.
    var func_import_types = std.SegmentedList(IndexedArena.Idx(FuncType), 8){};

    if (known_sections.import.len > 0) {
        const import_reader = Reader.init(&known_sections.import);
        errdefer wasm.* = import_reader.bytes.*;
        const import_len = try import_reader.readUleb128(u32);
        module.imports_start = import_reader.bytes.*.ptr;

        var names_arena = ArenaAllocator.init(temporary.allocator());
        // Reserve space for all of the names.
        _ = try names_arena.allocator().alloc(
            ImportName,
            std.math.add(usize, import_len, 2) catch return error.OutOfMemory,
        );

        _ = names_arena.reset(.retain_capacity);
        var func_imports = std.SegmentedList(ImportName, 8){};

        for (0..import_len) |_| {
            const mod = try import_reader.readName();
            const name = try import_reader.readName();
            const import_name = ImportName{
                .module_offset = @intCast(@intFromPtr(mod.bytes.ptr) - @intFromPtr(module.imports_start)),
                .module_len = std.math.cast(u16, mod.bytes.len) orelse return error.WasmImplementationLimit,

                .name_offset = @intCast(@intFromPtr(name.bytes.ptr) - @intFromPtr(module.imports_start)),
                .name_len = std.math.cast(u16, name.bytes.len) orelse return error.WasmImplementationLimit,
            };

            switch (try import_reader.readByteTag(ImportExportDesc)) {
                .func => {
                    try func_imports.append(names_arena.allocator(), import_name);
                    try func_import_types.append(
                        temporary.allocator(),
                        try resolveIdx(module.types, @intFromEnum(try import_reader.readIdx(TypeIdx, module.types))),
                    );
                },
                else => unreachable, // TODO
            }
        }

        module.func_imports = try arena.dupeSegmentedList(ImportName, 8, &func_imports);

        try import_reader.expectEndOfStream();
        known_sections.import = undefined;
    }

    const func_sec_len: u32 = if (known_sections.func.len > 0) len: {
        const func_reader = Reader.init(&known_sections.func);
        errdefer wasm.* = func_reader.bytes.*;
        const func_len = try func_reader.readUleb128(u32);
        const func_import_len: u32 = @intCast(func_import_types.len);
        module.func_types = try arena.alloc(
            IndexedArena.Idx(FuncType),
            std.math.add(u32, func_import_len, func_len) catch return error.InvalidWasm,
        );

        // Cannot use `temporary` until this runs.
        func_import_types.writeToSlice(module.func_types.items(&arena)[0..func_import_len], 0);

        for (func_import_len..(func_import_len + func_len)) |i| {
            const type_idx = try func_reader.readUleb128(u32);
            module.func_types.setAt(i, &arena, try resolveIdx(module.types, type_idx));
        }

        try func_reader.expectEndOfStream();
        known_sections.func = undefined;
        break :len func_len;
    } else no_func: {
        // Cannot use `temporary` until this runs.
        module.func_types = try arena.dupeSegmentedList(
            IndexedArena.Idx(FuncType),
            8,
            &func_import_types,
        );
        break :no_func 0;
    };

    std.debug.assert(module.func_types.len >= func_import_types.len);
    func_import_types = undefined;

    if (known_sections.@"export".len > 0) {
        const export_reader = Reader.init(&known_sections.@"export");
        errdefer wasm.* = export_reader.bytes.*;
        const export_len = try export_reader.readUleb128(u32);

        module.exports = .{
            .section_start = export_reader.bytes.*.ptr,
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

        _ = temporary.reset(.retain_capacity);
        comptime std.debug.assert(std.hash_map.default_max_load_percentage > 75);
        try export_dedup.ensureTotalCapacityContext(
            temporary.allocator(),
            // Prevent regrowth even with high load factor.
            std.math.add(u32, export_len, export_len / 4) catch return error.OutOfMemory,
            export_dedup_context,
        );

        for (module.exports.descs.items(&arena)) |*ex| {
            const name = try export_reader.readName();
            if (export_dedup.getOrPutAssumeCapacityContext(name.bytes, export_dedup_context).found_existing)
                return ParseError.InvalidWasm;

            ex.* = Export{
                .name_len = @intCast(name.bytes.len),
                .name_offset = @intCast(@intFromPtr(name.bytes.ptr) - @intFromPtr(module.exports.section_start)),
                .desc = switch (try export_reader.readByteTag(ImportExportDesc)) {
                    .func => .{ .func = try export_reader.readIdx(FuncIdx, module.func_types) },
                    else => unreachable, // TODO
                },
            };
        }

        try export_reader.expectEndOfStream();
        known_sections.@"export" = undefined;
    }

    if (known_sections.start.len > 0) {
        const start_reader = Reader.init(&known_sections.start);
        errdefer wasm.* = start_reader.bytes.*;

        module.start = .{
            .idx = try start_reader.readIdx(FuncIdx, module.func_types),
            .exists = true,
        };

        try start_reader.expectEndOfStream();
        known_sections.start = undefined;
    }

    if (known_sections.code.len > 0) {
        const code_reader = Reader.init(&known_sections.code);
        errdefer wasm.* = code_reader.bytes.*;
        const code_len = try code_reader.readUleb128(u32);
        if (code_len != func_sec_len) return error.MalformedWasm;

        module.code = .{
            .section_start = code_reader.bytes.*.ptr,
            .entries = try arena.alloc(Code, code_len),
        };

        for (module.code.entries.items(&arena)) |*code| {
            const contents = try code_reader.readByteVec();
            code.* = .{
                .size = @intCast(contents.len),
                .offset = @intCast(@intFromPtr(contents.ptr) - @intFromPtr(module.code.section_start)),
            };
        }

        try code_reader.expectEndOfStream();
        known_sections.code = undefined;
    } else if (func_sec_len > 0) return error.MalformedWasm;

    module.data = if (options.realloc_contents) realloc: {
        const src = arena.data.items;
        const dupe = try allocator.alignedAlloc(IndexedArena.Word, IndexedArena.max_alignment, src.len);
        @memcpy(dupe, src);
        break :realloc dupe;
    } else contents: {
        const desired_len = arena.data.items.len;
        if (arena.data.allocator.resize(arena.data.items, desired_len)) {
            arena.data.capacity = desired_len;
        } else {
            arena.data.expandToCapacity();
        }

        break :contents arena.data.toOwnedSlice() catch unreachable;
    };

    return module;
}

pub fn deinit(module: *Module, allocator: Allocator) void {
    allocator.free(module.data);
    module.* = undefined;
}
