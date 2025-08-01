pub const ValType = @import("Module/val_type.zig").ValType;
pub const FuncType = @import("Module/func_type.zig").FuncType;

pub const TypeIdx = enum(u31) {
    _,

    pub fn funcType(idx: TypeIdx, module: Module) *const FuncType {
        return &module.types()[@intFromEnum(idx)];
    }
};

pub const FuncIdx = enum(u31) {
    _,

    pub inline fn signature(idx: FuncIdx, module: Module) *const FuncType {
        return module.func_types()[@intFromEnum(idx)];
    }

    pub fn code(idx: FuncIdx, module: Module) ?*Code {
        return if (@intFromEnum(idx) < module.inner.raw.func_import_count)
            null
        else
            module.code(idx);
    }
};

pub const GlobalIdx = enum(u31) { _ };

// A 7-bit index allows parsing a byte instead of a LEB128 index.
pub const TableIdx = enum(u7) {
    default = 0,
    _,
};

pub const MemIdx = enum(u7) {
    default = 0,
    _,
};

pub const ElemIdx = enum(u16) { _ };
pub const DataIdx = enum(u16) { _ };

fn SmallIdx(comptime Int: type, comptime Idx: type) type {
    return enum(Int) {
        comptime {
            std.debug.assert(@bitSizeOf(Int) < @bitSizeOf(Idx));
        }

        _,

        const Self = @This();

        pub fn init(idx: Idx) LimitError!Self {
            return @enumFromInt(
                std.math.cast(Int, @intFromEnum(idx)) orelse
                    return error.WasmImplementationLimit,
            );
        }

        pub fn get(idx: Self) Idx {
            return @enumFromInt(@intFromEnum(idx));
        }
    };
}

const Module = @This();

// Fields are ordered manually, for the following reasons:
// - to (maybe) ensure fields used together are close together
// - to allow access from assembly code (when/if it is used)
// - to reduce padding (compiler should already do this though?)
//
// Slices are also manually split into length and ptr fields to shave a few bytes
// off the size.
const RawInner = extern struct {
    types: [*]const FuncType,
    types_count: u32,

    custom_sections_count: u32,
    custom_sections: [*]const CustomSection,

    func_types: [*]const *const FuncType, // Using TypeIdx would introduce another indirection

    func_import_count: u32,
    code_count: u32,

    /// Not set if `code_count == 0`.
    code_section: [*]const u8,
    code_entries: [*]const Code.Entry,
    code: [*]Code,

    global_exprs: [*]const ConstExpr,
    global_types: [*]const GlobalType,
    table_types: [*]const TableType,
    mem_types: [*]const MemType,

    start: Start,
    table_count: u8,
    table_import_count: u8,
    mem_count: u8,
    mem_import_count: u8,

    global_count: u32,
    global_import_count: u32,

    /// Not set if the total # of imports is zero.
    import_section: [*]const u8,
    func_imports: [*]const ImportName,
    table_imports: [*]const ImportName,
    mem_imports: [*]const ImportName,
    global_imports: [*]const ImportName,

    export_section: [*]const u8,
    exports: [*]const Export,
    export_count: u32,
    has_data_count_section: bool,
    // padding: [3]u8,

    elems: [*]const ElemSegment,
    active_elems: [*]const ActiveElem,
    /// A bitmask indicating which data segments are passive or active.
    ///
    /// This mask is used during module instantiation, as declarative element segments
    /// are "dropped" (their length is set to zero).
    non_declarative_elems_mask: [*]const u32,
    elems_count: u16,
    active_elems_count: u16,

    active_datas_count: u16,
    datas_count: u16,
    datas_ptrs: [*]const [*]const u8,
    datas_lens: [*]const u32,
    active_datas: [*]const ActiveData,
};

const Inner = struct {
    raw: RawInner,
    wasm: []const u8,
    arena: ArenaAllocator.State,
    runtime_shape: @import("runtime.zig").ModuleInst.Shape,
};

inner: *align(std.atomic.cache_line) const Inner,

pub inline fn customSections(module: Module) []const CustomSection {
    return module.inner.raw.custom_sections();
}

pub inline fn types(module: Module) []const FuncType {
    return module.inner.raw.types[0..module.inner.raw.types_count];
}

pub inline fn funcCount(module: Module) u32 {
    return module.inner.raw.func_import_count + module.inner.raw.code_count;
}

pub inline fn funcTypes(module: Module) []const *const FuncType {
    return module.inner.raw
        .func_types[0 .. module.inner.raw.func_import_count + module.inner.raw.code_count];
}

pub inline fn funcTypeIdx(module: Module, func: FuncIdx) TypeIdx {
    const func_idx: @typeInfo(FuncIdx).@"enum".tag_type = @intFromEnum(func);
    std.debug.assert(func_idx < module.inner.raw.func_import_count + module.inner.raw.code_count);

    const type_ptr = @intFromPtr(@as(*const FuncType, module.funcTypes()[func_idx]));
    std.debug.assert(
        type_ptr < @intFromPtr(
            @as(*const FuncType, &module.inner.raw.types[module.inner.raw.types_count]),
        ),
    );
    return @enumFromInt((type_ptr - @intFromPtr(module.inner.raw.types)) / @sizeOf(FuncType));
}

pub inline fn funcImportNames(module: Module) []const ImportName {
    return module.inner.raw.func_imports[0..module.inner.raw.func_import_count];
}

pub inline fn funcImportTypes(module: Module) []const *const FuncType {
    return module.funcTypes()[0..module.inner.raw.func_import_count];
}

pub inline fn tableTypes(module: Module) []const TableType {
    return module.inner.raw.table_types[0..module.inner.raw.table_count];
}

pub inline fn tableImportNames(module: Module) []const ImportName {
    return module.inner.raw.table_imports[0..module.inner.raw.table_import_count];
}

pub inline fn tableImportTypes(module: Module) []const TableType {
    return module.tableTypes()[0..module.inner.raw.table_import_count];
}

pub inline fn memTypes(module: Module) []const MemType {
    return module.inner.raw.mem_types[0..module.inner.raw.mem_count];
}

pub inline fn memImportNames(module: Module) []const ImportName {
    return module.inner.raw.mem_imports[0..module.inner.raw.mem_import_count];
}

pub inline fn memImportTypes(module: Module) []const MemType {
    return module.memTypes()[0..module.inner.raw.mem_import_count];
}

pub fn globalTypes(module: Module) []const GlobalType {
    return module.inner.raw.global_types[0..module.inner.raw.global_count];
}

pub inline fn globalImportNames(module: Module) []const ImportName {
    return module.inner.raw.global_imports[0..module.inner.raw.global_import_count];
}

pub inline fn globalImportTypes(module: Module) []const GlobalType {
    return module.globalTypes()[0..module.inner.raw.global_import_count];
}

pub inline fn globalInitializers(module: Module) []const ConstExpr {
    const defined_count = module.inner.raw.global_count - module.inner.raw.global_import_count;
    return module.inner.raw.global_exprs[0..defined_count];
}

pub inline fn codeEntries(module: Module) []const Code.Entry {
    return module.inner.raw.code_entries[0..module.inner.raw.code_count];
}

/// Asserts that the function index refers to a function definition.
pub inline fn code(module: Module, idx: FuncIdx) *Code {
    const definition_index = @intFromEnum(idx) - module.inner.raw.func_import_count;
    return &module.inner.raw.code[0..module.inner.raw.code_count][definition_index];
}

pub inline fn dataSegmentContents(module: Module, idx: DataIdx) []const u8 {
    const i = @intFromEnum(idx);
    std.debug.assert(i < module.inner.raw.datas_count);
    return module.inner.raw.datas_ptrs[i][0..module.inner.raw.datas_lens[i]];
}

pub inline fn elementSegments(module: Module) []const ElemSegment {
    return module.inner.raw.elems[0..module.inner.raw.elems_count];
}

pub inline fn exports(module: Module) []const Export {
    return module.inner.raw.exports[0..module.inner.raw.export_count];
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

    fn parse(
        readers: *Sections.Readers,
        functions: []const *const FuncType,
        diag: ParseDiagnostics,
    ) !Start {
        const start_reader = readers.start;
        if (start_reader.isEmpty()) {
            return .none;
        } else {
            const func_idx = try start_reader.readIdx(
                FuncIdx,
                functions.len,
                diag,
                "unknown function in 'start' section",
            );

            try start_reader.expectEnd(
                diag,
                "section size mismatch, expected end of 'start' section",
            );

            readers.start.bytes.* = undefined;
            readers.start = undefined;

            const signature = functions[@intFromEnum(func_idx)];
            if (signature.param_count != 0 or signature.result_count != 0) {
                return diag.print(
                    .validation,
                    "start function must not have {s}",
                    .{if (signature.param_count != 0) "parameters" else "results"},
                );
            }

            return .init(func_idx);
        }
    }
};

pub const WasmSlice = extern struct {
    offset: u32,
    size: u32,

    pub fn slice(
        s: WasmSlice,
        /// `base` is a pointer into `wasm`, usually referring to the first byte of some
        /// particular section.
        base: [*]const u8,
        /// `bounds` is `wasm`, and is used to assert that the calculated slice is not OOB.
        bounds: []const u8,
    ) []const u8 {
        const calculated = base[s.offset .. s.offset + s.size];
        std.debug.assert(
            @intFromPtr(calculated.ptr) + calculated.len <= @intFromPtr(bounds.ptr) + bounds.len,
        );
        return calculated;
    }
};

pub const ImportName = struct {
    name_offset: u16,
    name_size: u16,

    module_offset: u16,
    module_size: u16,

    pub inline fn desc_name(self: ImportName, module: Module) std.unicode.Utf8View {
        const name_slice = WasmSlice{ .offset = self.name_offset, .size = self.name_size };
        return .{
            .bytes = name_slice.slice(module.inner.raw.import_section, module.inner.wasm),
        };
    }

    pub inline fn module_name(self: ImportName, module: Module) std.unicode.Utf8View {
        const name_slice = WasmSlice{ .offset = self.module_offset, .size = self.module_size };
        return .{
            .bytes = name_slice.slice(module.inner.raw.import_section, module.inner.wasm),
        };
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

    pub inline fn name(self: Export, module: Module) std.unicode.Utf8View {
        const name_slice = WasmSlice{ .offset = self.name_offset, .size = self.name_size };
        const bytes = name_slice.slice(module.inner.raw.export_section, module.inner.wasm);
        return switch (@import("builtin").mode) {
            .Debug, .ReleaseSafe => std.unicode.Utf8View.init(bytes) catch unreachable,
            .ReleaseFast, .ReleaseSmall => .{
                .bytes = name_slice.slice(module.inner.raw.export_section, module.inner.wasm),
            },
        };
    }
};

pub const Limits = extern struct {
    min: usize,
    max: usize,

    pub inline fn matches(a: *const Limits, b: *const Limits) bool {
        return a.min >= b.min and a.max <= b.max;
    }

    pub fn format(limits: *const Limits, writer: *Writer) Writer.Error!void {
        try writer.print("{} {}", .{ limits.min, limits.max });
    }

    fn parse(
        reader: Reader,
        default_maximum: u32,
        /// For memories, spec test assumes limits do not exceed bounds before comparing `min` and
        /// `max`.
        comptime checkLimitsBounds: fn (Limits, diag: ParseDiagnostics) Reader.ValidationError!void,
        diag: ParseDiagnostics,
    ) !Limits {
        const LimitsFlag = enum(u2) {
            no_maximum = 0x00,
            has_maximum = 0x01,
        };

        const flag_byte = try reader.readByte(diag, "limits flag");
        // For some reason, spec test checks that the flag is a LEB128, despite the spec not
        // mentioning this.
        if (flag_byte & 0x80 != 0) {
            return diag.writeAll(.parse, "limits flag integer representation too long");
        }

        // If 64-bit memory and/or shared memory is used, limits is a LEB128 u32?
        // const flag = try reader.readUleb128Enum(u32, LimitsFlag, diag, "limits flag");
        const flag = std.meta.intToEnum(LimitsFlag, flag_byte) catch return diag.print(
            .parse,
            "limits flag integer too large: 0x{X:0>2}",
            .{flag_byte},
        );

        // When 64-bit memories are supported, parsed type needs to conditionally change to u64.
        const min = try reader.readUleb128(u32, diag, "limits minimum");

        const max: u32 = switch (flag) {
            .no_maximum => default_maximum,
            .has_maximum => try reader.readUleb128(u32, diag, "limits maximum"),
        };

        const limits = Limits{ .min = min, .max = max };
        try checkLimitsBounds(limits, diag);

        return if (min <= max)
            limits
        else
            diag.print(
                .validation,
                "size minimum must not be greater than maximum ({} > {})",
                .{ min, max },
            );
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

    pub fn format(table_type: *const TableType, writer: *Writer) Writer.Error!void {
        try writer.print("{f} {t}", .{ table_type.limits, table_type.elem_type });
    }

    fn noLimitsBounds(_: Limits, _: ParseDiagnostics) Reader.ValidationError!void {}

    fn parse(reader: Reader, diag: ParseDiagnostics) !TableType {
        const elem_type = try ValType.parse(reader, diag);
        if (!elem_type.isRefType()) {
            return diag.print(.parse, "{} must be a reference type", .{elem_type});
        }

        return .{
            .elem_type = elem_type,
            .limits = try Limits.parse(reader, std.math.maxInt(u32), noLimitsBounds, diag),
        };
    }
};

pub const MemType = extern struct {
    /// The minimum and maximum number of pages.
    ///
    /// Since only 32-bit memories are supported, both `min` and `min` are currently constrained
    /// to never exceed `65536`.
    limits: Limits,
    // flags: packed struct(u32) {
    //     log2_page_size: u5 = std.math.log2_int(u17, 65536),
    //     // index_type: IndexType,
    //     padding: u27 = 0,
    // } = .{},

    pub fn matches(a: *const MemType, b: *const MemType) bool {
        return a.limits.matches(&b.limits);
    }

    pub fn format(mem_type: *const MemType, writer: *Writer) Writer.Error!void {
        try mem_type.limits.format(writer);
    }

    fn checkMemoryLimits(limits: Limits, diag: ParseDiagnostics) Reader.ValidationError!void {
        if (limits.min > 65536 or limits.max > 65536) {
            return diag.print(
                .validation,
                "memory size must be at most 65536 pages (4GiB), got {}",
                .{if (limits.min > 65536) limits.min else limits.max},
            );
        }
    }

    fn parse(reader: Reader, diag: ParseDiagnostics) !MemType {
        const limits = try Limits.parse(reader, 65536, checkMemoryLimits, diag);
        return .{ .limits = limits };
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

    pub fn format(global_type: *const GlobalType, writer: *Writer) Writer.Error!void {
        switch (global_type.mut) {
            .@"const" => try writer.print("{t}", .{global_type.val_type}),
            .@"var" => try writer.print("(mut {t})", .{global_type.val_type}),
        }
    }

    fn parse(reader: Reader, diag: ParseDiagnostics) Reader.Error!GlobalType {
        const val_type = try ValType.parse(reader, diag);
        return .{
            .val_type = val_type,
            .mut = try reader.readByteTag(GlobalType.Mut, diag, "malformed mutability flag"),
        };
    }
};

pub const ConstExpr = union(enum) {
    i32_or_f32: u32,
    i64_or_f64: u64,
    @"ref.null": ValType,
    @"ref.func": FuncIdx,
    @"global.get": GlobalIdx,

    fn parse(
        reader: Reader,
        expected_type: ValType,
        func_count: u32,
        /// Should refer to global imports only.
        global_types: []const GlobalType,
        diag: ParseDiagnostics,
        desc: []const u8,
    ) !ConstExpr {
        const const_opcode = try reader.readByteTag(opcodes.ByteOpcode, diag, "illegal opcode");
        const expr: ConstExpr = expr: switch (const_opcode) {
            .@"i32.const" => {
                if (!expected_type.eql(ValType.i32)) {
                    return diag.print(
                        .validation,
                        "type mismatch: expected {t}, got i32.const in {s}",
                        .{ expected_type, desc },
                    );
                }

                break :expr .{
                    .i32_or_f32 = @bitCast(try reader.readIleb128(i32, diag, "i32.const")),
                };
            },
            .@"f32.const" => {
                if (!expected_type.eql(ValType.f32)) {
                    return diag.print(
                        .validation,
                        "type mismatch: expected {t}, got f32.const in {s}",
                        .{ expected_type, desc },
                    );
                }

                break :expr .{
                    .i32_or_f32 = std.mem.readInt(
                        u32,
                        try reader.readArray(4, diag, "f32.const"),
                        .little,
                    ),
                };
            },
            .@"i64.const" => {
                if (!expected_type.eql(ValType.i64)) {
                    return diag.print(
                        .validation,
                        "type mismatch: expected {t}, got i64.const in {s}",
                        .{ expected_type, desc },
                    );
                }

                break :expr .{
                    .i64_or_f64 = @bitCast(try reader.readIleb128(i64, diag, "i64.const")),
                };
            },
            .@"f64.const" => {
                if (!expected_type.eql(ValType.f64)) {
                    return diag.print(
                        .validation,
                        "type mismatch: expected {t}, got f64.const in {s}",
                        .{ expected_type, desc },
                    );
                }

                break :expr .{
                    .i64_or_f64 = std.mem.readInt(
                        u64,
                        try reader.readArray(8, diag, "f64.const"),
                        .little,
                    ),
                };
            },
            .@"ref.null" => ref_null: {
                const actual_type = try ValType.parse(reader, diag);
                if (!actual_type.isRefType()) {
                    return diag.print(
                        .validation,
                        "type mismatch: expected reference type for ref.null, got {t} in {s}",
                        .{ actual_type, desc },
                    );
                }

                if (actual_type != expected_type) {
                    return diag.print(
                        .validation,
                        "type mismatch: expected {t}, got ref.null {t} in {s}",
                        .{ expected_type, actual_type, desc },
                    );
                }

                break :ref_null .{ .@"ref.null" = expected_type };
            },
            .@"ref.func" => .{
                .@"ref.func" = try reader.readIdx(
                    FuncIdx,
                    func_count,
                    diag,
                    "unknown function in constant expression",
                ),
            },
            .@"global.get" => {
                const global_idx = try reader.readIdx(
                    GlobalIdx,
                    global_types.len,
                    diag,
                    "unknown global in constant expression",
                );

                const actual_type: *const GlobalType = &global_types[@intFromEnum(global_idx)];
                if (!actual_type.val_type.eql(expected_type)) {
                    return diag.print(
                        .validation,
                        "type mismatch: expected global {} to have type {t}, but got {f} in {s}",
                        .{ @intFromEnum(global_idx), expected_type, actual_type, desc },
                    );
                }

                break :expr .{ .@"global.get" = global_idx };
            },
            else => return diag.print(
                .validation,
                "constant expression required, got opcode {t} in {s}",
                .{ const_opcode, desc },
            ),
        };

        if (reader.isEmpty()) {
            // Spec thinks reading into code section is ok!?
            return diag.writeAll(.parse, "illegal opcode or unexpected end");
        }

        const end_opcode = try reader.readByteTag(
            opcodes.ByteOpcode,
            diag,
            "END opcode",
        );
        if (end_opcode != .end) {
            return diag.print(
                .validation,
                "constant expression required, expected END opcode in {s}, got {t}",
                .{ desc, end_opcode },
            );
        }

        return expr;
    }
};

pub const ElemSegment = struct {
    tag: Tag,
    len: u32,
    contents: Contents,

    pub const Tag = enum {
        func_indices,
        func_expressions,
        extern_expressions,
    };

    pub inline fn elementType(elem: *const ElemSegment) ValType {
        return switch (elem.tag) {
            .func_indices, .func_expressions => .funcref,
            .extern_expressions => .externref,
        };
    }

    pub const Contents = union {
        func_indices: [*]const FuncIdx,
        expressions: [*]const Expr,
    };

    pub const Expr = packed struct(u32) {
        tag: enum(u2) {
            @"ref.null",
            @"ref.func",
            @"global.get",
        },
        inner: packed union {
            @"ref.func": SmallIdx(u30, FuncIdx),
            @"global.get": SmallIdx(u30, GlobalIdx),
        },

        pub fn init(expr: ConstExpr, diag: ParseDiagnostics) !Expr {
            return switch (expr) {
                .@"ref.null" => |_| .{
                    .tag = .@"ref.null",
                    .inner = undefined,
                },
                .@"ref.func" => |func_idx| .{
                    .tag = .@"ref.func",
                    .inner = .{
                        .@"ref.func" = try SmallIdx(u30, FuncIdx).init(func_idx),
                    },
                },
                .@"global.get" => |global_idx| .{
                    .tag = .@"global.get",
                    .inner = .{
                        .@"global.get" = try SmallIdx(u30, GlobalIdx).init(global_idx),
                    },
                },
                else => diag.writeAll(
                    .validation,
                    "type mismatch: opcode does not produce reference value",
                ),
            };
        }
    };
};

pub const ActiveElem = struct {
    header: packed struct(u32) {
        offset_tag: enum(u9) {
            @"i32.const",
            @"global.get",
        },
        table: TableIdx,
        elements: ElemIdx,
    },
    offset: packed union {
        @"i32.const": u32,
        @"global.get": GlobalIdx,
    },
};

pub const Code = validator.Code;

pub const ActiveData = extern struct {
    header: packed struct(u32) {
        memory: MemIdx,
        offset_tag: enum(u25) {
            @"i32.const",
            @"global.get",
        },
    },
    data: DataIdx,
    offset: packed union {
        @"i32.const": u32,
        @"global.get": GlobalIdx,
    },
};

pub const CustomSection = struct {
    ptr: [*]const u8,
    name_len: u32,
    contents_len: u32,

    comptime {
        std.debug.assert(@sizeOf(CustomSection) <= 24);
    }

    pub inline fn name(sec: *CustomSection) std.unicode.Utf8View {
        return .{ .bytes = sec.name_ptr[0..sec.name_len] };
    }

    pub inline fn contents(sec: *CustomSection) []const u8 {
        return sec.contents_ptr[sec.name_len..sec.contents_len];
    }
};

const wasm_preamble = "\x00asm\x01\x00\x00\x00";

const ImportExportDesc = enum(u8) {
    func = 0,
    table = 1,
    mem = 2,
    global = 3,
};

pub const LimitError = Reader.LimitError;

pub const ParseError = Reader.ValidationError || Reader.Error || LimitError ||
    std.mem.Allocator.Error;

pub const ParseDiagnostics = Reader.Diagnostics;

pub const ParseOptions = struct {
    /// If set to `true`, any custom sections encountered during parsing can later be accessed
    /// by calling `.customSections()`.
    keep_custom_sections: bool = false,
    // diagnostics: ?*ParserDiagnostics = null,
    /// Random seed provided to a hash map used for ensuring all exports have unique
    /// names.
    random_seed: u64 = 42,
    diagnostics: ParseDiagnostics = .none,
};

const Sections = struct {
    known: *Known,
    readers: Readers,

    const Known = Struct([]const u8, &[0]u8{});
    const Readers = Struct(Reader, null);

    const Id = enum(u8) {
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

    const id_fields = @typeInfo(Id).@"enum".fields;

    const Order: type = order: {
        var fields: [id_fields.len + 1]Type.EnumField = undefined;

        fields[0] = .{ .name = "any", .value = 0 };
        for (id_fields, 1..) |f, i| {
            fields[i] = .{ .name = f.name, .value = i };
        }

        break :order @Type(.{
            .@"enum" = Type.Enum{
                .tag_type = std.math.IntFittingRange(0, fields.len),
                .is_exhaustive = true,
                .decls = &[0]Type.Declaration{},
                .fields = &fields,
            },
        });
    };

    fn Struct(comptime FieldType: type, comptime default: ?FieldType) type {
        return @Type(.{
            .@"struct" = Type.Struct{
                .layout = .auto,
                .decls = &[0]Type.Declaration{},
                .is_tuple = false,
                .fields = fields: {
                    var fields: [id_fields.len - 1]Type.StructField = undefined;
                    for (id_fields[0..fields.len], &fields) |f, *dst| {
                        std.debug.assert(!std.mem.eql(u8, f.name, "custom"));
                        dst.* = Type.StructField{
                            .name = f.name,
                            .type = FieldType,
                            .default_value_ptr = if (default) |default_val|
                                @ptrCast(@as(*const FieldType, &default_val))
                            else
                                null,
                            .is_comptime = false,
                            .alignment = 0,
                        };
                    }

                    break :fields &fields;
                },
            },
        });
    }

    fn parse(
        reader: Reader,
        known_sections: *Known,
        arena: *ArenaAllocator,
        custom_sections: *std.SegmentedList(CustomSection, 2),
        options: *const ParseOptions,
    ) ParseError!Sections {
        var section_order = Order.any;
        known_sections.* = Known{};
        var section_readers: Readers = undefined;
        var encountered = std.EnumSet(std.meta.FieldEnum(Known)).initEmpty();
        inline for (@typeInfo(Readers).@"struct".fields) |f| {
            @field(section_readers, f.name) = Reader.init(&@field(known_sections, f.name));
        }

        const diag = options.diagnostics;
        while (!reader.isEmpty()) {
            const id = try reader.readByteTag(Id, diag, "malformed section id");
            const section_contents = try reader.readByteVec(diag, "section contents");

            switch (id) {
                .custom => {
                    var custom_sec_contents = section_contents;
                    const custom_sec = Reader.init(&custom_sec_contents);
                    const section_name = try custom_sec.readName(diag);

                    std.debug.assert(
                        @intFromPtr(section_name.bytes.ptr + section_name.bytes.len) ==
                            @intFromPtr(custom_sec_contents.ptr),
                    );

                    if (options.keep_custom_sections) {
                        try custom_sections.append(
                            arena.allocator(),
                            CustomSection{
                                .ptr = section_name.bytes.ptr,
                                .name_len = @intCast(section_name.bytes.len),
                                .contents_len = @intCast(custom_sec_contents.len),
                            },
                        );
                    }
                },
                inline else => |known_id| {
                    const this_order = @field(Order, @tagName(known_id));
                    if (@intFromEnum(section_order) > @intFromEnum(this_order)) {
                        return diag.print(
                            .parse,
                            "unexpected content after last section: '{t}' was placed after {t}",
                            .{ known_id, section_order },
                        );
                    }

                    const this_key = @field(std.meta.FieldEnum(Known), @tagName(known_id));
                    if (encountered.contains(this_key)) {
                        return diag.print(
                            .parse,
                            "unexpected content after last section: duplicate '{t}' section",
                            .{known_id},
                        );
                    }

                    encountered.insert(this_key);
                    section_order = @enumFromInt(@intFromEnum(this_order) + 1);
                    @field(known_sections, @tagName(known_id)) = section_contents;
                },
            }
        }

        std.debug.assert(reader.isEmpty());

        return Sections{ .known = known_sections, .readers = section_readers };
    }

    const Counts = extern struct {
        type: u32,
        import: u32,
        func: u32,
        table: u8,
        mem: u8,
        global: u32,
        @"export": u32,
        elem: u32,
        data_count: u32,
        code: u32,
        data: u32,
        custom: u32,

        fn parse(readers: *const Readers, diag: ParseDiagnostics) !Counts {
            var counts = std.mem.zeroes(Counts);
            inline for (@typeInfo(Readers).@"struct".fields) |f| {
                if (!@hasField(Counts, f.name)) {
                    continue;
                }

                const read: Reader = @field(readers, f.name);
                if (!read.isEmpty()) {
                    const count_desc = f.name ++ " count";
                    const CountInt = @FieldType(Counts, f.name);
                    @field(counts, f.name) = if (CountInt == u32)
                        try read.readUleb128(u32, diag, count_desc)
                    else
                        try read.readUleb128Casted(u32, CountInt, diag, count_desc);
                }
            }

            return counts;
        }
    };
};

pub fn parse(
    gpa: Allocator,
    /// Pointer refering to the WebAssembly binary module to parse.
    ///
    /// If a parser error occurs, this points to where.
    wasm: *[]const u8,
    /// Used for temporary allocations that live for the rest of this function call.
    alloca: *ArenaAllocator,
    options: ParseOptions,
) ParseError!Module {
    _ = alloca.reset(.retain_capacity);
    const diag = options.diagnostics;
    const original_wasm = wasm.*;

    if (!std.mem.startsWith(u8, wasm.*, wasm_preamble)) {
        return diag.writeAll(
            .parse,
            if (wasm.len < 4)
                "unexpected end of magic header"
            else if (!std.mem.startsWith(u8, wasm.*, wasm_preamble[0..4]))
                "magic header not detected"
            else if (wasm.len < 8)
                "unexpected end of binary version"
            else
                "unknown binary version",
        );
    }

    defer _ = alloca.reset(.retain_capacity);

    var custom_sections_buf = std.SegmentedList(CustomSection, 2){}; // in `alloca`

    var known_sections: Sections.Known = undefined;
    var sections = sections: {
        const wasm_reader = Reader.init(wasm);
        errdefer wasm.* = wasm_reader.bytes.*;
        _ = wasm_reader.readAssumeLength(wasm_preamble.len);
        break :sections try Sections.parse(
            wasm_reader,
            &known_sections,
            alloca,
            &custom_sections_buf,
            &options,
        );
    };

    if (custom_sections_buf.len > std.math.maxInt(u32)) {
        return error.WasmImplementationLimit; // too many custom sections
    }

    const has_data_count_section = !sections.readers.data_count.isEmpty();

    const counts = try Sections.Counts.parse(&sections.readers, diag);

    if (has_data_count_section and counts.data_count != counts.data) {
        return diag.writeAll(.parse, "data count and data section have inconsistent lengths");
    }

    try sections.readers.data_count.expectEnd(diag, "data count section size mismatch");

    var module_arena = ArenaAllocator.init(gpa);
    var module = allocator: {
        var allocator = reservation_allocator.ReservationAllocator.zero;
        try allocator.reserve(FuncType, counts.type);
        try allocator.reserve(ValType, sections.readers.type.bytes.len -| counts.type);
        try allocator.reserve(ImportName, counts.import);
        // Assume most imports are functions
        try allocator.reserve(*const FuncType, counts.func +| (counts.import / 2));
        try allocator.reserve(TableType, @max(@min(1, counts.import), counts.table));
        try allocator.reserve(MemType, @max(@min(1, counts.mem), counts.mem));
        try allocator.reserve(GlobalType, counts.global);
        try allocator.reserve(ConstExpr, counts.global);
        // try allocator.reserve(u16, counts.global); // global_value_offsets
        try allocator.reserve(Export, counts.@"export");
        try allocator.reserve(
            u32,
            std.math.divCeil(u32, @intCast(counts.elem), 32) catch unreachable,
        );
        try allocator.reserve(ElemSegment, counts.elem);
        try allocator.reserve(u32, counts.data);
        try allocator.reserve([*]const u8, counts.data);
        try allocator.reserve(Code.Entry, counts.code);
        try allocator.reserve(Code, counts.code);
        try allocator.reserve(CustomSection, custom_sections_buf.len);

        break :allocator try allocator.arenaFallbackAllocatorWithHeaderAligned(
            &module_arena,
            Inner,
            .fromByteUnits(std.atomic.cache_line),
        );
    };
    errdefer module_arena.deinit();

    const type_sec = types: {
        errdefer wasm.* = sections.known.type;
        break :types try parseTypeSec(&module.alloc, counts.type, &sections.readers, diag);
    };

    var scratch = ArenaAllocator.init(alloca.allocator());

    const import_sec: ImportSec = imports: {
        errdefer wasm.* = sections.known.import;
        break :imports try parseImportSec(
            &module.alloc,
            type_sec,
            &counts,
            &sections.readers,
            &scratch,
            diag,
        );
    };

    {
        errdefer wasm.* = sections.known.func;
        try parseFuncSec(type_sec, &import_sec.types, counts.func, &sections.readers, diag);
    }
    {
        errdefer wasm.* = sections.known.table;
        try parseTableSec(&import_sec.types, counts.table, &sections.readers, diag);
    }
    {
        errdefer wasm.* = sections.known.mem;
        try parseMemSec(&import_sec.types, counts.mem, &sections.readers, diag);
    }

    const global_exprs = globals: {
        errdefer wasm.* = sections.known.global;
        break :globals try parseGlobalSec(
            &module.alloc,
            &import_sec,
            counts.global,
            &sections.readers,
            diag,
        );
    };
    // const global_value_offsets = try module.alloc.allocator().alloc(u16, counts.global);

    const export_sec = exports: {
        errdefer wasm.* = sections.known.@"export";
        break :exports try parseExportSec(
            &import_sec.types,
            &module.alloc,
            counts.@"export",
            &sections.readers,
            options.random_seed,
            &scratch,
            diag,
        );
    };

    const custom_sections = try module.alloc.allocator().alloc(
        CustomSection,
        custom_sections_buf.len,
    );
    custom_sections_buf.writeToSlice(custom_sections, 0);

    const start: Start = start: {
        errdefer wasm.* = sections.known.start;
        break :start try Start.parse(&sections.readers, import_sec.types.funcs, diag);
    };

    const elem_sec = elems: {
        errdefer wasm.* = sections.known.elem;
        break :elems try parseElemSec(
            &module.alloc,
            &sections.readers,
            counts.elem,
            &import_sec.types,
            &scratch,
            diag,
        );
    };

    // Because of spectests, checked after any errors in the element section occurs
    if (counts.code != counts.func) {
        return diag.writeAll(.parse, "function and code section have inconsistent lengths");
    }

    const code_sec = code: {
        errdefer wasm.* = sections.known.code;
        break :code try parseCodeSec(&module.alloc, &sections.readers, counts.code, diag);
    };

    const data_sec = data: {
        errdefer wasm.* = sections.known.data;
        break :data try parseDataSec(
            &module.alloc,
            &sections.readers,
            counts.data,
            &import_sec,
            &scratch,
            diag,
        );
    };

    module.inner.* = Inner{
        .raw = RawInner{
            .types = type_sec.ptr,
            .types_count = counts.type,

            .custom_sections_count = @intCast(custom_sections_buf.len),
            .custom_sections = custom_sections.ptr,

            .func_types = import_sec.types.funcs.ptr,

            .func_import_count = @intCast(import_sec.names.funcs.len),
            .code_count = counts.code,
            .code_section = code_sec.start,
            .code_entries = code_sec.entries.ptr,
            .code = code_sec.code.ptr,

            .global_exprs = global_exprs.ptr,
            .global_types = import_sec.types.globals.ptr,
            .table_types = import_sec.types.tables.ptr,
            .mem_types = import_sec.types.mems.ptr,

            .start = start,
            .table_count = @intCast(import_sec.types.tables.len),
            .table_import_count = @intCast(import_sec.names.tables.len),
            .mem_count = @intCast(import_sec.types.mems.len),
            .mem_import_count = @intCast(import_sec.names.mems.len),

            .global_count = @intCast(import_sec.types.globals.len),
            .global_import_count = @intCast(import_sec.names.globals.len),

            .import_section = import_sec.start,
            .func_imports = import_sec.names.funcs.ptr,
            .table_imports = import_sec.names.tables.ptr,
            .mem_imports = import_sec.names.mems.ptr,
            .global_imports = import_sec.names.globals.ptr,

            .export_section = export_sec.start,
            .exports = export_sec.descs.ptr,
            .export_count = @intCast(export_sec.descs.len),
            .has_data_count_section = has_data_count_section,

            .elems = elem_sec.segments.ptr,
            .active_elems = elem_sec.active.ptr,
            .non_declarative_elems_mask = elem_sec.non_declarative_mask.ptr,
            .elems_count = @intCast(elem_sec.segments.len),
            .active_elems_count = @intCast(elem_sec.active.len),

            .datas_count = @intCast(data_sec.datas_lens.len),
            .datas_ptrs = data_sec.datas_ptrs.ptr,
            .datas_lens = data_sec.datas_lens.ptr,
            .active_datas = data_sec.active_datas.ptr,
            .active_datas_count = @intCast(data_sec.active_datas.len),
        },
        .arena = module_arena.state,
        .wasm = original_wasm,
        .runtime_shape = undefined,
    };

    const final_module = Module{ .inner = module.inner };
    try module.inner.runtime_shape.calculate(final_module);
    return final_module;
}

fn parseTypeSec(
    arena: *reservation_allocator.ArenaFallbackAllocator,
    count: u32,
    readers: *const Sections.Readers,
    diag: ParseDiagnostics,
) ![]const FuncType {
    const type_reader = readers.type;
    const type_sec = try arena.allocator().alloc(FuncType, count);

    for (type_sec) |*func_type| {
        const TypeTag = enum(u8) { func = 0x60 };
        const tag = try type_reader.readByteTag(TypeTag, diag, "function type tag");
        std.debug.assert(tag == .func);

        var val_types = std.ArrayListUnmanaged(ValType).empty;
        const param_count = try type_reader.readUleb128Casted(
            u32,
            u16,
            diag,
            "parameter type count",
        );

        const param_types = try val_types.addManyAsSlice(arena.allocator(), param_count);
        for (param_types) |*ty| {
            ty.* = try ValType.parse(type_reader, diag);
        }

        const result_count = try type_reader.readUleb128Casted(u32, u16, diag, "result type count");
        try val_types.ensureTotalCapacityPrecise(
            arena.allocator(),
            @as(u32, param_count) + result_count,
        );
        const result_types = val_types.addManyAsSliceAssumeCapacity(result_count);
        for (result_types) |*ty| {
            ty.* = try ValType.parse(type_reader, diag);
        }

        func_type.* = FuncType{
            .types = val_types.items.ptr,
            .param_count = param_count,
            .result_count = result_count,
        };
    }

    try type_reader.expectEnd(diag, "type section size mismatch");
    type_reader.bytes.* = undefined;
    return type_sec;
}

const ImportSec = struct {
    start: [*]const u8,
    types: Types,
    names: Names,

    /// Slices are only partially allocated corresponding to the types of the imports.
    ///
    /// Parsers for other sections must fill the remaining types.
    ///
    /// Allocated in the `module`'s arena.
    const Types = struct {
        funcs: []*const FuncType,
        tables: []TableType,
        mems: []MemType,
        globals: []GlobalType,
    };

    /// Allocated in the `module`'s arena.
    const Names = struct {
        funcs: []const ImportName,
        tables: []const ImportName,
        mems: []const ImportName,
        globals: []const ImportName,

        fn moveToBuffer(
            dst: *std.ArrayListUnmanaged(ImportName),
            comptime prealloc_count: usize,
            src: *std.SegmentedList(ImportName, prealloc_count),
        ) Allocator.Error![]const ImportName {
            const names = dst.addManyAsSliceAssumeCapacity(src.len);
            src.writeToSlice(names, 0);
            return names;
        }
    };
};

fn parseImportSec(
    arena: *reservation_allocator.ArenaFallbackAllocator,
    type_sec: []const FuncType,
    counts: *const Sections.Counts,
    readers: *const Sections.Readers,
    scratch: *ArenaAllocator,
    diag: ParseDiagnostics,
) !ImportSec {
    defer _ = scratch.reset(.retain_capacity);

    const import_reader = readers.import;

    const TypesBuf = struct {
        funcs: std.SegmentedList(TypeIdx, 8) = .{},
        tables: std.SegmentedList(TableType, 1) = .{},
        mems: std.SegmentedList(MemType, 1) = .{},
        globals: std.SegmentedList(GlobalType, 4) = .{},
    };

    const NamesBuf = struct {
        funcs: std.SegmentedList(ImportName, 8) = .{},
        tables: std.SegmentedList(ImportName, 1) = .{},
        mems: std.SegmentedList(ImportName, 1) = .{},
        globals: std.SegmentedList(ImportName, 4) = .{},
    };

    // Allocated in `scratch`.
    // TODO(Zig): https://github.com/ziglang/zig/issues/19867
    var names = NamesBuf{};
    var import_types = TypesBuf{};

    var names_buf = try std.ArrayListUnmanaged(ImportName).initCapacity(
        arena.allocator(),
        counts.import,
    );

    const imports_start = import_reader.bytes.*.ptr;

    _ = scratch.reset(.retain_capacity);

    for (0..counts.import) |_| {
        if (import_reader.isEmpty()) {
            return diag.writeAll(.parse, "unexpected end of section or function, expected import");
        }

        const mod = try import_reader.readName(diag);
        const name = try import_reader.readName(diag);
        const import_name = ImportName{
            .module_offset = std.math.cast(
                u16,
                @intFromPtr(mod.bytes.ptr) - @intFromPtr(imports_start),
            ) orelse return error.WasmImplementationLimit, // too many imports
            .module_size = std.math.cast(u16, mod.bytes.len) orelse
                return error.WasmImplementationLimit, // too many imports

            .name_offset = std.math.cast(
                u16,
                @intFromPtr(name.bytes.ptr) - @intFromPtr(imports_start),
            ) orelse return error.WasmImplementationLimit, // too many imports
            .name_size = std.math.cast(u16, name.bytes.len) orelse
                return error.WasmImplementationLimit, // too many imports
        };

        const tag = try import_reader.readByteTag(ImportExportDesc, diag, "malformed import kind");
        (switch (tag) {
            inline else => |t| try @field(names, @tagName(t) ++ "s").addOne(scratch.allocator()),
        }).* = import_name;

        switch (tag) {
            .func => try import_types.funcs.append(
                scratch.allocator(),
                try import_reader.readIdx(
                    TypeIdx,
                    type_sec.len,
                    diag,
                    "unknown type for function import",
                ),
            ),
            .table => try import_types.tables.append(
                scratch.allocator(),
                try TableType.parse(import_reader, diag),
            ),
            .mem => try import_types.mems.append(
                scratch.allocator(),
                try MemType.parse(import_reader, diag),
            ),
            .global => try import_types.globals.append(
                scratch.allocator(),
                try GlobalType.parse(import_reader, diag),
            ),
        }
    }

    if (counts.mem + @as(u32, @intCast(names.mems.len)) > 1) {
        return diag.writeAll(.validation, "multiple memories are not yet supported");
    }

    try import_reader.expectEnd(diag, "import section size mismatch");
    import_reader.bytes.* = undefined;

    // Detect if code above accidentally added to the wrong name list.
    std.debug.assert(import_types.funcs.len == names.funcs.len);
    std.debug.assert(import_types.tables.len == names.tables.len);
    std.debug.assert(import_types.mems.len == names.mems.len);
    std.debug.assert(import_types.globals.len == names.globals.len);

    return ImportSec{
        .start = imports_start,
        .names = .{
            .funcs = try ImportSec.Names.moveToBuffer(&names_buf, 8, &names.funcs),
            .tables = try ImportSec.Names.moveToBuffer(&names_buf, 1, &names.tables),
            .mems = try ImportSec.Names.moveToBuffer(&names_buf, 1, &names.mems),
            .globals = try ImportSec.Names.moveToBuffer(&names_buf, 4, &names.globals),
        },
        .types = types: {
            var final_types: ImportSec.Types = undefined;
            var types_size = reservation_allocator.ReservationAllocator.zero;
            inline for (@typeInfo(ImportSec.Types).@"struct".fields) |f| {
                try types_size.reserve(
                    @typeInfo(@FieldType(ImportSec.Types, f.name)).pointer.child,
                    std.math.add(
                        u32,
                        @field(counts, f.name[0 .. f.name.len - 1]),
                        @intCast(@field(names, f.name).len),
                    ) catch return diag.writeAll(.parse, "too many " ++ f.name),
                );
            }

            var types_alloc = reservation_allocator.ArenaFallbackAllocator{
                .buffer = try types_size.bufferAllocator(arena.allocator()),
                .arena = arena.arena,
            };

            inline for (@typeInfo(ImportSec.Types).@"struct".fields[1..]) |f| {
                const src_types = &@field(import_types, f.name);
                const dst_types = try types_alloc.allocator().alloc(
                    @typeInfo(@FieldType(ImportSec.Types, f.name)).pointer.child,
                    src_types.len + @field(counts, f.name[0 .. f.name.len - 1]),
                );

                src_types.writeToSlice(dst_types[0..src_types.len], 0);

                @field(final_types, f.name) = dst_types;
            }

            {
                const dst_types = try types_alloc.allocator().alloc(
                    *const FuncType,
                    import_types.funcs.len + counts.func,
                );

                for (dst_types[0..import_types.funcs.len], 0..) |*func_ty, i| {
                    func_ty.* = &type_sec[@intFromEnum(import_types.funcs.at(i).*)];
                }

                final_types.funcs = dst_types;
            }

            break :types final_types;
        },
    };
}

fn parseFuncSec(
    type_sec: []const FuncType,
    import_types: *const ImportSec.Types,
    count: u32,
    readers: *const Sections.Readers,
    diag: ParseDiagnostics,
) !void {
    const func_reader = readers.func;
    const func_types = import_types.funcs;

    if (func_types.len > std.math.maxInt(@typeInfo(FuncIdx).@"enum".tag_type)) {
        return error.WasmImplementationLimit; // too many funcs
    }

    for (func_types[func_types.len - count ..], 0..count) |*func_ty, _| {
        const type_idx = try func_reader.readIdx(
            TypeIdx,
            type_sec.len,
            diag,
            "unknown type in 'func' section",
        );
        func_ty.* = &type_sec[@intFromEnum(type_idx)];
    }

    try func_reader.expectEnd(diag, "'func' section size mismatch");
    readers.func.bytes.* = undefined;
}

fn parseTableSec(
    import_types: *const ImportSec.Types,
    count: u32,
    readers: *const Sections.Readers,
    diag: ParseDiagnostics,
) !void {
    const table_reader = readers.table;
    const table_types = import_types.tables;

    if (table_types.len > std.math.maxInt(@typeInfo(TableIdx).@"enum".tag_type)) {
        return error.WasmImplementationLimit; // too many tables
    }

    for (table_types[table_types.len - count ..], 0..count) |*tt, _| {
        if (table_reader.isEmpty()) {
            return diag.writeAll(.parse, "unexpected end of section or function, expected table");
        }

        tt.* = try TableType.parse(table_reader, diag);
    }

    try table_reader.expectEnd(diag, "table section size mismatch");
    readers.table.bytes.* = undefined;
}

fn parseMemSec(
    import_types: *const ImportSec.Types,
    count: u32,
    readers: *const Sections.Readers,
    diag: ParseDiagnostics,
) !void {
    const mem_reader = readers.mem;
    const mem_types = import_types.mems;

    if (mem_types.len > std.math.maxInt(@typeInfo(MemIdx).@"enum".tag_type)) {
        return error.WasmImplementationLimit; // too many mems
    }

    // check std.math.maxInt(@typeInfo(MemIdx).@"enum".tag_type)

    for (import_types.mems[import_types.mems.len - count ..], 0..count) |*mem, _| {
        if (mem_reader.isEmpty()) {
            return diag.writeAll(.parse, "unexpected end of section or function, expected memory");
        }

        mem.* = try MemType.parse(mem_reader, diag);
    }

    try mem_reader.expectEnd(diag, "memory section size mismatch");
    readers.mem.bytes.* = undefined;
}

fn parseGlobalSec(
    arena: *reservation_allocator.ArenaFallbackAllocator,
    import_sec: *const ImportSec,
    count: u32,
    readers: *const Sections.Readers,
    diag: ParseDiagnostics,
) ![]const ConstExpr {
    const global_reader = readers.global;
    const global_types = import_sec.types.globals;
    const global_import_types = global_types[0..import_sec.names.globals.len];
    std.debug.assert(global_import_types.len + count == global_types.len);

    const global_exprs = try arena.allocator().alloc(ConstExpr, count);

    if (global_types.len > std.math.maxInt(@typeInfo(GlobalIdx).@"enum".tag_type)) {
        return error.WasmImplementationLimit; // too many globals
    }

    for (global_types[global_types.len - count ..], global_exprs) |*ty, *expr| {
        if (global_reader.isEmpty()) {
            return diag.writeAll(.parse, "unexpected end of section or function, expected global");
        }

        ty.* = try GlobalType.parse(global_reader, diag);
        expr.* = try ConstExpr.parse(
            global_reader,
            ty.val_type,
            @intCast(import_sec.types.funcs.len),
            global_import_types,
            diag,
            "global initializer",
        );
    }

    try global_reader.expectEnd(diag, "global section size mismatch");
    readers.global.bytes.* = undefined;
    return global_exprs;
}

const ExportSec = struct {
    start: [*]const u8,
    descs: []const Export,
};

fn parseExportSec(
    import_types: *const ImportSec.Types,
    arena: *reservation_allocator.ArenaFallbackAllocator,
    count: u32,
    readers: *const Sections.Readers,
    rng_seed: u64,
    scratch: *ArenaAllocator,
    diag: ParseDiagnostics,
) ParseError!ExportSec {
    const export_reader = readers.@"export";

    const ExportDedupContext = struct {
        seed: u64,

        pub fn eql(_: @This(), a: []const u8, b: []const u8) bool {
            return std.mem.eql(u8, a, b);
        }

        pub fn hash(ctx: @This(), name: []const u8) u64 {
            return std.hash.Wyhash.hash(ctx.seed, name);
        }
    };

    const descs = try arena.allocator().alloc(Export, count);

    var export_dedup = std.HashMapUnmanaged(
        []const u8,
        void,
        ExportDedupContext,
        std.hash_map.default_max_load_percentage,
    ).empty;

    const export_dedup_context = ExportDedupContext{ .seed = rng_seed };

    _ = scratch.reset(.retain_capacity);
    try export_dedup.ensureTotalCapacityContext(scratch.allocator(), count, export_dedup_context);
    defer _ = scratch.reset(.retain_capacity);

    const exports_start = export_reader.bytes.*.ptr;
    for (descs) |*ex| {
        if (export_reader.isEmpty()) {
            return diag.writeAll(.parse, "length out of bounds, expected export");
        }

        const name = try export_reader.readName(diag);
        if (export_dedup.getOrPutAssumeCapacityContext(name.bytes, export_dedup_context)
            .found_existing)
        {
            return diag.print(.validation, "duplicate export name \"{s}\"", .{name.bytes});
        }

        const tag = try export_reader.readByteTag(ImportExportDesc, diag, "export tag");

        ex.* = Export{
            .name_size = std.math.cast(u15, name.bytes.len) orelse
                return error.WasmImplementationLimit, // export name size
            .name_offset = std.math.cast(
                u16,
                @intFromPtr(name.bytes.ptr) - @intFromPtr(exports_start),
            ) orelse return error.WasmImplementationLimit, // export section size
            .desc_tag = switch (tag) {
                inline else => |desc_tag| @field(
                    std.meta.FieldEnum(Export.Desc),
                    @tagName(desc_tag),
                ),
            },
            .desc = switch (tag) {
                .func => .{
                    .func = try export_reader.readIdx(
                        FuncIdx,
                        import_types.funcs.len,
                        diag,
                        "unknown function in export",
                    ),
                },
                .table => .{
                    .table = try export_reader.readIdx(
                        TableIdx,
                        import_types.tables.len,
                        diag,
                        "unknown table in export",
                    ),
                },
                .mem => .{
                    .mem = try export_reader.readIdx(
                        MemIdx,
                        import_types.mems.len,
                        diag,
                        "unknown memory in export",
                    ),
                },
                .global => .{
                    .global = try export_reader.readIdx(
                        GlobalIdx,
                        import_types.globals.len,
                        diag,
                        "unknown global in export",
                    ),
                },
            },
        };
    }

    try export_reader.expectEnd(diag, "'export' section size mismatch");
    readers.@"export".bytes.* = undefined;
    return .{ .start = exports_start, .descs = descs };
}

const ElemSec = struct {
    segments: []const ElemSegment,
    active: []const ActiveElem,
    non_declarative_mask: []const u32,
};

fn parseElemSec(
    arena: *reservation_allocator.ArenaFallbackAllocator,
    readers: *const Sections.Readers,
    count: u32,
    import_types: *const ImportSec.Types,
    scratch: *ArenaAllocator,
    diag: ParseDiagnostics,
) !ElemSec {
    const elems_reader = readers.elem;

    if (count > std.math.maxInt(@typeInfo(ElemIdx).@"enum".tag_type)) {
        return error.WasmImplementationLimit; // too many element element segments
    }

    const elems = try arena.allocator().alloc(ElemSegment, count);
    const non_declarative_mask = try arena.allocator().alloc(
        u32,
        std.math.divCeil(u32, count, 32) catch unreachable,
    );
    @memset(non_declarative_mask, 0);

    _ = scratch.reset(.retain_capacity);
    var active_elems = std.SegmentedList(ActiveElem, 4){};
    defer _ = scratch.reset(.retain_capacity);

    const global_types_in_const = import_types.globals[0..import_types.globals.len];
    for (elems[0..count], 0..count) |*elem_segment, i| {
        const elem_idx: ElemIdx = @enumFromInt(
            @as(@typeInfo(ElemIdx).@"enum".tag_type, @intCast(i)),
        );

        const Tag = packed struct(u3) {
            kind: enum(u1) {
                active = 0,
                passive_or_declarative,
            },
            bit_1: packed union {
                active_has_table_idx: bool,
                is_declarative: bool,
            },
            use_elem_exprs: bool,
        };

        const tag_value = try elems_reader.readUleb128(u32, diag, "element segment tag");
        const tag: Tag = @bitCast(
            std.math.cast(u3, tag_value) orelse return diag.writeAll(
                .parse,
                "malformed element segment tag",
            ),
        );

        const ElemKind = enum(u8) { funcref = 0x00 };

        if (tag.kind == .active) {
            const table_idx: TableIdx = if (tag.bit_1.active_has_table_idx)
                try elems_reader.readIdx(
                    TableIdx,
                    import_types.tables.len,
                    diag,
                    "unknown table in element section",
                )
            else if (import_types.tables.len == 0)
                return diag.writeAll(.validation, "unknown table 0 in element section")
            else
                TableIdx.default;

            const offset = try ConstExpr.parse(
                elems_reader,
                .i32,
                @intCast(import_types.funcs.len),
                global_types_in_const,
                diag,
                "offset in element segment",
            );

            try active_elems.append(
                scratch.allocator(),
                ActiveElem{
                    .header = .{
                        .offset_tag = switch (offset) {
                            .@"global.get" => .@"global.get",
                            .i32_or_f32 => .@"i32.const",
                            else => unreachable,
                        },
                        .table = table_idx,
                        .elements = elem_idx,
                    },
                    .offset = switch (offset) {
                        .@"global.get" => |global_idx| .{ .@"global.get" = global_idx },
                        .i32_or_f32 => |n| .{ .@"i32.const" = n },
                        else => unreachable,
                    },
                },
            );
        } else {
            // TODO: maybe keep a list of passive segments too?
        }

        // std.debug.dumpHex(elems_reader.bytes.*);

        const ElemTypeParser = enum {
            none,
            elemkind,
            reftype,
        };

        // 3 0 1 | mode        | type parser
        // 0 0 0 | active      | none
        // 0 0 1 | passive     | elemkind
        // 0 1 0 | active      | elemkind
        // 0 1 1 | declarative | elemkind
        // 1 0 0 | active      | none
        // 1 0 1 | passive     | reftype
        // 1 1 0 | active      | reftype
        // 1 1 1 | declarative | reftype
        const elem_type_parser: ElemTypeParser = if (tag.kind == .active)
            if (!tag.bit_1.active_has_table_idx)
                .none
            else if (tag.use_elem_exprs)
                .reftype
            else
                .elemkind
        else if (tag.use_elem_exprs)
            .reftype
        else
            .elemkind;

        const ref_type = switch (elem_type_parser) {
            .none => ValType.funcref,
            .elemkind => func_type: {
                const elem_kind = try elems_reader.readByteTag(
                    ElemKind,
                    diag,
                    "malformed reference type",
                );
                std.debug.assert(elem_kind == .funcref);
                break :func_type ValType.funcref;
            },
            .reftype => try ValType.parse(elems_reader, diag),
        };

        if (!ref_type.isRefType()) {
            return diag.print(
                .parse,
                "malformed reference type {t} in element segment",
                .{ref_type},
            );
        }

        const expr_count = try elems_reader.readUleb128(
            u32,
            diag,
            "element segment expression count",
        );
        elem_segment.* = if (tag.use_elem_exprs) elem_exprs: {
            const exprs = try arena.allocator().alloc(ElemSegment.Expr, expr_count);
            for (exprs) |*e| {
                e.* = try ElemSegment.Expr.init(
                    try ConstExpr.parse(
                        elems_reader,
                        ref_type,
                        @intCast(import_types.funcs.len),
                        global_types_in_const,
                        diag,
                        "element segment expression",
                    ),
                    diag,
                );
            }

            break :elem_exprs ElemSegment{
                .tag = switch (ref_type) {
                    .funcref => .func_expressions,
                    .externref => .extern_expressions,
                    else => unreachable,
                },
                .len = expr_count,
                .contents = .{ .expressions = exprs.ptr },
            };
        } else idx_exprs: {
            std.debug.assert(ref_type == .funcref);
            const func_indices = try arena.allocator().alloc(FuncIdx, expr_count);
            for (func_indices) |*idx| {
                idx.* = try elems_reader.readIdx(
                    FuncIdx,
                    import_types.funcs.len,
                    diag,
                    "unknown function index in element segment",
                );
            }

            break :idx_exprs ElemSegment{
                .tag = .func_indices,
                .len = expr_count,
                .contents = .{ .func_indices = func_indices.ptr },
            };
        };

        const is_declarative = tag.kind == .passive_or_declarative and tag.bit_1.is_declarative;
        non_declarative_mask[std.math.divCeil(u32, @intCast(i), 32) catch unreachable] |=
            @as(u32, @intFromBool(!is_declarative)) << @as(u5, @intCast(i % 32));
    }

    try elems_reader.expectEnd(diag, "element section size mismatch");
    readers.elem.bytes.* = undefined;

    return .{
        .segments = elems,
        .non_declarative_mask = non_declarative_mask,
        .active = active: {
            const active = try arena.allocator().alloc(ActiveElem, active_elems.len);
            active_elems.writeToSlice(active, 0);
            break :active active;
        },
    };
}

const CodeSec = struct {
    start: [*]const u8,
    entries: []const Code.Entry,
    code: []Code,
};

pub fn parseCodeSec(
    arena: *reservation_allocator.ArenaFallbackAllocator,
    readers: *const Sections.Readers,
    count: u32,
    diag: ParseDiagnostics,
) !CodeSec {
    const code_reader = readers.code;

    const entries = try arena.allocator().alloc(Code.Entry, count);
    const validation = try arena.allocator().alloc(Code, count);

    const code_start = code_reader.bytes.*.ptr;
    for (entries) |*code_entry| {
        const contents = try code_reader.readByteVec(diag, "code section entry");
        code_entry.* = .{
            .contents = .{
                .size = @intCast(contents.len),
                .offset = @intCast(@intFromPtr(contents.ptr) - @intFromPtr(code_start)),
            },
        };
    }

    @memset(validation, .{ .inner = Code.validation_failed });

    try code_reader.expectEnd(diag, "'code' section size mismatch");
    readers.code.bytes.* = undefined;
    return .{
        .start = code_start,
        .entries = entries,
        .code = validation,
    };
}

const DataSec = struct {
    datas_ptrs: []const [*]const u8,
    datas_lens: []const u32,
    active_datas: []const ActiveData,
};

fn parseDataSec(
    arena: *reservation_allocator.ArenaFallbackAllocator,
    readers: *const Sections.Readers,
    count: u32,
    import_sec: *const ImportSec,
    scratch: *ArenaAllocator,
    diag: ParseDiagnostics,
) !DataSec {
    const datas_reader = readers.data;

    if (count > std.math.maxInt(@typeInfo(DataIdx).@"enum".tag_type)) {
        return error.WasmImplementationLimit; // too many data segments
    }

    const data_ptrs = try arena.allocator().alloc([*]const u8, count);
    const data_lens = try arena.allocator().alloc(u32, count);

    _ = scratch.reset(.retain_capacity);
    var active_datas = std.SegmentedList(ActiveData, 1){};
    defer _ = scratch.reset(.retain_capacity);

    for (data_ptrs, data_lens, 0..count) |*ptr, *len, i| {
        if (datas_reader.isEmpty()) {
            return diag.writeAll(
                .parse,
                "unexpected end of section or function, expected data segment",
            );
        }

        const data_idx: DataIdx = @enumFromInt(
            @as(@typeInfo(DataIdx).@"enum".tag_type, @intCast(i)),
        );

        const Flags = packed struct(u2) {
            is_passive: bool,
            has_mem_idx: bool,
        };

        const flags_int = try datas_reader.readUleb128Casted(u32, u2, diag, "data segment flag");
        if (flags_int > 2) {
            return diag.writeAll(.parse, "malformed data segment flag");
        }

        const flags: Flags = @bitCast(flags_int);
        if (!flags.is_passive) {
            const memory: MemIdx = if (flags.has_mem_idx)
                try datas_reader.readIdx(
                    MemIdx,
                    import_sec.types.mems.len,
                    diag,
                    "unknown memory in data segment",
                )
            else if (import_sec.types.mems.len == 0)
                return diag.writeAll(.validation, "unknown memory 0 in data segment")
            else
                MemIdx.default;

            const offset = try ConstExpr.parse(
                datas_reader,
                .i32,
                @intCast(import_sec.types.funcs.len),
                import_sec.types.globals[0..import_sec.names.globals.len],
                diag,
                "data segment offset",
            );

            try active_datas.append(
                scratch.allocator(),
                ActiveData{
                    .header = .{
                        .memory = memory,
                        .offset_tag = switch (offset) {
                            .i32_or_f32 => .@"i32.const",
                            .@"global.get" => .@"global.get",
                            else => unreachable,
                        },
                    },
                    .data = data_idx,
                    .offset = switch (offset) {
                        .i32_or_f32 => |n| .{ .@"i32.const" = n },
                        .@"global.get" => |global| .{ .@"global.get" = global },
                        else => unreachable,
                    },
                },
            );
        }

        const contents_len = try datas_reader.readUleb128(u32, diag, "data segment length");
        if (datas_reader.bytes.len < contents_len) {
            return diag.print(
                .parse,
                "unexpected end of section or function, data segment has length {}, but {}" ++
                    " bytes were remaining",
                .{ contents_len, datas_reader.bytes.len },
            );
        }

        const contents = datas_reader.readAssumeLength(contents_len);
        ptr.* = contents.ptr;
        len.* = contents_len;
    }

    try datas_reader.expectEnd(diag, "data section size mismatch");
    readers.data.bytes.* = undefined;
    return .{
        .datas_ptrs = data_ptrs,
        .datas_lens = data_lens,
        .active_datas = active: {
            const active = try arena.allocator().alloc(ActiveData, active_datas.len);
            active_datas.writeToSlice(active, 0);
            break :active active;
        },
    };
}

/// Returns `false` if validation of one of the functions began in another thread and did not yet finish.
pub fn finishCodeValidation(
    module: Module,
    allocator: Allocator,
    scratch: *ArenaAllocator,
    diag: ParseDiagnostics,
) validator.Error!bool {
    var all_validated = true;
    for (module.inner.raw.code[0..module.inner.raw.code_count]) |*code_entry| {
        _ = scratch.reset(.retain_capacity);
        all_validated = all_validated and try code_entry.validate(
            allocator,
            module,
            scratch,
            diag,
        );
    }

    // unreachable; // allows print debugging in validation code when interpreter also has print statements
    return all_validated;
}

// TODO: need separate allocator to free code entries
pub fn deinit(module: Module, gpa: Allocator) void {
    gpa.free(module.arena_data);
    module.* = undefined;
}

const std = @import("std");
const Type = std.builtin.Type;
const Writer = std.Io.Writer;
const Allocator = std.mem.Allocator;
const ArenaAllocator = std.heap.ArenaAllocator;
const reservation_allocator = @import("reservation_allocator.zig");
const Reader = @import("Module/Reader.zig");
const opcodes = @import("opcodes.zig");
const validator = @import("Module/validator.zig");
