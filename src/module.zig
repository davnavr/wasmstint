/// Slices are manually split into length and ptr fields to shave a few bytes off the size.
pub const Inner = struct {
    /// Contains fields accessed from assembly or LLVM IR code.
    ///
    /// Deleting or reordering fields requires updating the code generation for the x86-64 assembly
    /// and LLVM IR interpreter backends.
    const Ffi = extern struct {
        types: [*]const Module.FuncType,
        global_types: [*]const Module.GlobalType,
        datas_ptrs: [*]const [*]const u8,
        datas_lens: [*]const u32,
    };

    pub fn ofModule(module: anytype) (switch (@TypeOf(module)) {
        *Module => *Inner,
        *const Module => *const Inner,
        else => |bad| @compileError(@typeName(bad) ++ " is not a module pointer"),
    }) {
        return @fieldParentPtr("module", switch (@TypeOf(module)) {
            *Module => module,
            *const Module => @constCast(module),
            else => comptime unreachable,
        });
    }

    /// Arranged such that a `*Ffi` is also a valid `*Module`.
    module: Module,

    wasm: []const u8,

    types_count: u22,
    /// Nicer but less space efficient to store pointers rather than `TypeIdx`.
    func_types: [*]const *const Module.FuncType,
    // types (`[]const FuncType`) used in FFI

    /// Not set if the total # of imports is zero.
    import_section: [*]const u8,
    func_imports: [*]const Module.ImportName,
    func_import_count: u22,
    table_imports: [*]const Module.ImportName,
    table_import_count: u8,
    mem_imports: [*]const Module.ImportName,
    mem_import_count: u8,
    global_imports: [*]const Module.ImportName,
    global_import_count: u22,

    /// Set of functions that are allowed to be used with `ref.func` in function bodies.
    ///
    /// See: https://webassembly.github.io/spec/core/valid/conventions.html#context
    func_refs: FuncRefs.Lookup,

    /// Total number of tables, including imports.
    table_count: u8,
    table_types: [*]const Module.TableType,

    /// Total number of memories, including imports.
    mem_count: u8,
    mem_types: [*]const Module.MemType,

    /// Total number of globals, including imports.
    global_count: u22,
    /// Not set if the number of defined globals is zero.
    global_section: [*]const u8,
    global_exprs: [*]const GlobalExpr,
    // global types (`[]const GlobalType`) used in FFI

    export_section: [*]const u8,
    exports: Module.Export.Lookup,
    exports_hash_seed: u64,

    start: Start,

    elem_section: [*]const u8,
    /// The total number of element segments.
    elems_count: u16,
    elems: [*]const Module.ElemSegment,
    /// The number of element segments that are `active` element segments.
    active_elems_count: u16,
    active_elems: [*]const Module.ActiveElem,
    /// A bitmask indicating which data segments are passive or active.
    ///
    /// This mask is used during module instantiation, as declarative element segments
    /// are "dropped" (their length is set to zero).
    non_declarative_elems_mask: [*]const u32,

    has_data_count_section: bool,

    code_count: u22,
    /// Not set if `code_count == 0`.
    code_section: [*]const u8,
    code_entries: [*]const Module.Code.Entry,
    code: [*]Module.Code,

    /// The total number of data segments.
    datas_count: u16,
    data_section: [*]const u8,
    /// The number of data segments that are `active` data segments.
    active_datas_count: u16,
    active_datas: [*]const Module.ActiveData,
    // data pointers and lengths used in FFI

    custom_sections_count: u32,
    custom_sections: [*]const Module.CustomSection,
    name_section: *const Module.NameSection,

    /// The maximum stack height required to evaluate all of the module's constant expressions.
    init_max_stack: u16,
    runtime_shape: @import("wasmstint").runtime.ModuleInst.Shape,

    arena: ArenaAllocator.State,
};

const GlobalExpr = struct {
    init: Module.ConstExpr,

    pub fn bytes(
        expr: GlobalExpr,
        module: *const Module,
    ) [:@intFromEnum(opcodes.ByteOpcode.end)]const u8 {
        return expr.init.bytes(module.internal().global_section, module);
    }
};

const Start = packed struct(u22) {
    exists: bool,
    idx: Module.FuncIdx,

    pub fn get(start: Start) ?Module.FuncIdx {
        return if (start.exists) start.idx else null;
    }
};

const OffsetExpr = struct {
    /// Must evaluate to an `i32`.
    value: Module.ConstExpr,
};

fn enumMaxValue(comptime E: type) @typeInfo(E).@"enum".tag_type {
    return std.math.maxInt(@typeInfo(E).@"enum".tag_type);
}

/// A parsed and validated WebAssembly module.
///
/// Do not initialize this struct directly.
pub const Module = extern struct {
    pub const ValType = @import("module/val_type.zig").ValType;
    pub const FuncType = @import("module/func_type.zig").FuncType;

    pub const TypeIdx = enum(u21) {
        _,

        pub fn funcType(idx: TypeIdx, module: *const Module) *const FuncType {
            return &module.types()[@intFromEnum(idx)];
        }
    };

    pub const FuncIdx = enum(u21) {
        _,

        pub inline fn signature(idx: FuncIdx, module: *const Module) *const FuncType {
            return module.func_types()[@intFromEnum(idx)];
        }

        /// Returns `null` if the `FuncIdx` refers to a function import.
        pub fn code(idx: FuncIdx, module: *const Module) ?*Code {
            if (@intFromEnum(idx) < module.funcImportCount()) {
                return null;
            } else {
                const definition_index = @intFromEnum(idx) - module.funcImportCount();
                return &module.internal().code[0..module.funcDefinedCount()][definition_index];
            }
        }
    };

    pub const GlobalIdx = enum(u21) {
        _,
    };

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
    pub const DataIdx = enum(u16) {
        _,

        pub inline fn contents(idx: DataIdx, module: *const Module) []const u8 {
            const i = @intFromEnum(idx);
            std.debug.assert(i < module.internal().datas_count);
            return module.inner.datas_ptrs[i][0..module.inner.datas_lens[i]];
        }
    };

    /// Internal API. Do not modify these fields.
    inner: Inner.Ffi,

    const internal = Inner.ofModule;

    /// A slice of the original WASM module.
    pub inline fn wasmBytes(module: *const Module) []const u8 {
        return module.internal().wasm;
    }

    pub inline fn customSections(module: *const Module) []const CustomSection {
        return module.internal().custom_sections[0..module.internal().custom_sections_count];
    }

    pub inline fn typeCount(module: *const Module) u32 {
        return module.internal().types_count;
    }

    pub inline fn types(module: *const Module) []const FuncType {
        return module.inner.types[0..module.typeCount()];
    }

    pub inline fn funcImportCount(module: *const Module) u32 {
        return module.internal().func_import_count;
    }

    pub inline fn funcDefinedCount(module: *const Module) u32 {
        return module.internal().code_count;
    }

    /// Total number of imported and defined functions.
    pub inline fn funcCount(module: *const Module) u32 {
        return module.funcImportCount() + module.funcDefinedCount();
    }

    pub inline fn funcTypes(module: *const Module) []const *const FuncType {
        return module.internal().func_types[0..module.funcCount()];
    }

    /// Gets the `TypeIdx` used as the given function's.
    pub inline fn funcTypeIdx(module: *const Module, func: FuncIdx) TypeIdx {
        const func_idx: @typeInfo(FuncIdx).@"enum".tag_type = @intFromEnum(func);
        std.debug.assert(func_idx < module.funcTypes().len);

        const type_ptr = @intFromPtr(@as(*const FuncType, module.funcTypes()[func_idx]));
        const type_count = module.typeCount();
        std.debug.assert( // out of bounds type
            type_ptr < @intFromPtr(@as(*const FuncType, &module.types().ptr[type_count])),
        );
        const idx = (type_ptr - @intFromPtr(module.inner.types)) / @sizeOf(FuncType);
        std.debug.assert(idx < type_count);
        return @enumFromInt(idx);
    }

    pub inline fn funcImportNames(module: *const Module) []const ImportName {
        return module.internal().func_imports[0..module.funcImportCount()];
    }

    pub inline fn funcImportTypes(module: *const Module) []const *const FuncType {
        return module.funcTypes()[0..module.funcImportCount()];
    }

    /// Returns `true` if a `ref.func` instruction can be used with the given function.
    ///
    /// See: https://webassembly.github.io/spec/core/valid/conventions.html#context
    pub fn funcIsReferencable(module: *const Module, idx: FuncIdx) bool {
        // Don't need to check for imports, as the set already contains it
        // @intFromEnum(idx) < module.inner.func_import_count or
        return module.internal().func_refs.containsContext(idx, .{});
    }

    /// Total number of imported and defined tables.
    pub inline fn tableCount(module: *const Module) u32 {
        return module.internal().table_count;
    }

    pub inline fn tableImportCount(module: *const Module) u32 {
        return module.internal().table_import_count;
    }

    pub inline fn tableTypes(module: *const Module) []const TableType {
        return module.internal().table_types[0..module.tableCount()];
    }

    pub inline fn tableImportNames(module: *const Module) []const ImportName {
        return module.internal().table_imports[0..module.tableImportCount()];
    }

    pub inline fn tableImportTypes(module: *const Module) []const TableType {
        return module.tableTypes()[0..module.tableImportCount()];
    }

    pub inline fn tableDefinedTypes(module: *const Module) []const TableType {
        return module.tableTypes()[module.tableImportCount()..];
    }

    /// Total number of imported and defined memories.
    pub inline fn memCount(module: *const Module) u32 {
        return module.internal().mem_count;
    }

    pub inline fn memImportCount(module: *const Module) u32 {
        return module.internal().mem_import_count;
    }

    pub inline fn memTypes(module: *const Module) []const MemType {
        return module.internal().mem_types[0..module.memCount()];
    }

    pub inline fn memImportNames(module: *const Module) []const ImportName {
        return module.internal().mem_imports[0..module.memImportCount()];
    }

    pub inline fn memImportTypes(module: *const Module) []const MemType {
        return module.memTypes()[0..module.memImportCount()];
    }

    pub inline fn memDefinedTypes(module: *const Module) []const MemType {
        return module.memTypes()[module.memImportCount()..];
    }

    /// Total number of imported and defined globals.
    pub inline fn globalCount(module: *const Module) u32 {
        return module.internal().global_count;
    }

    pub inline fn globalImportCount(module: *const Module) u32 {
        return module.internal().global_import_count;
    }

    pub inline fn globalDefinedCount(module: *const Module) u32 {
        return module.globalCount() - module.globalImportCount();
    }

    pub fn globalTypes(module: *const Module) []const GlobalType {
        return module.inner.global_types[0..module.globalCount()];
    }

    pub inline fn globalImportNames(module: *const Module) []const ImportName {
        return module.internal().global_imports[0..module.globalImportCount()];
    }

    pub inline fn globalImportTypes(module: *const Module) []const GlobalType {
        return module.globalTypes()[0..module.globalImportCount()];
    }

    pub inline fn globalDefinedTypes(module: *const Module) []const GlobalType {
        return module.globalTypes()[module.globalImportCount()..];
    }

    pub inline fn globalInitializers(module: *const Module) []const GlobalExpr {
        return module.internal().global_exprs[0..module.globalDefinedCount()];
    }

    pub inline fn codeEntries(module: *const Module) []const Code.Entry {
        return module.internal().code_entries[0..module.funcDefinedCount()];
    }

    pub inline fn code(module: *const Module) []const Code {
        return module.internal().code[0..module.funcDefinedCount()];
    }

    pub inline fn dataSegmentCount(module: *const Module) u32 {
        return module.internal().datas_count;
    }

    pub inline fn elementSegmentCount(module: *const Module) u32 {
        return module.internal().elems_count;
    }

    pub inline fn elementSegments(module: *const Module) []const ElemSegment {
        return module.internal().elems[0..module.elementSegmentCount()];
    }

    pub inline fn exports(module: *const Module) []const Export {
        return module.internal().exports.keys();
    }

    pub inline fn findExport(module: *const Module, name: []const u8) ?Export {
        return module.internal().exports.getKeyAdapted(
            name,
            Export.LookupContext{ .module = module },
        );
    }

    pub inline fn nameSection(module: *const Module) *const NameSection {
        return module.internal().name_section;
    }

    pub const WasmSlice = extern struct {
        offset: u32,
        size: u32,

        pub fn slice(
            s: WasmSlice,
            /// `base` is a pointer into `wasm`, usually referring to the first byte of some
            /// particular section after its count.
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

    /// An UTF-8 string.
    pub const Name = struct {
        ptr: [*]const u8,
        len: u16,

        /// Asserts that `name` is valid UTF-8 and `name.len <= std.math.maxInt(u16)`.
        pub fn init(name: []const u8) Name {
            std.debug.assert(std.unicode.utf8ValidateSlice(name));
            return .{ .ptr = name.ptr, .len = @intCast(name.len) };
        }

        pub fn bytes(name: Name) []const u8 {
            return name.ptr[0..name.len];
        }

        /// Prints a WebAssembly Text Format [string literal], emitting escape sequences for
        /// non-printable and non-ASCII characters.
        ///
        /// [string literal]: https://webassembly.github.io/spec/core/text/values.html#strings
        pub fn format(name: Name, writer: *Writer) Writer.Error!void {
            var remaining = name.bytes();
            try writer.writeByte('\"');
            while (remaining.len > 0) {
                switch (remaining[0]) {
                    '\t' => try writer.writeAll("\\t"),
                    '\n' => try writer.writeAll("\\n"),
                    '\r' => try writer.writeAll("\\r"),
                    '\"' => try writer.writeAll("\\\""),
                    '\'' => try writer.writeAll("\\'"),
                    '\\' => try writer.writeAll("\\\\"),
                    else => if (std.ascii.isPrint(remaining[0])) {
                        try writer.writeByte(remaining[0]);
                        remaining = remaining[1..];
                        continue;
                    } else {
                        // Unicode escape sequence
                        const utf8_len = std.unicode.utf8ByteSequenceLength(remaining[0]) catch
                            unreachable;

                        const codepoint = switch (utf8_len) {
                            1 => remaining[0],
                            2 => std.unicode.utf8Decode2(remaining[0..2].*) catch unreachable,
                            3 => std.unicode.utf8Decode3(remaining[0..3].*) catch unreachable,
                            4 => std.unicode.utf8Decode4(remaining[0..4].*) catch unreachable,
                            else => unreachable,
                        };

                        remaining = remaining[utf8_len..];
                        try writer.print("\\u{{{x}}}", .{codepoint});
                        continue;
                    },
                }

                remaining = remaining[1..];
            }
            try writer.writeByte('\"');
        }

        /// Prints a WebAssembly Text Format [identifier].
        ///
        /// [identifier]: https://webassembly.github.io/spec/core/text/values.html#text-id
        pub fn formatIdentifier(name: Name, writer: *Writer) Writer.Error!void {
            try writer.writeByte('$');
            const contents = name.bytes();
            string: {
                for (contents) |c| {
                    if (!std.ascii.isPrint(c)) break :string;

                    switch (c) {
                        ' ', '"', ',', ';', '{', '}', '(', ')', '[', ']' => break :string,
                        else => continue,
                    }
                }

                // No string literal needed
                try writer.writeAll(contents);
                return;
            }

            try name.format(writer);
        }

        pub fn fmtIdentifier(name: Name) std.fmt.Alt(Name, formatIdentifier) {
            return .{ .data = name };
        }
    };

    pub const ImportName = struct {
        name_offset: u16,
        name_size: u16,

        module_offset: u16,
        module_size: u16,

        pub inline fn desc(self: ImportName, mod: *const Module) Name {
            const name_slice = WasmSlice{ .offset = self.name_offset, .size = self.name_size };
            return Name.init(name_slice.slice(mod.internal().import_section, mod.wasmBytes()));
        }

        pub inline fn module(self: ImportName, mod: *const Module) Name {
            const name_slice = WasmSlice{ .offset = self.module_offset, .size = self.module_size };
            return Name.init(name_slice.slice(mod.internal().import_section, mod.wasmBytes()));
        }
    };

    /// A definition exported by this `Module` that is available after it is instantiated.
    pub const Export = packed struct(u63) {
        desc: Desc,
        desc_tag: Desc.Tag,
        name_size: u14,
        name_offset: u16,

        // TODO: Consider storing name bits in key, since value would be Desc (21 bits) & Tag (2 bits)
        const Lookup = std.array_hash_map.Custom(Export, void, void, true);

        const LookupContext = struct {
            module: *const Module,

            pub fn eql(ctx: @This(), a: []const u8, b: Export, _: usize) bool {
                return std.mem.eql(u8, a, b.name(ctx.module).bytes());
            }

            pub fn hash(ctx: @This(), n: []const u8) u32 {
                return @truncate(std.hash.Wyhash.hash(ctx.module.internal().exports_hash_seed, n));
            }
        };

        /// Indicates the index of the definition that is exported.
        pub const Desc = packed union {
            func: PackedIdx(FuncIdx),
            table: PackedIdx(TableIdx),
            mem: PackedIdx(MemIdx),
            global: PackedIdx(GlobalIdx),

            pub const Tag = std.meta.FieldEnum(Desc);

            fn PackedIdx(comptime Idx: type) type {
                return packed struct(u31) {
                    idx: Idx,
                    padding: @Int(.unsigned, 31 - @bitSizeOf(Idx)) = 0,
                };
            }
        };

        pub inline fn name(ex: Export, module: *const Module) Module.Name {
            const name_slice = WasmSlice{ .offset = ex.name_offset, .size = ex.name_size };
            const bytes = name_slice.slice(module.internal().export_section, module.wasmBytes());
            return Module.Name.init(bytes);
        }

        pub const DescIdx = t: {
            const src_fields = @typeInfo(Desc).@"union".fields;
            break :t @Union(
                .auto,
                std.meta.FieldEnum(Desc),
                names: {
                    var names: [src_fields.len][]const u8 = undefined;
                    for (src_fields, &names) |src, *dst| {
                        dst.* = src.name;
                    }
                    break :names &names;
                },
                types: {
                    var field_types: [src_fields.len]type = undefined;
                    for (src_fields, &field_types) |src, *dst| {
                        dst.* = @FieldType(src.type, "idx");
                    }
                    break :types &field_types;
                },
                &(.{std.builtin.Type.UnionField.Attributes{}} ** src_fields.len),
            );
        };

        pub fn descIdx(ex: Export) DescIdx {
            return switch (ex.desc_tag) {
                inline else => |tag| @unionInit(
                    DescIdx,
                    @tagName(tag),
                    @field(ex.desc, @tagName(tag)).idx,
                ),
            };
        }
    };

    /// Indicates the minimum and maximum sizes in `MemType`s and `TableType`s.
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
            /// For memories, spec test assumes limits do not exceed bounds before comparing `min`
            /// and `max`.
            comptime checkLimitsBounds: fn (
                Limits,
                diag: ?*ParseDiagnostics,
            ) Reader.ValidationError!void,
            diag: ?*ParseDiagnostics,
        ) !Limits {
            const LimitsFlag = enum(u2) {
                no_maximum = 0x00,
                has_maximum = 0x01,
            };

            const flag_byte = try reader.readByte(diag, "limits flag");
            // For some reason, spec test checks that the flag is a LEB128, despite the spec not
            // mentioning this.
            if (flag_byte & 0x80 != 0) {
                return Reader.fail(diag, .parse, "limits flag integer representation too long");
            }

            // If 64-bit memory and/or shared memory is used, limits is a LEB128 u32?
            // const flag = try reader.readUleb128Enum(u32, LimitsFlag, diag, "limits flag");
            const flag = std.enums.fromInt(LimitsFlag, flag_byte) orelse {
                return Reader.failPrint(
                    diag,
                    .parse,
                    "limits flag integer too large: 0x{X:0>2}",
                    .{flag_byte},
                );
            };

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
                Reader.failPrint(
                    diag,
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

        fn noLimitsBounds(_: Limits, _: ?*ParseDiagnostics) Reader.ValidationError!void {}

        fn parse(reader: Reader, diag: ?*ParseDiagnostics) !TableType {
            const elem_type = try ValType.parse(reader, diag);
            return if (!elem_type.isRefType())
                Reader.failPrint(diag, .parse, "{} must be a reference type", .{elem_type})
            else
                TableType{
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

        fn checkMemoryLimits(limits: Limits, diag: ?*ParseDiagnostics) Reader.ValidationError!void {
            if (limits.min > 65536 or limits.max > 65536) {
                return Reader.failPrint(
                    diag,
                    .validation,
                    "memory size must be at most 65536 pages (4GiB), got {}",
                    .{if (limits.min > 65536) limits.min else limits.max},
                );
            }
        }

        fn parse(reader: Reader, diag: ?*ParseDiagnostics) !MemType {
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

        fn parse(reader: Reader, diag: ?*ParseDiagnostics) Reader.Error!GlobalType {
            const val_type = try ValType.parse(reader, diag);
            return if (val_type == .v128 and !wasm_features.simd128)
                Reader.fail(diag, .parse, "invalid global type, " ++ Reader.no_simd_message)
            else
                GlobalType{
                    .val_type = val_type,
                    .mut = try reader.readByteTag(
                        GlobalType.Mut,
                        diag,
                        "malformed mutability flag",
                    ),
                };
        }
    };

    pub const ConstExpr = @import("module/ConstExpr.zig");

    pub const ElemSegment = struct {
        header: packed struct(u32) {
            tag: Tag,
            /// When the `contents` are expressions, this counts the total number of instructions in
            /// each element expression.
            ///
            /// Set to `0` when tag` is `.func_indices`.
            instruction_count: u15,
            /// Maximum height of value stack needed to evaluate all elements.
            elem_max_stack: u15,
        },
        len: u32,
        contents: Contents,

        pub const Tag = enum(u2) {
            func_indices,
            func_expressions,
            extern_expressions,
        };

        pub inline fn elementType(elem: *const ElemSegment) ValType {
            return switch (elem.header.tag) {
                .func_indices, .func_expressions => .funcref,
                .extern_expressions => .externref,
            };
        }

        pub const Contents = union {
            func_indices: [*]const FuncIdx,
            expressions: [*]const Expr,
        };

        pub const Expr = struct {
            /// Must evaluate to a value that is of a reference type.
            init: ConstExpr,

            pub fn bytes(
                expr: Expr,
                module: *const Module,
            ) [:@intFromEnum(opcodes.ByteOpcode.end)]const u8 {
                return expr.init.bytes(module.internal().elem_section, module);
            }
        };
    };

    const ActiveElem = struct {
        // header: packed struct (u32) { fuel_count: u25, table: TableIdx, },
        table: TableIdx,
        elements: ElemIdx,
        offset: OffsetExpr,

        pub fn offsetBytes(
            elem: *const ActiveElem,
            module: *const Module,
        ) [:@intFromEnum(opcodes.ByteOpcode.end)]const u8 {
            return elem.offset.value.bytes(module.internal().elem_section, module);
        }
    };

    pub const Code = validator.Code;

    const ActiveData = struct {
        memory: MemIdx,
        data: DataIdx,
        offset: OffsetExpr,

        pub fn offsetBytes(
            data: *const ActiveData,
            module: *const Module,
        ) [:@intFromEnum(opcodes.ByteOpcode.end)]const u8 {
            return data.offset.value.bytes(module.internal().data_section, module);
        }
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

    pub const NameSection = @import("module/NameSection.zig");

    /// Marks the start of a WebAssembly module in the binary format.
    pub const wasm_preamble = "\x00asm\x01\x00\x00\x00";

    pub const LimitError = Reader.LimitError;

    pub const ParseError = Reader.ValidationError || Reader.Error || LimitError ||
        std.mem.Allocator.Error;

    pub const ParseDiagnostics = Reader.Diagnostics;

    pub const ParseOptions = struct {
        /// If set to `true`, any custom sections encountered during parsing can later be accessed
        /// by calling `.customSections()`.
        keep_custom_sections: bool = false,
        /// Random seed provided to hash maps, such as the one used for ensuring all exports have unique
        /// names.
        random_seed: u64 = 42,
        /// Stores a description describing why parsing or validation of the `Module` failed.
        diagnostics: ?*ParseDiagnostics = null,
        /// Whether or not to parse the custom `name` section, if it exists in the parsed module.
        parse_names: Metadata = .parse_without_diagnostics,
        // /// Whether or not to parse embedded DWARF debug information, if it exists in the parsed module.
        // parse_dwarf_metadata: Metadata = .ignore,

        /// Indicates whether custom sections containing metadata should be parsed.
        pub const Metadata = union(enum) {
            ignore,
            parse: ?*ParseDiagnostics,

            /// The custom section should be parsed without any `ParseDiagnostics`.
            pub const parse_without_diagnostics = Metadata{ .parse = null };
        };
    };

    /// Parses a WebAssembly binary.
    ///
    /// Validation of function bodies occurs as a separate step, to support lazy validation or to
    /// speed up validation using multiple threads. To validation all function bodies, one can also
    /// call `finishCodeValidation()`.
    pub fn parse(
        gpa: Allocator,
        /// Pointer refering to the WebAssembly binary module to parse.
        ///
        /// If a parser error occurs, this points to where.
        wasm: *[]const u8,
        /// Used for temporary allocations that live for the rest of this function call.
        alloca: *ArenaAllocator,
        options: ParseOptions,
    ) ParseError!*Module {
        var coz_transaction = coz.begin("wasmstint.Module.parse");
        defer coz_transaction.end();

        _ = alloca.reset(.retain_capacity);
        const diag = options.diagnostics;
        const original_wasm = wasm.*;

        if (!std.mem.startsWith(u8, wasm.*, wasm_preamble)) {
            return Reader.fail(
                diag,
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

        var custom_sections_buf = std.ArrayList(CustomSection).empty; // in `alloca`

        var known_sections: Sections.Known = undefined;
        var sections = sections: {
            const wasm_reader = Reader.init(wasm);
            errdefer wasm.* = wasm_reader.bytes.*;
            _ = wasm_reader.readAssumeLength(wasm_preamble.len);
            break :sections try Sections
                .parse(wasm_reader, &known_sections, alloca, &custom_sections_buf, &options);
        };

        const has_data_count_section = !sections.readers.data_count.isEmpty();

        const counts = try Sections.Counts.parse(&sections.readers, diag);

        if (counts.type > enumMaxValue(TypeIdx)) {
            return Reader.fail(diag, .implementation_limit, "too many types");
        }

        if (counts.import > max_import_count) {
            return errorTooManyImports(diag);
        }

        if (counts.elem > enumMaxValue(ElemIdx)) {
            return Reader.fail(diag, .implementation_limit, "too many element segments");
        }

        if (counts.data > enumMaxValue(DataIdx)) {
            return Reader.fail(diag, .implementation_limit, "too many data segments");
        }

        if (has_data_count_section and counts.data_count != counts.data) {
            return Reader.fail(
                diag,
                .parse,
                "data count and data section have inconsistent lengths",
            );
        }

        try sections.readers.data_count.expectEnd(diag, "data count section size mismatch");

        // Since the total number of functions, globals, tables, memories, etc. aren't known until
        // imports are parsed, they are stored in a separate allocation.
        const fixed_layout = layout: {
            var calc = allocators.Reservation{};
            // Order of reservations must exactly match the order of allocations.
            calc.reserveAligned(Inner, .fromByteUnits(std.atomic.cache_line), 1) catch unreachable;
            try calc.reserve(FuncType, counts.type);
            try calc.reserve(ImportName, counts.import);
            try calc.reserve(GlobalExpr, counts.global);
            // Can't guess how many bytes for `Export.Lookup` for large number of exports
            try calc.reserve(CustomSection, custom_sections_buf.items.len);
            try calc.reserve(ElemSegment, counts.elem);
            const non_declarative_elems_mask =
                std.math.divCeil(u32, @intCast(counts.elem), 32) catch unreachable;
            try calc.reserve(u32, non_declarative_elems_mask);
            try calc.reserve(Code.Entry, counts.code);
            try calc.reserve(Code, counts.code);
            try calc.reserve([*]const u8, counts.data);
            try calc.reserve(u32, counts.data); // datas_lens

            break :layout calc;
        };

        var module_arena = ArenaAllocator.init(gpa);
        errdefer module_arena.deinit();
        var fixed_buffer: FixedBufferAllocator =
            try fixed_layout.bufferAllocator(module_arena.allocator());
        const module = fixed_buffer.allocator().create(Inner) catch unreachable;
        module.wasm = original_wasm;
        module.has_data_count_section = has_data_count_section;
        module.init_max_stack = 0;

        {
            errdefer wasm.* = sections.known.type;
            module.types_count = @intCast(counts.type);
            try parseTypeSec(module, &fixed_buffer, &module_arena, &sections.readers, diag);
        }

        var scratch = ArenaAllocator.init(alloca.allocator());
        {
            errdefer wasm.* = sections.known.import;
            try parseImportSec(
                module,
                &fixed_buffer,
                &module_arena,
                &counts,
                &sections.readers,
                &scratch,
                diag,
            );
        }

        var func_refs = try FuncRefs.init(alloca, @intCast(module.func_import_count));

        {
            errdefer wasm.* = sections.known.func;
            // The check for matching `func` and `code` section counts occurs later.
            try parseFuncSec(module, counts.func, &sections.readers, diag);
        }
        {
            errdefer wasm.* = sections.known.table;
            try parseTableSec(&module.module, counts.table, &sections.readers, diag);
        }
        {
            errdefer wasm.* = sections.known.mem;
            try parseMemSec(&module.module, counts.mem, &sections.readers, diag);
        }

        {
            errdefer wasm.* = sections.known.global;
            try parseGlobalSec(
                &module.module,
                &fixed_buffer,
                &counts,
                &sections.readers,
                &func_refs,
                diag,
                &scratch,
            );
        }

        module.exports_hash_seed = options.random_seed;
        {
            errdefer wasm.* = sections.known.@"export";
            try parseExportSec(
                &module.module,
                gpa,
                &counts,
                &sections.readers,
                &func_refs,
                diag,
            );
        }
        errdefer {
            module.exports.unlockPointers();
            module.exports.deinit(gpa);
        }

        {
            const custom_sections = fixed_buffer.allocator()
                .dupe(CustomSection, custom_sections_buf.items) catch unreachable;
            module.custom_sections_count = @intCast(custom_sections.len);
            module.custom_sections = custom_sections.ptr;
        }

        {
            errdefer wasm.* = sections.known.start;
            try parseStartSec(module, &counts, &sections.readers, diag);
        }

        {
            errdefer wasm.* = sections.known.elem;
            try parseElemSec(
                module,
                &fixed_buffer,
                &module_arena,
                &counts,
                &sections.readers,
                &func_refs,
                &scratch,
                diag,
            );
        }

        // Because of spectests, checked after any errors in the element section occurs
        if (counts.code != counts.func) {
            return Reader.fail(diag, .parse, "function and code section have inconsistent lengths");
        }

        {
            errdefer wasm.* = sections.known.code;
            module.code_count = counts.code;
            try parseCodeSec(module, &fixed_buffer, &sections.readers, diag);
        }

        {
            errdefer wasm.* = sections.known.data;
            module.datas_count = @intCast(counts.data);
            try parseDataSec(
                module,
                &fixed_buffer,
                &module_arena,
                &sections.readers,
                &scratch,
                diag,
            );
        }

        module.name_section = names: {
            if (sections.name_section) |name_sec| {
                absent: switch (options.parse_names) {
                    .ignore => {},
                    .parse => |names_diag| break :names NameSection.parse(
                        &module_arena,
                        name_sec,
                        &scratch,
                        names_diag,
                        .{ .func = module.func_import_count + module.code_count },
                    ) catch |err| switch (err) {
                        // Currently, OOM during name parsing means module parsing as a whole fails.
                        error.OutOfMemory => |oom| return oom,
                        else => break :absent,
                    },
                }
            }

            break :names &NameSection.absent;
        };

        module.func_refs = try func_refs.finish(module_arena.allocator());
        try module.runtime_shape.calculate(&module.module);
        module.arena = module_arena.state;
        return &module.module;
    }

    /// Returns `false` if validation of one of the functions began in another thread and did not yet finish.
    pub fn finishCodeValidation(
        module: *Module,
        allocator: Allocator,
        scratch: *ArenaAllocator,
        diag: ?*ParseDiagnostics,
    ) validator.Error!bool {
        var all_validated = true;
        var initialized: u32 = 0;
        // TODO: Don't deinit, leave validated entries intact.
        errdefer {
            for (module.internal().code[0..initialized]) |*entry| {
                entry.deinit(allocator);
            }
        }
        for (module.internal().code[0..module.funcDefinedCount()]) |*code_entry| {
            _ = scratch.reset(.retain_capacity);
            all_validated = all_validated and try code_entry.validate(
                allocator,
                module,
                scratch,
                diag,
            );
            initialized += 1;
        }

        // unreachable; // allows print debugging in validation code when interpreter also has print statements
        return all_validated;
    }

    pub fn deinitLeakCodeEntries(module: *Module, gpa: Allocator) void {
        const parent: *Inner = module.internal();
        parent.exports.unlockPointers();
        parent.exports.deinit(gpa);
        parent.arena.promote(gpa).deinit();
    }

    pub fn deinitWithContext(
        module: *Module,
        gpa: Allocator,
        code_deinit_ctx: anytype,
        code_deinit: fn (@TypeOf(code_deinit_ctx), *Code) void,
    ) void {
        for (module.internal().code[0..module.funcDefinedCount()]) |*code_entry| {
            if (code_entry.isValidationFinished()) {
                code_deinit(code_deinit_ctx, code_entry);
            }
        }
        module.deinitLeakCodeEntries(gpa);
    }

    pub fn deinit(module: *Module, module_allocator: Allocator, code_allocator: Allocator) void {
        const DeinitContext = struct {
            allocator: Allocator,

            fn deinitCodeEntry(ctx: @This(), code_entry: *Code) void {
                code_entry.deinit(ctx.allocator);
            }
        };

        return module.deinitWithContext(
            module_allocator,
            DeinitContext{ .allocator = code_allocator },
            DeinitContext.deinitCodeEntry,
        );
    }
};

const max_import_count = 1_000_000;
const max_export_count = 1_000_000;

const Sections = struct {
    known: *Known,
    readers: Readers,
    name_section: ?[]const u8,

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
        const field_count = id_fields.len + 1;
        const OrderInt = std.math.IntFittingRange(0, field_count);
        break :order @Enum(
            OrderInt,
            .exhaustive,
            names: {
                var names: [field_count][]const u8 = undefined;
                names[0] = "any";
                for (id_fields, names[1..]) |f, *n| {
                    n.* = f.name;
                }
                break :names &names;
            },
            values: {
                var values: [field_count]OrderInt = undefined;
                for (&values, 1..) |*v, i| {
                    v.* = @intCast(i);
                }
                break :values &values;
            },
        );
    };

    fn Struct(comptime FieldType: type, comptime default: ?FieldType) type {
        const field_count = id_fields.len - 1;
        const attributes = std.builtin.Type.StructField.Attributes{
            .default_value_ptr = if (default) |default_val|
                @ptrCast(@as(*const FieldType, &default_val))
            else
                null,
        };
        return @Struct(
            .auto,
            null,
            names: {
                var names: [field_count][]const u8 = undefined;
                for (id_fields[0..field_count], &names) |f, *n| {
                    std.debug.assert(!std.mem.eql(u8, f.name, "custom"));
                    n.* = f.name;
                }
                break :names &names;
            },
            &(.{FieldType} ** field_count),
            &(.{attributes} ** field_count),
        );
    }

    fn parse(
        reader: Reader,
        known_sections: *Known,
        arena: *ArenaAllocator,
        custom_sections: *std.ArrayList(Module.CustomSection),
        options: *const Module.ParseOptions,
    ) Module.ParseError!Sections {
        var section_order = Order.any;
        known_sections.* = Known{};
        var section_readers: Readers = undefined;
        var encountered = std.EnumSet(std.meta.FieldEnum(Known)).initEmpty();
        inline for (@typeInfo(Readers).@"struct".fields) |f| {
            @field(section_readers, f.name) = Reader.init(&@field(known_sections, f.name));
        }

        var name_section: ?[]const u8 = null;

        const diag = options.diagnostics;
        while (!reader.isEmpty()) {
            const id = try reader.readByteTag(Id, diag, "malformed section id");
            const section_contents = try reader.readByteVec(diag, "section contents");

            switch (id) {
                .custom => {
                    var custom_sec_contents = section_contents;
                    const custom_sec = Reader.init(&custom_sec_contents);
                    const section_name = try custom_sec.readName(diag);

                    // Name section "should" only appear after the data section, but it's better to
                    // have some name information rather than to silently discard it. WASM doesn't
                    // allow custom sections to impact semantics.
                    if (options.parse_names != .ignore and
                        std.mem.eql(u8, section_name.bytes, "name") and
                        name_section == null)
                    {
                        name_section = custom_sec_contents;
                    }

                    std.debug.assert(
                        @intFromPtr(section_name.bytes.ptr + section_name.bytes.len) ==
                            @intFromPtr(custom_sec_contents.ptr),
                    );

                    if (options.keep_custom_sections) {
                        if (custom_sections.items.len >= std.math.maxInt(u32)) {
                            return Reader.fail(
                                diag,
                                .implementation_limit,
                                "too many custom sections",
                            );
                        }

                        try custom_sections.append(
                            arena.allocator(),
                            Module.CustomSection{
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
                        return Reader.failPrint(
                            diag,
                            .parse,
                            "unexpected content after last section: '{t}' was placed after {t}",
                            .{ known_id, section_order },
                        );
                    }

                    const this_key = @field(std.meta.FieldEnum(Known), @tagName(known_id));
                    if (encountered.contains(this_key)) {
                        return Reader.failPrint(
                            diag,
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

        return Sections{
            .known = known_sections,
            .readers = section_readers,
            .name_section = name_section,
        };
    }

    const Counts = struct {
        type: u22,
        import: std.math.IntFittingRange(0, max_import_count),
        func: u22,
        table: u8,
        mem: u8,
        global: u22,
        @"export": std.math.IntFittingRange(0, max_export_count),
        elem: u17,
        data_count: u17,
        code: u22,
        data: u17,
        custom: u32,

        fn parse(readers: *const Readers, diag: ?*Reader.Diagnostics) !Counts {
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

fn parseTypeSec(
    module: *Inner,
    buffer: *FixedBufferAllocator,
    arena: *ArenaAllocator,
    readers: *const Sections.Readers,
    diag: ?*Reader.Diagnostics,
) !void {
    const type_reader = readers.type;
    const type_sec = buffer.allocator().alloc(Module.FuncType, module.types_count) catch
        unreachable;
    module.module.inner.types = type_sec.ptr;
    for (type_sec) |*func_type| {
        const TypeTag = enum(u8) { func = 0x60 };
        const tag = try type_reader.readByteTag(TypeTag, diag, "function type tag");
        std.debug.assert(tag == .func);

        var val_types = std.ArrayList(Module.ValType).empty;
        const param_count = try type_reader.readUleb128Casted(
            u32,
            u16,
            diag,
            "parameter type count",
        );

        const param_types = try val_types.addManyAsSlice(arena.allocator(), param_count);
        for (param_types) |*ty| {
            ty.* = try Module.ValType.parse(type_reader, diag);
            if (ty.* == .v128 and !wasm_features.simd128) {
                return Reader.fail(
                    diag,
                    .parse,
                    "expected valid param type, " ++ Reader.no_simd_message,
                );
            }
        }

        const result_count =
            try type_reader.readUleb128Casted(u32, u16, diag, "result type count");
        try val_types.ensureTotalCapacityPrecise(
            arena.allocator(),
            @as(u32, param_count) + result_count,
        );
        const result_types = val_types.addManyAsSliceAssumeCapacity(result_count);
        for (result_types) |*ty| {
            ty.* = try Module.ValType.parse(type_reader, diag);
            if (ty.* == .v128 and !wasm_features.simd128) {
                return Reader.fail(
                    diag,
                    .parse,
                    "expected valid result type, " ++ Reader.no_simd_message,
                );
            }
        }

        func_type.* = Module.FuncType{
            .types = val_types.items.ptr,
            .param_count = param_count,
            .result_count = result_count,
        };
    }

    try type_reader.expectEnd(diag, "type section size mismatch");
    type_reader.bytes.* = undefined;
}

const ImportExportDesc = enum(u8) {
    func = 0,
    table = 1,
    mem = 2,
    global = 3,
};

fn errorTooManyImports(diag: ?*Reader.Diagnostics) Reader.LimitError {
    return Reader.fail(diag, .implementation_limit, "too many imports");
}

const multi_memory_not_supported = "multiple memories are not yet supported";

fn parseImportSec(
    module: *Inner,
    buffer: *FixedBufferAllocator,
    arena: *ArenaAllocator,
    counts: *const Sections.Counts,
    readers: *const Sections.Readers,
    scratch: *ArenaAllocator,
    diag: ?*Reader.Diagnostics,
) !void {
    defer _ = scratch.reset(.retain_capacity);

    const TypesBuf = struct {
        funcs: std.ArrayList(*const Module.FuncType) = .empty,
        tables: std.ArrayList(Module.TableType) = .empty,
        mems: std.ArrayList(Module.MemType) = .empty,
        globals: std.ArrayList(Module.GlobalType) = .empty,
    };

    const NamesBuf = struct {
        funcs: std.ArrayList(Module.ImportName) = .empty,
        tables: std.ArrayList(Module.ImportName) = .empty,
        mems: std.ArrayList(Module.ImportName) = .empty,
        globals: std.ArrayList(Module.ImportName) = .empty,
    };

    // Allocated in `scratch`.
    var names = NamesBuf{};
    var import_types = TypesBuf{};

    var names_buf = std.ArrayList(Module.ImportName).initCapacity(
        buffer.allocator(),
        counts.import,
    ) catch unreachable;

    const import_reader = readers.import;
    const imports_start = import_reader.bytes.*.ptr;
    module.import_section = imports_start;

    _ = scratch.reset(.retain_capacity);

    std.debug.assert(counts.import <= max_import_count);
    const type_sec = module.module.types();
    for (0..counts.import) |_| {
        if (import_reader.isEmpty()) {
            return Reader.fail(
                diag,
                .parse,
                "unexpected end of section or function, expected import",
            );
        }

        const mod = try import_reader.readName(diag);
        const name = try import_reader.readName(diag);
        const import_name = name: {
            const module_offset = @intFromPtr(mod.bytes.ptr) - @intFromPtr(imports_start);
            const name_offset = @intFromPtr(name.bytes.ptr) - @intFromPtr(imports_start);
            break :name Module.ImportName{
                .module_offset = std.math.cast(u16, module_offset) orelse
                    return errorTooManyImports(diag),
                .module_size = std.math.cast(u16, mod.bytes.len) orelse
                    return errorTooManyImports(diag),

                .name_offset = std.math.cast(u16, name_offset) orelse
                    return errorTooManyImports(diag),
                .name_size = std.math.cast(u16, name.bytes.len) orelse
                    return errorTooManyImports(diag),
            };
        };

        const tag = try import_reader.readByteTag(ImportExportDesc, diag, "malformed import kind");
        (switch (tag) {
            inline else => |t| try @field(names, @tagName(t) ++ "s").addOne(scratch.allocator()),
        }).* = import_name;

        switch (tag) {
            .func => {
                if (import_types.funcs.items.len + counts.func >= enumMaxValue(Module.FuncIdx)) {
                    return Reader.fail(diag, .implementation_limit, "too many functions");
                }

                // The type section currently only contains function types, so this is always valid
                const type_idx = try import_reader.readIdx(
                    Module.TypeIdx,
                    counts.type,
                    diag,
                    &.{ "type", "for function import" },
                );
                try import_types.funcs.append(
                    scratch.allocator(),
                    &type_sec[@intFromEnum(type_idx)],
                );
            },
            .table => {
                if (import_types.tables.items.len + counts.table >= enumMaxValue(Module.TableIdx)) {
                    return Reader.fail(diag, .implementation_limit, "too many tables");
                }

                const table_type = try Module.TableType.parse(import_reader, diag);
                try import_types.tables.append(scratch.allocator(), table_type);
            },
            .mem => {
                if (import_types.mems.items.len + counts.mem >= 1) {
                    return Reader.fail(diag, .validation, multi_memory_not_supported);
                }

                const mem_type = try Module.MemType.parse(import_reader, diag);
                if (import_types.mems.capacity == 0) {
                    try import_types.mems.ensureTotalCapacityPrecise(scratch.allocator(), 1);
                }
                try import_types.mems.append(scratch.allocator(), mem_type);
            },
            .global => {
                if (import_types.globals.items.len + counts.global >=
                    enumMaxValue(Module.GlobalIdx))
                {
                    return Reader.fail(diag, .implementation_limit, "too many globals");
                }

                const global_type = try Module.GlobalType.parse(import_reader, diag);
                try import_types.globals.append(scratch.allocator(), global_type);
            },
        }
    }

    try import_reader.expectEnd(diag, "import section size mismatch");
    import_reader.bytes.* = undefined;

    // Detect if code above accidentally added to the wrong name list.
    std.debug.assert(import_types.funcs.items.len == names.funcs.items.len);
    std.debug.assert(import_types.tables.items.len == names.tables.items.len);
    std.debug.assert(import_types.mems.items.len == names.mems.items.len);
    std.debug.assert(import_types.globals.items.len == names.globals.items.len);

    var types_layout = allocators.Reservation{};

    inline for (std.enums.values(ImportExportDesc)) |tag| {
        const tag_name = @tagName(tag);
        const prefix = tag_name ++ "_import";
        const count: u32 = @intCast(@field(names, tag_name ++ "s").items.len);
        @field(module, prefix ++ "_count") = @intCast(count);

        const dst_names = names_buf.addManyAsSliceAssumeCapacity(count);
        @memcpy(dst_names, @field(names, tag_name ++ "s").items);
        @field(module, prefix ++ "s") = dst_names.ptr;

        const total_count = std.math.add(u32, @field(counts, tag_name), count) catch
            // WASM syntax does not allow more than `maxInt(u32)` functions, tables, etc.
            return Reader.fail(diag, .parse, "too many " ++ tag_name ++ "s");

        try types_layout.reserve(switch (tag) {
            .func => *const Module.FuncType,
            .table => Module.TableType,
            .mem => Module.MemType,
            .global => Module.GlobalType,
        }, total_count);

        if (tag != .func) {
            @field(module, tag_name ++ "_count") = @intCast(total_count);
        }
    }

    std.debug.assert(names_buf.items.len == counts.import);

    var types_alloc = try types_layout.bufferAllocator(arena.allocator());
    errdefer comptime unreachable;

    inline for (
        comptime std.meta.fieldNames(TypesBuf),
        comptime std.enums.values(ImportExportDesc),
    ) |src_field_name, desc_tag| {
        const desc_name = @tagName(desc_tag);
        const TyElem = @typeInfo(@FieldType(TypesBuf, src_field_name).Slice).pointer.child;
        const src_types: []const TyElem = @field(import_types, src_field_name).items;
        const dst_types = types_alloc.allocator().alloc(
            TyElem,
            src_types.len + @field(counts, desc_name),
        ) catch unreachable;

        @memcpy(dst_types[0..src_types.len], src_types);
        @field(if (desc_tag == .global) module.module.inner else module, desc_name ++ "_types") =
            dst_types.ptr;
    }
}

fn parseFuncSec(
    module: *Inner,
    count: u22,
    readers: *const Sections.Readers,
    diag: ?*Reader.Diagnostics,
) !void {
    const func_reader = readers.func;
    const func_types: []*const Module.FuncType =
        @constCast(module.func_types[0..(count + module.func_import_count)]);

    if (func_types.len > enumMaxValue(Module.FuncIdx)) {
        return Reader.fail(diag, .implementation_limit, "too many functions");
    }

    const type_sec = module.module.inner.types[0..module.types_count];
    for (func_types[func_types.len - count ..], 0..count) |*func_ty, _| {
        const type_idx = try func_reader.readIdx(
            Module.TypeIdx,
            module.types_count,
            diag,
            &.{ "type", "in 'func' section" },
        );
        func_ty.* = &type_sec[@intFromEnum(type_idx)];
    }

    try func_reader.expectEnd(diag, "'func' section size mismatch");
    readers.func.bytes.* = undefined;
}

fn parseTableSec(
    module: *Module,
    count: u8,
    readers: *const Sections.Readers,
    diag: ?*Reader.Diagnostics,
) !void {
    const table_reader = readers.table;
    const table_types: []Module.TableType = @constCast(module.tableTypes());

    if (table_types.len > enumMaxValue(Module.TableIdx)) {
        return Reader.fail(diag, .implementation_limit, "too many tables");
    }

    for (table_types[module.tableImportCount()..], 0..count) |*tt, _| {
        if (table_reader.isEmpty()) {
            return Reader.fail(
                diag,
                .parse,
                "unexpected end of section or function, expected table",
            );
        }

        tt.* = try Module.TableType.parse(table_reader, diag);
    }

    try table_reader.expectEnd(diag, "table section size mismatch");
    readers.table.bytes.* = undefined;
}

fn parseMemSec(
    module: *Module,
    count: u8,
    readers: *const Sections.Readers,
    diag: ?*Reader.Diagnostics,
) !void {
    const mem_reader = readers.mem;
    const mem_types: []Module.MemType = @constCast(module.memTypes());

    if (mem_types.len > 1) {
        return Reader.fail(diag, .validation, multi_memory_not_supported);
    }
    // if (mem_types.len > enumMaxValue(MemIdx)) {
    //     return Reader.fail(diag, .implementation_limit, "too many memories");
    // }

    for (mem_types[module.memImportCount()..], 0..count) |*mem, _| {
        if (mem_reader.isEmpty()) {
            return Reader.fail(
                diag,
                .parse,
                "unexpected end of section or function, expected memory",
            );
        }

        mem.* = try Module.MemType.parse(mem_reader, diag);
    }

    try mem_reader.expectEnd(diag, "memory section size mismatch");
    readers.mem.bytes.* = undefined;
}

fn parseGlobalSec(
    module: *Module,
    buffer: *FixedBufferAllocator,
    counts: *const Sections.Counts,
    readers: *const Sections.Readers,
    func_refs: *FuncRefs,
    diag: ?*Reader.Diagnostics,
    scratch: *ArenaAllocator,
) !void {
    const global_reader: Reader = readers.global;
    const start = global_reader.bytes.ptr;
    module.internal().global_section = start;

    const global_types: []Module.GlobalType = @constCast(module.globalTypes());
    const global_import_types: []const Module.GlobalType =
        global_types[0..module.globalImportCount()];

    std.debug.assert(global_import_types.len + counts.global == global_types.len);

    const global_exprs = buffer.allocator().alloc(GlobalExpr, counts.global) catch unreachable;
    module.internal().global_exprs = global_exprs.ptr;

    if (global_types.len > enumMaxValue(Module.GlobalIdx)) {
        return Reader.fail(diag, .implementation_limit, "too many globals");
    }

    const func_count = module.funcImportCount() + counts.func;
    const init_max_stack = &module.internal().init_max_stack;
    for (global_types[(global_types.len - counts.global)..], global_exprs) |*ty, *expr| {
        if (global_reader.isEmpty()) {
            return Reader.fail(
                diag,
                .parse,
                "unexpected end of section or function, expected global",
            );
        }

        ty.* = try Module.GlobalType.parse(global_reader, diag);
        const init_expr = try Module.ConstExpr.parse(
            global_reader,
            module,
            start,
            ty.val_type,
            func_count,
            func_refs,
            diag,
            "global initializer",
            scratch,
        );

        expr.* = GlobalExpr{ .init = init_expr.expr };
        init_max_stack.* = @max(init_max_stack.*, init_expr.max_stack);
    }

    try global_reader.expectEnd(diag, "global section size mismatch");
    readers.global.bytes.* = undefined;
    module.internal().global_section = start;
}

fn parseExportSec(
    module: *Module,
    gpa: Allocator,
    counts: *const Sections.Counts,
    readers: *const Sections.Readers,
    func_refs: *FuncRefs,
    diag: ?*Reader.Diagnostics,
) Module.ParseError!void {
    const export_reader: Reader = readers.@"export";

    if (counts.@"export" > max_export_count) {
        return Reader.fail(diag, .implementation_limit, "too many exports");
    }

    const lookup: *Module.Export.Lookup = &module.internal().exports;
    lookup.* = Module.Export.Lookup.empty;
    errdefer lookup.deinit(gpa);
    try lookup.entries.setCapacity(gpa, counts.@"export");
    try lookup.ensureTotalCapacity(gpa, counts.@"export"); // allows allocating header for large # of exports

    const exports_start = export_reader.bytes.*.ptr;
    module.internal().export_section = exports_start;
    const lookup_context = Module.Export.LookupContext{ .module = module };
    for (0..counts.@"export") |_| {
        if (export_reader.isEmpty()) {
            return Reader.fail(diag, .parse, "length out of bounds, expected export");
        }

        const name = try export_reader.readName(diag);
        const entry = lookup.getOrPutAssumeCapacityAdapted(name.bytes, lookup_context);
        if (entry.found_existing) {
            return Reader.failPrint(diag, .validation, "duplicate export name {f}", .{
                Module.Name.init(name.bytes),
            });
        }

        const tag = try export_reader.readByteTag(ImportExportDesc, diag, "export tag");

        entry.key_ptr.* = Module.Export{
            .name_size = std.math.cast(u14, name.bytes.len) orelse
                return Reader.fail(diag, .implementation_limit, "too many exports"),
            .name_offset = std.math.cast(
                u16,
                @intFromPtr(name.bytes.ptr) - @intFromPtr(exports_start),
            ) orelse return Reader.fail(diag, .implementation_limit, "too many exports"),
            .desc_tag = switch (tag) {
                inline else => |desc_tag| @field(
                    std.meta.FieldEnum(Module.Export.Desc),
                    @tagName(desc_tag),
                ),
            },
            .desc = desc: switch (tag) {
                .func => {
                    const func_idx = try export_reader.readIdx(
                        Module.FuncIdx,
                        module.funcImportCount() + counts.func,
                        diag,
                        &.{ "function", "in export" },
                    );

                    try func_refs.insert(func_idx);
                    break :desc .{ .func = .{ .idx = func_idx } };
                },
                .table => .{
                    .table = .{
                        .idx = try export_reader.readIdx(
                            Module.TableIdx,
                            module.tableCount(),
                            diag,
                            &.{ "table", "in export" },
                        ),
                    },
                },
                .mem => .{
                    .mem = .{
                        .idx = try export_reader.readIdx(
                            Module.MemIdx,
                            module.memCount(),
                            diag,
                            &.{ "memory", "in export" },
                        ),
                    },
                },
                .global => .{
                    .global = .{
                        .idx = try export_reader.readIdx(
                            Module.GlobalIdx,
                            module.globalCount(),
                            diag,
                            &.{ "global", "in export" },
                        ),
                    },
                },
            },
        };
    }

    try export_reader.expectEnd(diag, "'export' section size mismatch");
    readers.@"export".bytes.* = undefined;
    lookup.lockPointers();
}

fn parseStartSec(
    module: *Inner,
    counts: *const Sections.Counts,
    readers: *const Sections.Readers,
    diag: ?*Reader.Diagnostics,
) !void {
    const start_reader: Reader = readers.start;
    module.start = if (start_reader.isEmpty())
        Start{ .exists = false, .idx = undefined }
    else start: {
        const functions = module.func_types[0..(module.func_import_count + counts.func)];
        const func_idx = try start_reader
            .readIdx(Module.FuncIdx, functions.len, diag, &.{ "function", "in 'start' section" });

        try start_reader.expectEnd(diag, "section size mismatch, expected end of 'start' section");

        const signature = functions[@intFromEnum(func_idx)];
        const error_prefix = "start function must not have ";
        if (signature.param_count != 0) {
            return Reader.fail(diag, .validation, error_prefix ++ "parameters");
        } else if (signature.result_count != 0) {
            return Reader.fail(diag, .validation, error_prefix ++ "results");
        } else {
            break :start Start{ .exists = true, .idx = func_idx };
        }
    };
}

fn parseElemSec(
    module: *Inner,
    buffer: *FixedBufferAllocator,
    arena: *ArenaAllocator,
    counts: *const Sections.Counts,
    readers: *const Sections.Readers,
    func_refs: *FuncRefs,
    scratch: *ArenaAllocator,
    diag: ?*Reader.Diagnostics,
) !void {
    const elems_reader: Reader = readers.elem;
    const start = elems_reader.bytes.ptr;
    module.elem_section = start;

    module.elems_count = @intCast(counts.elem);
    const elems = buffer.allocator().alloc(Module.ElemSegment, counts.elem) catch unreachable;
    module.elems = elems.ptr;

    const non_declarative_mask = buffer.allocator()
        .alloc(u32, std.math.divCeil(u32, counts.elem, 32) catch unreachable) catch unreachable;
    module.non_declarative_elems_mask = non_declarative_mask.ptr;

    @memset(non_declarative_mask, 0);

    _ = scratch.reset(.retain_capacity);
    var active_elems = std.ArrayList(Module.ActiveElem).empty;

    const table_types = module.table_types[0..module.table_count];
    const func_count = module.func_import_count + counts.func;
    for (elems[0..counts.elem], 0..counts.elem) |*elem_segment, i| {
        const elem_idx: Module.ElemIdx =
            @enumFromInt(@as(@typeInfo(Module.ElemIdx).@"enum".tag_type, @intCast(i)));

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
            std.math.cast(u3, tag_value) orelse return Reader.fail(
                diag,
                .parse,
                "malformed element segment tag",
            ),
        );

        const ElemKind = enum(u8) { funcref = 0x00 };

        var expr_arena = std.heap.ArenaAllocator.init(scratch.allocator());
        const expected_ref_type = if (tag.kind == .active) active: {
            const table_idx: Module.TableIdx = if (tag.bit_1.active_has_table_idx)
                try elems_reader.readIdx(
                    Module.TableIdx,
                    module.table_count,
                    diag,
                    &.{ "table", "in element section" },
                )
            else if (module.table_count == 0)
                return Reader.fail(diag, .validation, "unknown table 0 in element section")
            else
                Module.TableIdx.default;

            var dummy_func_refs = FuncRefs.dummy;
            const offset = try Module.ConstExpr.parse(
                elems_reader,
                &module.module,
                start,
                .i32,
                func_count,
                &dummy_func_refs,
                diag,
                "offset in element segment",
                &expr_arena,
            );
            module.init_max_stack = @max(module.init_max_stack, offset.max_stack);

            try active_elems.append(scratch.allocator(), Module.ActiveElem{
                .table = table_idx,
                .elements = elem_idx,
                .offset = OffsetExpr{ .value = offset.expr },
            });

            break :active table_types[@intFromEnum(table_idx)].elem_type;
        } else passive: {
            // TODO: maybe keep a list of passive segments too?
            break :passive null;
        };

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
            .none => Module.ValType.funcref,
            .elemkind => func_type: {
                const elem_kind = try elems_reader
                    .readByteTag(ElemKind, diag, "malformed reference type");
                std.debug.assert(elem_kind == .funcref);
                break :func_type Module.ValType.funcref;
            },
            .reftype => try Module.ValType.parse(elems_reader, diag),
        };

        if (!ref_type.isRefType()) {
            return Reader.failPrint(
                diag,
                .parse,
                "malformed reference type {t} in element segment",
                .{ref_type},
            );
        }

        if (expected_ref_type) |expected_ty| {
            if (!expected_ty.eql(ref_type)) {
                return Reader.failPrint(
                    diag,
                    .validation,
                    "type mismatch at elem segment: got {t}, expected {t}",
                    .{ ref_type, expected_ty },
                );
            }
        }

        const expr_count = try elems_reader
            .readUleb128(u32, diag, "element segment expression count");
        elem_segment.* = if (tag.use_elem_exprs) elem_exprs: {
            const exprs = try arena.allocator().alloc(Module.ElemSegment.Expr, expr_count);
            var elem_max_stack: u15 = 0;
            var instruction_count: u15 = 0;
            for (exprs) |*e| {
                const init_expr = try Module.ConstExpr.parse(
                    elems_reader,
                    &module.module,
                    start,
                    ref_type,
                    func_count,
                    func_refs,
                    diag,
                    "element segment expression",
                    &expr_arena,
                );
                e.* = Module.ElemSegment.Expr{ .init = init_expr.expr };
                elem_max_stack = @max(
                    elem_max_stack,
                    std.math.cast(u15, init_expr.max_stack) orelse return Reader.fail(
                        diag,
                        .implementation_limit,
                        "element expression too large",
                    ),
                );
                instruction_count = std.math.add(
                    u15,
                    instruction_count,
                    std.math.cast(u15, init_expr.instr_count) orelse return Reader.fail(
                        diag,
                        .implementation_limit,
                        "element expression too many instructions",
                    ),
                ) catch {
                    return Reader.fail(diag, .implementation_limit, "too many element expressions");
                };
            }

            std.debug.assert(exprs.len <= instruction_count);
            module.init_max_stack = @max(module.init_max_stack, elem_max_stack);

            // if (tag.kind == .active) {
            //     active_elems.items[active_elems.items.len - 1].elem_max_stack = elem_max_stack;
            // }

            break :elem_exprs Module.ElemSegment{
                .header = .{
                    .tag = switch (ref_type) {
                        .funcref => .func_expressions,
                        .externref => .extern_expressions,
                        else => unreachable,
                    },
                    .instruction_count = instruction_count,
                    .elem_max_stack = elem_max_stack,
                },
                .len = expr_count,
                .contents = Module.ElemSegment.Contents{ .expressions = exprs.ptr },
            };
        } else idx_exprs: {
            std.debug.assert(ref_type == .funcref);
            const func_indices = try arena.allocator().alloc(Module.FuncIdx, expr_count);
            // Assumes that most C, C++, Rust, Zig tables are filled with unique function indices
            try func_refs.ensureUnusedCapacity(expr_count / 2);
            for (func_indices) |*idx| {
                idx.* = try elems_reader.readIdx(
                    Module.FuncIdx,
                    func_count,
                    diag,
                    &.{ "function", "in element segment" },
                );
                try func_refs.insert(idx.*);
            }

            break :idx_exprs Module.ElemSegment{
                .header = .{
                    .tag = .func_indices,
                    .instruction_count = 0,
                    .elem_max_stack = 0,
                },
                .len = expr_count,
                .contents = Module.ElemSegment.Contents{ .func_indices = func_indices.ptr },
            };
        };

        const is_declarative = tag.kind == .passive_or_declarative and tag.bit_1.is_declarative;
        non_declarative_mask[i / 32] |=
            @as(u32, @intFromBool(!is_declarative)) << @as(u5, @intCast(i % 32));
    }

    try elems_reader.expectEnd(diag, "element section size mismatch");
    readers.elem.bytes.* = undefined;

    const active = try arena.allocator().dupe(Module.ActiveElem, active_elems.items);
    module.active_elems_count = @intCast(active.len);
    module.active_elems = active.ptr;
}

fn parseCodeSec(
    module: *Inner,
    buffer: *FixedBufferAllocator,
    readers: *const Sections.Readers,
    diag: ?*Reader.Diagnostics,
) !void {
    const code_reader = readers.code;

    const entries = buffer.allocator().alloc(Module.Code.Entry, module.code_count) catch
        unreachable;
    module.code_entries = entries.ptr;
    const validation = buffer.allocator().alloc(Module.Code, module.code_count) catch unreachable;
    module.code = validation.ptr;

    const code_start = code_reader.bytes.*.ptr;
    module.code_section = code_start;
    for (entries) |*code_entry| {
        const contents = try code_reader.readByteVec(diag, "code section entry");
        code_entry.* = .{
            .contents = Module.WasmSlice{
                .size = @intCast(contents.len),
                .offset = @intCast(@intFromPtr(contents.ptr) - @intFromPtr(code_start)),
            },
        };
    }

    @memset(validation, Module.Code{ .inner = Module.Code.validation_failed });

    try code_reader.expectEnd(diag, "'code' section size mismatch");
    readers.code.bytes.* = undefined;
}

fn parseDataSec(
    module: *Inner,
    buffer: *FixedBufferAllocator,
    arena: *ArenaAllocator,
    readers: *const Sections.Readers,
    scratch: *ArenaAllocator,
    diag: ?*Reader.Diagnostics,
) !void {
    const datas_reader: Reader = readers.data;
    const start = datas_reader.bytes.ptr;
    module.data_section = start;

    const count = module.datas_count;
    const data_ptrs = buffer.allocator().alloc([*]const u8, count) catch unreachable;
    module.module.inner.datas_ptrs = data_ptrs.ptr;
    const data_lens = buffer.allocator().alloc(u32, count) catch unreachable;
    module.module.inner.datas_lens = data_lens.ptr;

    _ = scratch.reset(.retain_capacity);
    var active_datas = std.ArrayList(Module.ActiveData).empty; // in scratch

    // data section parsed after code section
    const func_count = module.func_import_count + module.code_count;
    for (data_ptrs, data_lens, 0..count) |*ptr, *len, i| {
        if (datas_reader.isEmpty()) {
            return Reader.fail(
                diag,
                .parse,
                "unexpected end of section or function, expected data segment",
            );
        }

        const data_idx: Module.DataIdx =
            @enumFromInt(@as(@typeInfo(Module.DataIdx).@"enum".tag_type, @intCast(i)));

        const Flags = packed struct(u2) {
            is_passive: bool,
            has_mem_idx: bool,
        };

        const flags_int = try datas_reader.readUleb128Casted(u32, u2, diag, "data segment flag");
        if (flags_int > 2) {
            return Reader.fail(diag, .parse, "malformed data segment flag");
        }

        const flags: Flags = @bitCast(flags_int);
        if (!flags.is_passive) {
            const memory: Module.MemIdx = if (flags.has_mem_idx)
                try datas_reader.readIdx(
                    Module.MemIdx,
                    module.mem_count,
                    diag,
                    &.{ "memory", "data segment" },
                )
            else if (module.mem_count == 0)
                return Reader.fail(diag, .validation, "unknown memory 0 in data segment")
            else
                Module.MemIdx.default;

            var expr_arena = ArenaAllocator.init(scratch.allocator());

            var dummy_func_refs = FuncRefs.dummy;
            const offset = try Module.ConstExpr.parse(
                datas_reader,
                &module.module,
                start,
                .i32,
                func_count,
                &dummy_func_refs,
                diag,
                "data segment offset",
                &expr_arena,
            );

            module.init_max_stack = @max(module.init_max_stack, offset.max_stack);
            try active_datas.append(scratch.allocator(), Module.ActiveData{
                .memory = memory,
                .data = data_idx,
                .offset = OffsetExpr{ .value = offset.expr },
            });
        }

        const contents_len = try datas_reader.readUleb128(u32, diag, "data segment length");
        if (datas_reader.bytes.len < contents_len) {
            return Reader.failPrint(
                diag,
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

    module.active_datas_count = @intCast(active_datas.items.len);
    module.active_datas = (try arena.allocator().dupe(Module.ActiveData, active_datas.items)).ptr;
}

const std = @import("std");
const Writer = std.Io.Writer;
const Allocator = std.mem.Allocator;
const ArenaAllocator = std.heap.ArenaAllocator;
const FixedBufferAllocator = std.heap.FixedBufferAllocator;

const allocators = @import("allocators");
const coz = @import("coz");
const opcodes = @import("opcodes");
const wasm_features = @import("wasm_features");

const Reader = @import("module/Reader.zig");
const FuncRefs = @import("module/FuncRefs.zig");
const validator = @import("module/validator.zig");

test {
    _ = Reader;
}
