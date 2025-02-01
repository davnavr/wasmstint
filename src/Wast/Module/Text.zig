//! A module in the [WebAssembly Text] format.
//!
//! [WebAssembly Text]: https://webassembly.github.io/spec/core/index.html

const std = @import("std");
const ArenaAllocator = std.heap.ArenaAllocator;
const IndexedArena = @import("../../IndexedArena.zig");

const sexpr = @import("../sexpr.zig");
const ParseContext = sexpr.Parser.Context;

const Ident = @import("../ident.zig").Ident;
const Name = @import("../Name.zig");

const Caches = @import("../Caches.zig");

pub const Instr = @import("Instr.zig");
pub const Expr = @import("Expr.zig");
pub const Func = @import("Func.zig");
pub const Type = @import("Type.zig");
pub const TypeUse = @import("TypeUse.zig");
pub const Limits = @import("Limits.zig");

fields: IndexedArena.Slice(Field),

const Text = @This();

pub const Field = struct {
    keyword: sexpr.TokenId,
    contents: Contents,

    comptime {
        std.debug.assert(@sizeOf(Field) == switch (@import("builtin").mode) {
            .Debug, .ReleaseSafe => 12,
            .ReleaseFast, .ReleaseSmall => 8,
        });
    }
};

pub const Contents = union {
    type: IndexedArena.Idx(Type),
    // import: IndexedArena.Idx(Import),
    func: IndexedArena.Idx(Func),
    table: IndexedArena.Idx(Table),
    mem: IndexedArena.Idx(Mem),
    global: IndexedArena.Idx(Global),
};

pub const ValType = struct {
    keyword: sexpr.TokenId, // sexpr.Value // GC proposal support
    type: Types,

    const Types = union { simple: void };

    comptime {
        std.debug.assert(@sizeOf(ValType) <= 8);
    }

    pub fn parseAtom(
        atom: sexpr.TokenId,
        parser: *sexpr.Parser,
        ctx: *ParseContext,
        parent: sexpr.List.Id,
    ) sexpr.Parser.ParseError!ValType {
        switch (atom.tag(ctx.tree)) {
            .keyword_i32, .keyword_i64, .keyword_f32, .keyword_f64, .keyword_funcref, .keyword_externref => {
                _ = parser;
                _ = parent;
                return .{ .keyword = atom, .type = .{ .simple = {} } };
            },
            else => return (try ctx.errorAtToken(atom, "expected valtype")).err,
        }
    }

    pub fn parse(parser: *sexpr.Parser, ctx: *ParseContext, parent: sexpr.List.Id) sexpr.Parser.ParseError!ValType {
        const atom = try parser.parseAtomInList(parent, ctx, "valtype");
        return parseAtom(atom, parser, ctx, parent);
    }
};

pub const Export = struct {
    /// The `export` keyword.
    keyword: sexpr.TokenId,
    name: Name,

    pub fn parseContents(
        contents: *sexpr.Parser,
        ctx: *ParseContext,
        arena: *IndexedArena,
        caches: *Caches,
        keyword: sexpr.TokenId,
        parent: sexpr.List.Id,
        scratch: *ArenaAllocator,
    ) sexpr.Parser.ParseError!Export {
        std.debug.assert(keyword.tag(ctx.tree) == .keyword_export);
        const name = try Name.parse(
            contents,
            ctx,
            caches.allocator,
            &caches.names,
            arena,
            parent,
            scratch,
        );

        return Export{ .keyword = keyword, .name = name };
    }
};

pub const ParamOrLocal = struct {
    /// The `param` or `local` keyword.
    keyword: sexpr.TokenId,
    /// Must be `.none` if `types.len > 1`.
    id: Ident.Symbolic align(4),
    types: IndexedArena.Slice(ValType),

    pub fn parseContents(
        contents: *sexpr.Parser,
        ctx: *ParseContext,
        arena: *IndexedArena,
        caches: *Caches,
        keyword: sexpr.TokenId,
        parent: sexpr.List.Id,
    ) error{OutOfMemory}!ParamOrLocal {
        const ident = try Ident.Symbolic.parse(
            contents,
            ctx.tree,
            caches.allocator,
            &caches.ids,
        );

        var types = try IndexedArena.BoundedArrayList(ValType).initCapacity(
            arena,
            contents.remaining.len,
        );

        while (!contents.isEmpty()) {
            const val_type = ValType.parse(contents, ctx, parent) catch |e| switch (e) {
                error.OutOfMemory => |oom| return oom,
                error.ReportedParserError => continue,
            };

            types.appendAssumeCapacity(arena, val_type);
        }

        return .{ .keyword = keyword, .id = ident, .types = types.items };
    }
};

pub const Param = ParamOrLocal;

pub const Result = struct {
    keyword: sexpr.TokenId,
    types: IndexedArena.Slice(ValType),

    pub fn parseContents(
        contents: *sexpr.Parser,
        ctx: *ParseContext,
        arena: *IndexedArena,
        keyword: sexpr.TokenId,
        parent: sexpr.List.Id,
    ) error{OutOfMemory}!Text.Result {
        std.debug.assert(keyword.tag(ctx.tree) == .keyword_result);

        var types = try IndexedArena.BoundedArrayList(ValType).initCapacity(
            arena,
            contents.remaining.len,
        );

        while (!contents.isEmpty()) {
            const val_type = ValType.parse(contents, ctx, parent) catch |e| switch (e) {
                error.OutOfMemory => |oom| return oom,
                error.ReportedParserError => continue,
            };

            types.appendAssumeCapacity(arena, val_type);
        }

        return .{ .keyword = keyword, .types = types.items };
    }
};

pub const Local = ParamOrLocal;

pub const ImportName = struct {
    module: Name,
    name: Name,

    pub fn parseContents(
        contents: *sexpr.Parser,
        ctx: *ParseContext,
        arena: *IndexedArena,
        caches: *Caches,
        parent: sexpr.List.Id,
        scratch: *ArenaAllocator,
    ) sexpr.Parser.ParseError!ImportName {
        const module = try Name.parse(
            contents,
            ctx,
            caches.allocator,
            &caches.names,
            arena,
            parent,
            scratch,
        );

        _ = scratch.reset(.retain_capacity);
        const name = try Name.parse(
            contents,
            ctx,
            caches.allocator,
            &caches.names,
            arena,
            parent,
            scratch,
        );

        return ImportName{ .module = module, .name = name };
    }
};

pub const InlineImport = struct {
    /// The `import` keyword.
    keyword: sexpr.TokenId.Opt,
    /// Must not be read if `keyword == .none`.
    name: ImportName,

    pub const none = InlineImport{
        .keyword = .none,
        .name = undefined,
    };

    pub fn parseContents(
        contents: *sexpr.Parser,
        ctx: *ParseContext,
        arena: *IndexedArena,
        caches: *Caches,
        keyword: sexpr.TokenId,
        parent: sexpr.List.Id,
        scratch: *ArenaAllocator,
    ) sexpr.Parser.ParseError!InlineImport {
        std.debug.assert(keyword.tag(ctx.tree) == .keyword_import);

        const name = try ImportName.parseContents(contents, ctx, arena, caches, parent, scratch);
        return InlineImport{
            .keyword = sexpr.TokenId.Opt.init(keyword),
            .name = name,
        };
    }
};

pub const MemType = struct {
    limits: Limits,

    pub fn parseContents(
        contents: *sexpr.Parser,
        ctx: *ParseContext,
        parent: sexpr.List.Id,
    ) sexpr.Parser.ParseError!MemType {
        return .{ .limits = try Limits.parseContents(contents, ctx, parent) };
    }
};

pub const InlineExports = IndexedArena.Slice(Export);

/// Used when parsing memories, tables, and globals.
pub const InlineImportExports = struct {
    exports: InlineExports,
    import: InlineImport,

    pub const none = InlineImportExports{
        .exports = .empty,
        .import = .none,
    };

    pub fn parseContents(
        contents: *sexpr.Parser,
        ctx: *ParseContext,
        arena: *IndexedArena,
        caches: *Caches,
        alloca: *ArenaAllocator,
    ) error{OutOfMemory}!InlineImportExports {
        var import_exports = InlineImportExports.none;
        var lookahead: sexpr.Parser = contents.*;

        _ = alloca.reset(.retain_capacity);
        var scratch = ArenaAllocator.init(alloca.allocator());
        var export_buf = std.SegmentedList(Export, 1){};

        while (!import_exports.import.keyword.some) {
            _ = scratch.reset(.retain_capacity);
            const list = (lookahead.parseValue() catch break).getList() orelse break;
            var list_contents = sexpr.Parser.init(list.contents(ctx.tree).values(ctx.tree));

            const keyword = (list_contents.parseValue() catch break).getAtom() orelse break;

            switch (keyword.tag(ctx.tree)) {
                .keyword_export => {
                    if (import_exports.import.keyword.some) break;

                    const parsed_export = Export.parseContents(
                        &list_contents,
                        ctx,
                        arena,
                        caches,
                        keyword,
                        list,
                        &scratch,
                    ) catch |e| switch (e) {
                        error.OutOfMemory => |oom| return oom,
                        error.ReportedParserError => break,
                    };

                    try export_buf.append(scratch.allocator(), parsed_export);
                },
                .keyword_import => {
                    std.debug.assert(!import_exports.import.keyword.some);

                    const parsed_import = InlineImport.parseContents(
                        &list_contents,
                        ctx,
                        arena,
                        caches,
                        keyword,
                        list,
                        &scratch,
                    ) catch |e| switch (e) {
                        error.OutOfMemory => |oom| return oom,
                        error.ReportedParserError => break,
                    };

                    import_exports.import = parsed_import;
                },
                else => break,
            }

            try list_contents.expectEmpty(ctx);

            contents.* = lookahead;
        }

        import_exports.exports = try arena.dupeSegmentedList(Export, 1, &export_buf);
        return import_exports;
    }
};

pub const Mem = struct {
    id: Ident.Symbolic align(4),
    import_exports: InlineImportExports,
    mem_type: MemType,
    // TODO: Inline data segments, split import_exports field

    pub fn parseContents(
        contents: *sexpr.Parser,
        ctx: *ParseContext,
        parent: sexpr.List.Id,
        arena: *IndexedArena,
        caches: *Caches,
        scratch: *ArenaAllocator,
    ) sexpr.Parser.ParseError!Mem {
        return .{
            .id = try Ident.Symbolic.parse(
                contents,
                ctx.tree,
                caches.allocator,
                &caches.ids,
            ),
            .import_exports = try InlineImportExports.parseContents(
                contents,
                ctx,
                arena,
                caches,
                scratch,
            ),
            .mem_type = try MemType.parseContents(contents, ctx, parent),
        };
    }
};

pub const TableType = struct {
    limits: Limits,
    ref_type: sexpr.TokenId,

    pub fn parseContents(
        contents: *sexpr.Parser,
        ctx: *ParseContext,
        parent: sexpr.List.Id,
    ) sexpr.Parser.ParseError!TableType {
        const limits = try Limits.parseContents(contents, ctx, parent);
        const ref_type = try contents.parseAtomInList(parent, ctx, "reftype");
        switch (ref_type.tag(ctx.tree)) {
            .keyword_funcref, .keyword_externref => {},
            else => return (try ctx.errorAtToken(ref_type, "expected reftype")).err,
        }

        return .{ .limits = limits, .ref_type = ref_type };
    }
};

pub const Table = struct {
    id: Ident.Symbolic align(4),
    inline_exports: InlineExports,
    /// Indicates that a table type is not explicitly specified, and that an inline element segment is present.
    ///
    /// If `.none`, then `inner == .no_elements`.
    ref_type_keyword: sexpr.TokenId.Opt,
    inner: union {
        /// Invariant that `ref_type_keyword == .none`.
        no_elements: struct {
            inline_import: InlineImport,
            table_type: TableType,
        },
        /// Inline elements are allowed only when the table is not an inline import and a table type is not present.
        ///
        /// Invariant that `ref_type_keyword != .none`.
        ref_type: struct {
            /// The `elem` keyword.
            keyword: sexpr.TokenId,
            elements: InlineElements,
        },
    },

    pub const InlineElements = union(enum) {
        expressions: IndexedArena.Slice(ElementSegment.Item),
        indices: IndexedArena.SliceAligned(Ident, 4),
    };

    comptime {
        std.debug.assert(@alignOf(Table) == @alignOf(u32));
    }

    pub fn parseContents(
        contents: *sexpr.Parser,
        ctx: *ParseContext,
        parent: sexpr.List.Id,
        arena: *IndexedArena,
        caches: *Caches,
        scratch: *ArenaAllocator,
    ) sexpr.Parser.ParseError!IndexedArena.Idx(Table) {
        const table_idx = try arena.create(Table);

        const id = try Ident.Symbolic.parse(
            contents,
            ctx.tree,
            caches.allocator,
            &caches.ids,
        );

        const import_exports = try InlineImportExports.parseContents(
            contents,
            ctx,
            arena,
            caches,
            scratch,
        );

        // Decide if a `tabletype` or a `reftype` has to be parsed.
        var lookahead: sexpr.Parser = contents.*;
        const type_token = try lookahead.parseAtomInList(parent, ctx, "reftype or table type");

        const table = table: switch (type_token.tag(ctx.tree)) {
            // Detect the limits of a `tabletype`.
            .integer => {
                contents.* = lookahead;
                lookahead = undefined;

                const table_type = try TableType.parseContents(contents, ctx, parent);

                break :table Table{
                    .id = id,
                    .inline_exports = import_exports.exports,
                    .ref_type_keyword = .none,
                    .inner = .{
                        .no_elements = .{
                            .inline_import = import_exports.import,
                            .table_type = table_type,
                        },
                    },
                };
            },
            .keyword_funcref, .keyword_externref => {
                contents.* = lookahead;
                lookahead = undefined;

                if (import_exports.import.keyword.some)
                    return (try ctx.errorAtToken(type_token, "expected inline element segment")).err;

                const elem_list = try contents.parseListInList(parent, ctx);

                var elem_contents = sexpr.Parser.init(elem_list.contents(ctx.tree).values(ctx.tree));
                const elem_keyword = try elem_contents.parseAtomInList(elem_list, ctx, "'elem' keyword");

                if (elem_keyword.tag(ctx.tree) != .keyword_elem)
                    return (try ctx.errorAtToken(elem_keyword, "expected 'elem' keyword")).err;

                const first_elem_value = elem_contents.parseValue() catch
                    return (try ctx.errorAtList(elem_list, .end, "expected inline element segment")).err;

                const elements = elements: switch (first_elem_value.unpacked()) {
                    .atom => |first_idx| {
                        var indices = try IndexedArena.BoundedArrayListAligned(Ident, 4).initCapacity(
                            arena,
                            1 + elem_contents.remaining.len,
                        );

                        indices.appendAssumeCapacity(
                            arena,
                            try Ident.parseAtom(
                                first_idx,
                                ctx,
                                caches.allocator,
                                &caches.ids,
                            ),
                        );

                        while (!elem_contents.isEmpty()) {
                            indices.appendAssumeCapacity(
                                arena,
                                try Ident.parse(
                                    &elem_contents,
                                    ctx,
                                    elem_list,
                                    caches.allocator,
                                    &caches.ids,
                                ),
                            );
                        }

                        break :elements InlineElements{ .indices = indices.items };
                    },
                    .list => |first_elem_list| {
                        var items = try IndexedArena.BoundedArrayList(ElementSegment.Item).initCapacity(
                            arena,
                            1 + elem_contents.remaining.len,
                        );

                        _ = scratch.reset(.retain_capacity);
                        items.appendAssumeCapacity(
                            arena,
                            try ElementSegment.Item.parseList(
                                first_elem_list,
                                ctx,
                                arena,
                                caches,
                                scratch,
                            ),
                        );

                        while (!elem_contents.isEmpty()) {
                            _ = scratch.reset(.retain_capacity);
                            const parsed_item = try ElementSegment.Item.parse(
                                &elem_contents,
                                ctx,
                                elem_list,
                                arena,
                                caches,
                                scratch,
                            );

                            items.appendAssumeCapacity(arena, parsed_item);
                        }

                        break :elements InlineElements{ .expressions = items.items };
                    },
                };

                std.debug.assert(elem_contents.isEmpty());

                break :table Table{
                    .id = id,
                    .inline_exports = import_exports.exports,
                    .ref_type_keyword = sexpr.TokenId.Opt.init(type_token),
                    .inner = .{
                        .ref_type = .{
                            .keyword = elem_keyword,
                            .elements = elements,
                        },
                    },
                };
            },
            else => return (try ctx.errorAtToken(type_token, "expected reftype or table type")).err,
        };

        table_idx.set(arena, table);

        return table_idx;
    }
};

pub const GlobalType = struct {
    mut: sexpr.TokenId.Opt,
    val_type: ValType,

    pub fn parse(
        parser: *sexpr.Parser,
        ctx: *ParseContext,
        parent: sexpr.List.Id,
    ) sexpr.Parser.ParseError!GlobalType {
        const value = parser.parseValue() catch
            return (try ctx.errorAtList(parent, .start, "expected global type")).err;

        switch (value.unpacked()) {
            .atom => |type_keyword| return .{
                .mut = .none,
                .val_type = try ValType.parseAtom(type_keyword, parser, ctx, parent),
            },
            .list => |list| {
                var list_contents = sexpr.Parser.init(list.contents(ctx.tree).values(ctx.tree));
                const mut_keyword = try list_contents.parseAtomInList(list, ctx, "'mut' keyword");

                if (mut_keyword.tag(ctx.tree) != .keyword_mut)
                    return (try ctx.errorAtToken(mut_keyword, "expected 'mut' keyword")).err;

                const val_type = try ValType.parse(&list_contents, ctx, parent);

                try list_contents.expectEmpty(ctx);

                return .{ .mut = sexpr.TokenId.Opt.init(mut_keyword), .val_type = val_type };
            },
        }
    }
};

pub const Global = struct {
    id: Ident.Symbolic align(4),
    inline_exports: InlineExports,
    inline_import: sexpr.TokenId.Opt,
    global_type: GlobalType,
    inner: union {
        init: Expr,
        inline_import: ImportName,
    },

    pub fn parseContents(
        contents: *sexpr.Parser,
        ctx: *ParseContext,
        parent: sexpr.List.Id,
        arena: *IndexedArena,
        caches: *Caches,
        scratch: *ArenaAllocator,
    ) sexpr.Parser.ParseError!IndexedArena.Idx(Global) {
        const global = try arena.create(Global);

        const id = try Ident.Symbolic.parse(
            contents,
            ctx.tree,
            caches.allocator,
            &caches.ids,
        );

        const import_exports = try InlineImportExports.parseContents(
            contents,
            ctx,
            arena,
            caches,
            scratch,
        );

        const global_type = try GlobalType.parse(contents, ctx, parent);

        global.set(
            arena,
            Global{
                .id = id,
                .inline_exports = import_exports.exports,
                .inline_import = import_exports.import.keyword,
                .global_type = global_type,
                .inner = if (import_exports.import.keyword.some)
                    .{ .inline_import = import_exports.import.name }
                else
                    .{
                        .init = try Expr.parseContents(
                            contents,
                            ctx,
                            parent,
                            arena,
                            caches,
                            scratch,
                        ),
                    },
            },
        );

        try contents.expectEmpty(ctx);

        return global;
    }
};

pub const ElementSegment = struct {
    /// An *`elemexpr`*.
    pub const Item = struct {
        /// The `item` keyword.
        keyword: sexpr.TokenId,
        expr: Expr,

        pub fn parseList(
            list: sexpr.List.Id,
            ctx: *ParseContext,
            arena: *IndexedArena,
            caches: *Caches,
            scratch: *ArenaAllocator,
        ) sexpr.Parser.ParseError!Item {
            var contents = sexpr.Parser.init(list.contents(ctx.tree).values(ctx.tree));
            var item_keyword = try contents.parseAtomInList(list, ctx, "'item' keyword");

            if (item_keyword.tag(ctx.tree) != .keyword_item)
                return (try ctx.errorAtToken(item_keyword, "expected 'item' keyword")).err;

            const expr = try Expr.parseContents(
                &contents,
                ctx,
                list,
                arena,
                caches,
                scratch,
            );

            std.debug.assert(contents.isEmpty());

            return .{ .keyword = item_keyword, .expr = expr };
        }

        pub fn parse(
            contents: *sexpr.Parser,
            ctx: *ParseContext,
            parent: sexpr.List.Id,
            arena: *IndexedArena,
            caches: *Caches,
            scratch: *ArenaAllocator,
        ) sexpr.Parser.ParseError!Item {
            const list = try contents.parseListInList(parent, ctx);
            return parseList(list, ctx, arena, caches, scratch);
        }
    };
};

pub fn parseFields(
    contents: *sexpr.Parser,
    ctx: *ParseContext,
    arena: *IndexedArena,
    caches: *Caches,
    scratch: *ArenaAllocator,
) error{OutOfMemory}!IndexedArena.Slice(Field) {
    var fields = try IndexedArena.BoundedArrayList(Field).initCapacity(arena, contents.remaining.len);

    arena.ensureUnusedCapacityForBytes(@import("../../size.zig").averageOfFields(Field) *| fields.capacity) catch {};

    while (true) {
        const field_list: sexpr.List.Id = contents.parseList(ctx) catch |e| switch (e) {
            error.EndOfStream => break,
            error.OutOfMemory => |oom| return oom,
            error.ReportedParserError => continue,
        };

        var field_contents = sexpr.Parser.init(field_list.contents(ctx.tree).values(ctx.tree));
        const field_keyword = (field_contents.parseAtomInList(field_list, ctx, "module field")) catch |e| switch (e) {
            error.OutOfMemory => |oom| return oom,
            error.ReportedParserError => continue,
        };

        _ = scratch.reset(.retain_capacity);
        const module_field: Contents = field: switch (field_keyword.tag(ctx.tree)) {
            .keyword_type => {
                const type_def = try arena.create(Type);

                const parsed_type = Type.parseContents(
                    &field_contents,
                    ctx,
                    field_list,
                    arena,
                    caches,
                    scratch,
                ) catch |e| switch (e) {
                    error.OutOfMemory => |oom| return oom,
                    error.ReportedParserError => continue,
                };

                type_def.set(arena, parsed_type);
                break :field .{ .type = type_def };
            },
            .keyword_func => {
                const func = try arena.create(Func);

                const parsed_func = Func.parseContents(
                    &field_contents,
                    ctx,
                    field_list,
                    arena,
                    caches,
                    scratch,
                ) catch |e| switch (e) {
                    error.OutOfMemory => |oom| return oom,
                    error.ReportedParserError => continue,
                };

                func.set(arena, parsed_func);

                break :field .{ .func = func };
            },
            .keyword_table => {
                const parsed_table = Table.parseContents(
                    &field_contents,
                    ctx,
                    field_list,
                    arena,
                    caches,
                    scratch,
                ) catch |e| switch (e) {
                    error.OutOfMemory => |oom| return oom,
                    error.ReportedParserError => continue,
                };

                break :field .{ .table = parsed_table };
            },
            .keyword_memory => {
                const mem = try arena.create(Mem);
                const parsed_mem = Mem.parseContents(
                    &field_contents,
                    ctx,
                    field_list,
                    arena,
                    caches,
                    scratch,
                ) catch |e| switch (e) {
                    error.OutOfMemory => |oom| return oom,
                    error.ReportedParserError => continue,
                };

                mem.set(arena, parsed_mem);
                break :field .{ .mem = mem };
            },
            .keyword_global => {
                const parsed_global = Global.parseContents(
                    &field_contents,
                    ctx,
                    field_list,
                    arena,
                    caches,
                    scratch,
                ) catch |e| switch (e) {
                    error.OutOfMemory => |oom| return oom,
                    error.ReportedParserError => continue,
                };

                break :field .{ .global = parsed_global };
            },
            else => {
                _ = try ctx.errorAtToken(field_keyword, "expected module field keyword");
                continue;
            },
        };

        try field_contents.expectEmpty(ctx);

        fields.appendAssumeCapacity(
            arena,
            .{ .keyword = field_keyword, .contents = module_field },
        );
    }

    std.debug.assert(contents.isEmpty());

    return fields.items;
}
