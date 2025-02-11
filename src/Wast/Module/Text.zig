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
    data: IndexedArena.Idx(Data),
    elem: IndexedArena.Idx(Elem),
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
        var ident = try Ident.Symbolic.parse(
            contents,
            ctx.tree,
            caches.allocator,
            &caches.ids,
        );

        var types = try IndexedArena.BoundedArrayList(ValType).initCapacity(
            arena,
            contents.remaining.len,
        );

        if (ident.some) err: {
            const val_type = ValType.parse(contents, ctx, parent) catch |e| switch (e) {
                error.OutOfMemory => |oom| return oom,
                error.ReportedParserError => {
                    ident = Ident.Symbolic.none;
                    break :err;
                },
            };

            types.appendAssumeCapacity(arena, val_type);
            try contents.expectEmpty(ctx);
        } else {
            for (0..types.capacity) |_| {
                const val_type = ValType.parse(contents, ctx, parent) catch |e| switch (e) {
                    error.OutOfMemory => |oom| return oom,
                    error.ReportedParserError => continue,
                };

                types.appendAssumeCapacity(arena, val_type);
            }
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

pub const StringLiteral = struct {
    token: sexpr.TokenId,

    /// The contents of the string literal, without translating escape sequences.
    ///
    /// This is always valid UTF-8, though it may not be after translating its escape sequences.
    pub fn rawContents(lit: StringLiteral, tree: *const sexpr.Tree) []const u8 {
        const bytes = lit.token.contents(tree);
        const tag = lit.token.tag(tree);
        std.debug.assert(tag == .string or tag == .string_raw);
        return bytes[1 .. bytes.len - 1];
    }
};

pub const DataString = struct {
    contents: IndexedArena.Slice(StringLiteral),

    pub fn parseContents(
        contents: *sexpr.Parser,
        ctx: *ParseContext,
        arena: *IndexedArena,
    ) error{OutOfMemory}!DataString {
        var strings = try IndexedArena.BoundedArrayList(StringLiteral).initCapacity(
            arena,
            contents.remaining.len,
        );

        for (0..strings.capacity) |_| {
            const lit_token = contents.parseAtom(
                ctx,
                "data string literal",
            ) catch |e| switch (e) {
                error.OutOfMemory => |err| return err,
                error.ReportedParserError => continue,
                error.EndOfStream => unreachable,
            };

            switch (lit_token.tag(ctx.tree)) {
                .string, .string_raw => strings.appendAssumeCapacity(
                    arena,
                    StringLiteral{ .token = lit_token },
                ),
                else => _ = try ctx.errorAtToken(lit_token, "expected data string literal"),
            }
        }

        return .{ .contents = strings.items };
    }

    pub fn writeToBuf(
        data: *const DataString,
        tree: *const sexpr.Tree,
        arena: IndexedArena.ConstData,
        allocator: std.mem.Allocator,
    ) error{OutOfMemory}!std.ArrayListUnmanaged(u8) {
        var buf = std.ArrayList(u8).init(allocator);
        errdefer buf.deinit();

        for (
            @as([]const StringLiteral, data.contents.items(arena)),
            0..data.contents.len,
        ) |data_string, i| {
            const raw_string = data_string.rawContents(tree);
            var string_escapes = @import("../value.zig").string(raw_string);

            // In the worst case, all of the remaining input encodes UTF-8 codepoints at a 10-to-1 ratio.
            // In the best case, 1 byte in the string corresponds to one byte in the output.
            try buf.ensureUnusedCapacity(raw_string.len / 2);
            try string_escapes.appendToBuf(&buf, i == data.contents.len - 1);

            std.debug.assert(string_escapes.remaining.len == 0);
        }

        return buf.moveToUnmanaged();
    }
};

pub const Mem = struct {
    id: Ident.Symbolic align(4),
    inline_exports: InlineExports,
    /// Indicates that a memory type is not explicitly specified, and that an inline data segment is present.
    ///
    /// If `.none`, then `inner == no_data`.
    data_keyword: sexpr.TokenId.Opt,
    inner: union {
        /// Invariant that `data_keyword == .none`.
        no_data: struct {
            inline_import: InlineImport,
            mem_type: MemType,
        },
        /// A data segment with an implicit offset of `0`.
        ///
        /// The memory type is also implied to be the length of the data segment rounded up to the nearest
        /// multiple of the page size.
        data: DataString,
    },

    pub fn parseContents(
        contents: *sexpr.Parser,
        ctx: *ParseContext,
        parent: sexpr.List.Id,
        arena: *IndexedArena,
        caches: *Caches,
        scratch: *ArenaAllocator,
    ) sexpr.Parser.ParseError!IndexedArena.Idx(Mem) {
        const mem_idx = try arena.create(Mem);

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

        // Decide if a `memtype` or inline data segment is present.
        var lookahead: sexpr.Parser = contents.*;
        const memtype_or_data = lookahead.parseValue() catch
            return (try ctx.errorAtList(parent, .end, "expected memtype or inline data segment")).err;

        const mem: Mem = switch (memtype_or_data.unpacked()) {
            .atom => .{
                .id = id,
                .inline_exports = import_exports.exports,
                .data_keyword = .none,
                .inner = .{
                    .no_data = .{
                        .inline_import = import_exports.import,
                        .mem_type = try MemType.parseContents(contents, ctx, parent),
                    },
                },
            },
            .list => |data_list| with_data: {
                contents.* = lookahead;
                var in_data = sexpr.Parser.init(data_list.contents(ctx.tree).values(ctx.tree));
                const data_keyword = try in_data.parseAtomInList(data_list, ctx, "'data' keyword");
                if (data_keyword.tag(ctx.tree) != .keyword_data)
                    return (try ctx.errorAtToken(data_keyword, "expected 'data' keyword")).err;

                const data = try DataString.parseContents(&in_data, ctx, arena);

                std.debug.assert(in_data.isEmpty());
                break :with_data .{
                    .id = id,
                    .inline_exports = import_exports.exports,
                    .data_keyword = sexpr.TokenId.Opt.init(data_keyword),
                    .inner = .{ .data = data },
                };
            },
        };

        mem_idx.set(arena, mem);
        return mem_idx;
    }

    pub fn inlineImport(mem: *const Mem) ?*const InlineImport {
        return if (mem.data_keyword.some) null else &mem.inner.no_data.inline_import;
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
        expressions: IndexedArena.Slice(Elem.Item),
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

        const table: Table = table: switch (type_token.tag(ctx.tree)) {
            // Detect the limits of a `tabletype`.
            .integer => {
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
                        var items = try IndexedArena.BoundedArrayList(Elem.Item).initCapacity(
                            arena,
                            1 + elem_contents.remaining.len,
                        );

                        _ = scratch.reset(.retain_capacity);
                        items.appendAssumeCapacity(
                            arena,
                            try Elem.Item.parseList(
                                first_elem_list,
                                ctx,
                                arena,
                                caches,
                                scratch,
                            ),
                        );

                        while (!elem_contents.isEmpty()) {
                            _ = scratch.reset(.retain_capacity);
                            const parsed_item = try Elem.Item.parse(
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

    pub fn inlineImport(table: *const Table) ?*const InlineImport {
        return if (table.ref_type_keyword.some) null else &table.inner.no_elements.inline_import;
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

pub const Data = struct {
    id: Ident.Symbolic align(4),
    memory: Ident.Opt align(4),
    active: packed struct(u32) {
        /// Must only be set and read when `memory.some`.
        memory_keyword: sexpr.TokenId,
        /// If `true`, then this is an *active* data segment, and an `offset` is present.
        has_offset: bool,
    },
    /// Must only be set and read when `has_offset` is `true`.
    offset: Offset,
    data: DataString,

    pub const Offset = struct {
        /// The `offset` keyword.
        keyword: sexpr.TokenId.Opt,
        expr: Expr,
    };

    pub fn parseContents(
        contents: *sexpr.Parser,
        ctx: *ParseContext,
        parent: sexpr.List.Id,
        arena: *IndexedArena,
        caches: *Caches,
        scratch: *ArenaAllocator,
    ) sexpr.Parser.ParseError!IndexedArena.Idx(Data) {
        const data_idx = try arena.create(Data);
        var data = Data{
            .id = try Ident.Symbolic.parse(
                contents,
                ctx.tree,
                caches.allocator,
                &caches.ids,
            ),
            .memory = .none,
            .active = .{
                .memory_keyword = undefined,
                .has_offset = false,
            },
            .offset = undefined,
            .data = undefined,
        };

        is_passive: {
            var lookahead = contents.*;
            const memuse_or_offset_list = (lookahead.parseValue() catch break :is_passive)
                .getList() orelse break :is_passive;

            contents.* = lookahead;
            lookahead = undefined;
            data.active.has_offset = true;
            data.offset.keyword = .none;

            var memuse_parser = sexpr.Parser.init(
                memuse_or_offset_list
                    .contents(ctx.tree)
                    .values(ctx.tree),
            );
            var offset_parser = memuse_parser;

            const memuse_or_offset_keyword = try memuse_parser.parseAtomInList(
                memuse_or_offset_list,
                ctx,
                "'memory' or 'offset' keyword, or an instruction",
            );

            var offset_list = memuse_or_offset_list;
            var offset_expr_parser = offset_parser;
            var maybe_offset_keyword = memuse_or_offset_keyword;
            if (memuse_or_offset_keyword.tag(ctx.tree) == .keyword_memory) {
                const mem_idx = try Ident.parse(
                    &memuse_parser,
                    ctx,
                    memuse_or_offset_list,
                    caches.allocator,
                    &caches.ids,
                );

                data.memory = Ident.Opt.init(mem_idx);
                data.active.memory_keyword = memuse_or_offset_keyword;

                try memuse_parser.expectEmpty(ctx);

                offset_list = try contents.parseListInList(parent, ctx);
                offset_parser = sexpr.Parser.init(offset_list.contents(ctx.tree).values(ctx.tree));
                offset_expr_parser = offset_parser;
                maybe_offset_keyword = try offset_parser.parseAtomInList(
                    offset_list,
                    ctx,
                    "'offset' keyword or instruction",
                );
            }

            const maybe_offset_tag = maybe_offset_keyword.tag(ctx.tree);
            std.debug.assert(maybe_offset_tag != .keyword_memory);

            const has_offset_keyword = maybe_offset_tag == .keyword_offset;
            if (has_offset_keyword) {
                offset_expr_parser = offset_parser;
                data.offset.keyword = sexpr.TokenId.Opt.init(maybe_offset_keyword);
            }

            offset_parser = undefined;

            data.offset.expr = try Expr.parseContents(
                &offset_expr_parser,
                ctx,
                offset_list,
                arena,
                caches,
                scratch,
            );

            if (!has_offset_keyword and data.offset.expr.count != 2) {
                _ = try ctx.errorFmtAtList(
                    offset_list,
                    .all,
                    "offset abbreviation requires a single instruction, got {} instructions",
                    .{data.offset.expr.count - 1},
                );
            }

            std.debug.assert(offset_expr_parser.isEmpty());
        }

        data.data = try DataString.parseContents(contents, ctx, arena);
        std.debug.assert(contents.isEmpty());

        data_idx.set(arena, data);
        return data_idx;
    }
};

/// <https://webassembly.github.io/spec/core/text/modules.html#element-segments>
pub const Elem = struct {
    id: Ident.Symbolic align(4),
    /// The *table* that an *active* element segment copies its contents to. If omitted,
    /// this implicitly refers to table `0`.
    ///
    /// Always set to `.none` in the case of *passive* and *declarative* element segments.
    table: Ident.Opt align(4),
    /// If `table.some`, then this refers to the `table` keyword in the *tableuse*.
    ///
    /// Otherwise, this is a *passive* element segment when `.none`, or refers to the
    /// `declare` keyword in the case of a *declarative* element segment.
    keyword: sexpr.TokenId.Opt,
    /// Only set for *active* element segments.
    ///
    /// If `.omitted`, then a default offset of `0` is used.
    offset: Offset,
    elements: List,

    pub const Offset = struct {
        inner: Data.Offset,

        pub const omitted = Offset{
            .inner = .{
                .keyword = .none,
                .expr = .{
                    .contents = .empty,
                    .count = 0,
                },
            },
        };

        pub fn isOmitted(offset: *const Offset) bool {
            return offset.inner.expr.count == 0;
        }

        pub fn get(offset: *const Offset) ?*const Data.Offset {
            return if (offset.isOmitted()) null else &offset.inner;
        }
    };

    pub const ElemType = struct {
        /// If this is not a *reftype*, but instead the `func` keyword or `.none`, then the
        /// elements are a sequence of function indices.
        keyword: sexpr.TokenId.Opt,

        pub fn asValType(elem_type: ElemType, tree: *const sexpr.Tree) ?ValType {
            const keyword = elem_type.keyword.get() orelse
                return null;

            return if (keyword.tag(tree) == .keyword_func)
                null
            else
                ValType{ .keyword = keyword, .type = .{ .simple = {} } };
        }
    };

    pub const List = struct {
        ref_type: ElemType,
        items: Items,

        pub const Items = union {
            expressions: IndexedArena.Slice(Item),
            /// Only when `ref_type.token` is the `func` keyword.
            indices: IndexedArena.SliceAligned(Ident, 4),
        };

        pub fn itemsTag(list: *const List, tree: *const sexpr.Tree) std.meta.FieldEnum(Items) {
            return if (!list.ref_type.keyword.some or list.ref_type.keyword.inner_id.tag(tree) == .keyword_func)
                .indices
            else
                .expressions;
        }

        pub fn itemsExpanded(list: *const List, tree: *const sexpr.Tree) Table.InlineElements {
            return switch (list.itemsTag(tree)) {
                inline else => |tag| @unionInit(
                    Table.InlineElements,
                    @tagName(tag),
                    @field(list.items, @tagName(tag)),
                ),
            };
        }
    };

    /// An *`elemexpr`*.
    pub const Item = struct {
        /// The `item` keyword.
        ///
        /// If omitted, then it is an invariant that `expr.count == 2`.
        keyword: sexpr.TokenId.Opt,
        expr: Expr,

        pub fn parseList(
            list: sexpr.List.Id,
            ctx: *ParseContext,
            arena: *IndexedArena,
            caches: *Caches,
            scratch: *ArenaAllocator,
        ) sexpr.Parser.ParseError!Item {
            var item_or_expr_parser = sexpr.Parser.init(list.contents(ctx.tree).values(ctx.tree));
            var expr_parser = item_or_expr_parser;

            var maybe_item_keyword = try item_or_expr_parser.parseAtomInList(list, ctx, "'item' keyword");
            var item_keyword = sexpr.TokenId.Opt.none;

            if (maybe_item_keyword.tag(ctx.tree) == .keyword_item) {
                item_keyword = sexpr.TokenId.Opt.init(maybe_item_keyword);
                expr_parser = item_or_expr_parser;
            }

            item_or_expr_parser = undefined;

            const expr = try Expr.parseContents(
                &expr_parser,
                ctx,
                list,
                arena,
                caches,
                scratch,
            );

            std.debug.assert(expr_parser.isEmpty());

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

    pub fn parseContents(
        contents: *sexpr.Parser,
        ctx: *ParseContext,
        arena: *IndexedArena,
        caches: *Caches,
        scratch: *ArenaAllocator,
    ) sexpr.Parser.ParseError!IndexedArena.Idx(Elem) {
        const elem_idx = try arena.create(Elem);
        var elem = Elem{
            .id = try Ident.Symbolic.parse(
                contents,
                ctx.tree,
                caches.allocator,
                &caches.ids,
            ),
            .table = .none,
            .keyword = .none,
            .offset = .omitted,
            .elements = List{
                .ref_type = .{ .keyword = .none },
                .items = .{ .indices = .empty },
            },
        };

        const State = union(enum) {
            start,
            elem_list,
            offset: struct {
                list: sexpr.List.Id,
                parser: sexpr.Parser,
            },
            offset_or_elem_list,
        };

        state: switch (State{ .start = {} }) {
            .start => {
                var lookahead: sexpr.Parser = contents.*;
                switch ((lookahead.parseValue() catch break :state).unpacked()) {
                    .atom => |token| switch (token.tag(ctx.tree)) {
                        .keyword_declare => {
                            contents.* = lookahead;
                            continue :state .elem_list;
                        },
                        .id, .integer => break :state,
                        else => continue :state .elem_list,
                    },
                    .list => |list| {
                        var list_parser = sexpr.Parser.init(list.contents(ctx.tree).values(ctx.tree));
                        const offset_instr_parser = list_parser;
                        const token = try list_parser.parseAtomInList(
                            list,
                            ctx,
                            "'offset', 'table' or an instruction",
                        );

                        switch (token.tag(ctx.tree)) {
                            .keyword_table => {
                                const table_id = try Ident.parse(
                                    &list_parser,
                                    ctx,
                                    list,
                                    caches.allocator,
                                    &caches.ids,
                                );

                                elem.table = Ident.Opt.init(table_id);
                                elem.keyword = sexpr.TokenId.Opt.init(token);
                                try list_parser.expectEmpty(ctx);

                                contents.* = lookahead;
                                continue :state .offset_or_elem_list;
                            },
                            .keyword_offset => {
                                contents.* = lookahead;
                                continue :state State{
                                    .offset = .{ .parser = list_parser, .list = list },
                                };
                            },
                            .keyword_item => break :state,
                            else => {
                                contents.* = lookahead;
                                continue :state State{
                                    .offset = .{ .parser = offset_instr_parser, .list = list },
                                };
                            },
                        }
                    },
                }
            },
            .offset_or_elem_list => {
                var lookahead: sexpr.Parser = contents.*;
                switch ((lookahead.parseValue() catch break :state).unpacked()) {
                    .atom => continue :state .elem_list,
                    .list => |list| {
                        var list_parser = sexpr.Parser.init(list.contents(ctx.tree).values(ctx.tree));
                        const offset_instr_parser = list_parser;
                        const token = try list_parser.parseAtomInList(
                            list,
                            ctx,
                            "'offset' or an instruction",
                        );

                        switch (token.tag(ctx.tree)) {
                            .keyword_offset => {
                                contents.* = lookahead;
                                continue :state State{
                                    .offset = .{ .parser = list_parser, .list = list },
                                };
                            },
                            .keyword_item => break :state,
                            else => {
                                contents.* = lookahead;
                                continue :state State{
                                    .offset = .{ .parser = offset_instr_parser, .list = list },
                                };
                            },
                        }
                    },
                }
            },
            .offset => |offset| {
                var offset_parser: sexpr.Parser = offset.parser;
                elem.offset.inner.expr = try Expr.parseContents(
                    &offset_parser,
                    ctx,
                    offset.list,
                    arena,
                    caches,
                    scratch,
                );

                std.debug.assert(offset_parser.isEmpty());

                continue :state .elem_list;
            },
            .elem_list => {
                var lookahead: sexpr.Parser = contents.*;
                const maybe_elem_type = lookahead.parseAtom(
                    ctx,
                    "reftype, 'func' keyword, or element list",
                ) catch |e| switch (e) {
                    error.EndOfStream => break :state,
                    else => |err| return err,
                };

                switch (maybe_elem_type.tag(ctx.tree)) {
                    .keyword_func,
                    .keyword_funcref,
                    .keyword_externref,
                    => {
                        elem.elements.ref_type = .{ .keyword = sexpr.TokenId.Opt.init(maybe_elem_type) };
                        contents.* = lookahead;
                        break :state;
                    },
                    .id, .integer => break :state,
                    else => return (try ctx.errorAtToken(
                        maybe_elem_type,
                        "expected reftype, 'func' keyword, or element list",
                    )).err,
                }
            },
        }

        const elem_count = std.math.cast(u32, contents.remaining.len) orelse
            return error.OutOfMemory;

        elem.elements.items = items: switch (elem.elements.itemsTag(ctx.tree)) {
            .indices => {
                var indices = try IndexedArena.BoundedArrayListAligned(Ident, 4).initCapacity(
                    arena,
                    elem_count,
                );

                for (0..elem_count) |_| {
                    const ident_token = contents.parseAtom(
                        ctx,
                        "function identifier or closing parentehsis",
                    ) catch |e| switch (e) {
                        error.EndOfStream => unreachable,
                        else => |err| return err,
                    };

                    indices.appendAssumeCapacity(
                        arena,
                        try Ident.parseAtom(
                            ident_token,
                            ctx,
                            caches.allocator,
                            &caches.ids,
                        ),
                    );
                }

                break :items List.Items{ .indices = indices.items };
            },
            .expressions => {
                var expressions = try IndexedArena.BoundedArrayList(Item).initCapacity(
                    arena,
                    elem_count,
                );

                for (0..elem_count) |_| {
                    _ = scratch.reset(.retain_capacity);

                    const item_list = contents.parseList(ctx) catch |e| switch (e) {
                        error.EndOfStream => unreachable,
                        else => |err| return err,
                    };

                    expressions.appendAssumeCapacity(
                        arena,
                        try Item.parseList(item_list, ctx, arena, caches, scratch),
                    );
                }

                break :items List.Items{ .expressions = expressions.items };
            },
        };

        std.debug.assert(contents.isEmpty());
        elem_idx.set(arena, elem);
        return elem_idx;
    }
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

                break :field .{ .mem = parsed_mem };
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
            .keyword_elem => {
                const parsed_elem = Elem.parseContents(
                    &field_contents,
                    ctx,
                    arena,
                    caches,
                    scratch,
                ) catch |e| switch (e) {
                    error.OutOfMemory => |oom| return oom,
                    error.ReportedParserError => continue,
                };

                break :field .{ .elem = parsed_elem };
            },
            .keyword_data => {
                const parsed_data = Data.parseContents(
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

                break :field .{ .data = parsed_data };
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
