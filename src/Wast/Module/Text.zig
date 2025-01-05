//! A module in the [WebAssembly Text] format.
//!
//! [WebAssembly Text]: https://webassembly.github.io/spec/core/index.html

const std = @import("std");
const ArenaAllocator = std.heap.ArenaAllocator;
const IndexedArena = @import("../../IndexedArena.zig");

const sexpr = @import("../sexpr.zig");
const Error = sexpr.Error;
const ParseResult = sexpr.Parser.Result;

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
    // global: IndexedArena.Idx(Global),
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
        tree: *const sexpr.Tree,
        parent: sexpr.List.Id,
    ) ParseResult(ValType) {
        switch (atom.tag(tree)) {
            .keyword_i32, .keyword_i64, .keyword_f32, .keyword_f64, .keyword_funcref, .keyword_externref => {},
            else => return .{
                .err = Error.initUnexpectedValue(sexpr.Value.initAtom(atom), .at_value),
            },
        }

        _ = parser;
        _ = parent;

        return .{ .ok = .{ .keyword = atom, .type = .{ .simple = {} } } };
    }

    pub fn parse(parser: *sexpr.Parser, tree: *const sexpr.Tree, parent: sexpr.List.Id) ParseResult(ValType) {
        const atom: sexpr.TokenId = switch (parser.parseAtomInList(.keyword_unknown, parent)) {
            .ok => |ok| ok,
            .err => |err| return .{ .err = err },
        };

        return parseAtom(atom, parser, tree, parent);
    }
};

pub const Export = struct {
    /// The `export` keyword.
    keyword: sexpr.TokenId,
    name: Name,

    pub fn parseContents(
        contents: *sexpr.Parser,
        tree: *const sexpr.Tree,
        arena: *IndexedArena,
        caches: *Caches,
        keyword: sexpr.TokenId,
        parent: sexpr.List.Id,
        scratch: *ArenaAllocator,
    ) error{OutOfMemory}!ParseResult(Export) {
        std.debug.assert(keyword.tag(tree) == .keyword_export);
        return switch (try Name.parse(contents, tree, caches.allocator, &caches.names, arena, parent, scratch)) {
            .ok => |name| .{ .ok = Export{ .keyword = keyword, .name = name } },
            .err => |err| .{ .err = err },
        };
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
        tree: *const sexpr.Tree,
        arena: *IndexedArena,
        caches: *Caches,
        keyword: sexpr.TokenId,
        parent: sexpr.List.Id,
        errors: *Error.List,
    ) error{OutOfMemory}!ParamOrLocal {
        const ident = try Ident.Symbolic.parse(contents, tree, caches.allocator, &caches.ids);

        var types = try IndexedArena.BoundedArrayList(ValType).initCapacity(arena, contents.remaining.len);
        while (!contents.isEmpty()) {
            const val_type = switch (ValType.parse(contents, tree, parent)) {
                .ok => |ok| ok,
                .err => |err| {
                    try errors.append(err);
                    continue;
                },
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
        tree: *const sexpr.Tree,
        arena: *IndexedArena,
        keyword: sexpr.TokenId,
        parent: sexpr.List.Id,
        errors: *Error.List,
    ) error{OutOfMemory}!Text.Result {
        std.debug.assert(keyword.tag(tree) == .keyword_result);

        var types = try IndexedArena.BoundedArrayList(ValType).initCapacity(arena, contents.remaining.len);
        while (!contents.isEmpty()) {
            const val_type = switch (ValType.parse(contents, tree, parent)) {
                .ok => |ok| ok,
                .err => |err| {
                    try errors.append(err);
                    continue;
                },
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
        tree: *const sexpr.Tree,
        arena: *IndexedArena,
        caches: *Caches,
        parent: sexpr.List.Id,
        scratch: *ArenaAllocator,
    ) error{OutOfMemory}!ParseResult(ImportName) {
        const module = switch (try Name.parse(contents, tree, caches.allocator, &caches.names, arena, parent, scratch)) {
            .ok => |ok| ok,
            .err => |err| return .{ .err = err },
        };

        _ = scratch.reset(.retain_capacity);
        const name = switch (try Name.parse(contents, tree, caches.allocator, &caches.names, arena, parent, scratch)) {
            .ok => |ok| ok,
            .err => |err| return .{ .err = err },
        };

        return .{ .ok = ImportName{ .module = module, .name = name } };
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
        tree: *const sexpr.Tree,
        arena: *IndexedArena,
        caches: *Caches,
        keyword: sexpr.TokenId,
        parent: sexpr.List.Id,
        scratch: *ArenaAllocator,
    ) error{OutOfMemory}!ParseResult(InlineImport) {
        std.debug.assert(keyword.tag(tree) == .keyword_import);

        const name_result = try ImportName.parseContents(contents, tree, arena, caches, parent, scratch);
        return switch (name_result) {
            .ok => |name| .{
                .ok = InlineImport{
                    .keyword = sexpr.TokenId.Opt.init(keyword),
                    .name = name,
                },
            },
            .err => |err| .{ .err = err },
        };
    }
};

pub const MemType = struct {
    limits: Limits,

    pub fn parseContents(
        contents: *sexpr.Parser,
        tree: *const sexpr.Tree,
        parent: sexpr.List.Id,
        errors: *Error.List,
    ) error{OutOfMemory}!ParseResult(MemType) {
        const limits = switch (try Limits.parseContents(contents, tree, parent, errors)) {
            .ok => |ok| ok,
            .err => |err| return .{ .err = err },
        };

        return .{ .ok = .{ .limits = limits } };
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
        tree: *const sexpr.Tree,
        arena: *IndexedArena,
        caches: *Caches,
        errors: *Error.List,
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
            var list_contents = sexpr.Parser.init(list.contents(tree).values(tree));

            const keyword = (list_contents.parseValue() catch break).getAtom() orelse break;

            switch (keyword.tag(tree)) {
                .keyword_export => {
                    if (import_exports.import.keyword.some) break;

                    const result = try Export.parseContents(
                        &list_contents,
                        tree,
                        arena,
                        caches,
                        keyword,
                        list,
                        &scratch,
                    );

                    switch (result) {
                        .ok => |ok| try export_buf.append(scratch.allocator(), ok),
                        .err => break,
                    }
                },
                .keyword_import => {
                    std.debug.assert(!import_exports.import.keyword.some);

                    const import_result = try InlineImport.parseContents(
                        &list_contents,
                        tree,
                        arena,
                        caches,
                        keyword,
                        list,
                        &scratch,
                    );

                    switch (import_result) {
                        .ok => |ok| import_exports.import = ok,
                        .err => break,
                    }
                },
                else => break,
            }

            try list_contents.expectEmpty(errors);

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
        tree: *const sexpr.Tree,
        parent: sexpr.List.Id,
        arena: *IndexedArena,
        caches: *Caches,
        errors: *Error.List,
        scratch: *ArenaAllocator,
    ) error{OutOfMemory}!ParseResult(Mem) {
        const id = try Ident.Symbolic.parse(contents, tree, caches.allocator, &caches.ids);

        const import_exports = try InlineImportExports.parseContents(contents, tree, arena, caches, errors, scratch);

        const mem_type = switch (try MemType.parseContents(contents, tree, parent, errors)) {
            .ok => |ok| ok,
            .err => |err| return .{ .err = err },
        };

        return .{
            .ok = .{
                .id = id,
                .import_exports = import_exports,
                .mem_type = mem_type,
            },
        };
    }
};

pub const TableType = struct {
    limits: Limits,
    ref_type: sexpr.TokenId,

    pub fn parseContents(
        contents: *sexpr.Parser,
        tree: *const sexpr.Tree,
        parent: sexpr.List.Id,
        errors: *Error.List,
    ) error{OutOfMemory}!ParseResult(TableType) {
        const limits = switch (try Limits.parseContents(contents, tree, parent, errors)) {
            .ok => |ok| ok,
            .err => |err| return .{ .err = err },
        };

        const ref_type = switch (contents.parseAtomInList(null, parent)) {
            .ok => |ok| ok,
            .err => |err| return .{ .err = err },
        };

        switch (ref_type.tag(tree)) {
            .keyword_funcref, .keyword_externref => {},
            else => return .{ .err = Error.initUnexpectedValue(sexpr.Value.initAtom(ref_type), .at_value) },
        }

        return .{ .ok = .{ .limits = limits, .ref_type = ref_type } };
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
        indices: IndexedArena.Slice(Ident.Unaligned),
    };

    comptime {
        std.debug.assert(@alignOf(Table) == @alignOf(u32));
    }

    pub fn parseContents(
        contents: *sexpr.Parser,
        tree: *const sexpr.Tree,
        parent: sexpr.List.Id,
        arena: *IndexedArena,
        caches: *Caches,
        errors: *Error.List,
        scratch: *ArenaAllocator,
    ) error{OutOfMemory}!ParseResult(IndexedArena.Idx(Table)) {
        const table_idx = try arena.create(Table);

        const id = try Ident.Symbolic.parse(contents, tree, caches.allocator, &caches.ids);

        const import_exports = try InlineImportExports.parseContents(contents, tree, arena, caches, errors, scratch);

        // Decide if a `tabletype` or a `reftype` has to be parsed.
        var lookahead: sexpr.Parser = contents.*;
        const type_token: sexpr.TokenId = switch (lookahead.parseAtomInList(null, parent)) {
            .ok => |ok| ok,
            .err => |err| return .{ .err = err },
        };

        const table = table: switch (type_token.tag(tree)) {
            // Detect the limits of a `tabletype`.
            .integer => {
                contents.* = lookahead;
                lookahead = undefined;

                const table_type = switch (try TableType.parseContents(contents, tree, parent, errors)) {
                    .ok => |ok| ok,
                    .err => |err| return .{ .err = err },
                };

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

                if (import_exports.import.keyword.some) return .{
                    .err = Error.initUnexpectedValue(sexpr.Value.initAtom(type_token), .at_value),
                };

                const elem_list: sexpr.List.Id = switch (contents.parseListInList(parent)) {
                    .ok => |ok| ok,
                    .err => |err| return .{ .err = err },
                };

                var elem_contents = sexpr.Parser.init(elem_list.contents(tree).values(tree));
                const elem_keyword = switch (elem_contents.parseAtomInList(.keyword_elem, elem_list)) {
                    .ok => |ok| ok,
                    .err => |err| return .{ .err = err },
                };

                const first_elem_value = elem_contents.parseValue() catch return .{
                    .err = Error.initExpectedToken(sexpr.Value.initList(elem_list), .integer, .at_list_end),
                };

                const elements = elements: switch (first_elem_value.unpacked()) {
                    .atom => |first_idx| {
                        var indices = try IndexedArena.BoundedArrayList(Ident.Unaligned).initCapacity(
                            arena,
                            1 + elem_contents.remaining.len,
                        );

                        switch (try Ident.parseAtom(first_idx, tree, caches.allocator, &caches.ids)) {
                            .ok => |ok| indices.appendAssumeCapacity(arena, .{ .ident = ok }),
                            .err => |err| return .{ .err = err },
                        }

                        while (!elem_contents.isEmpty()) {
                            switch (try Ident.parse(&elem_contents, tree, elem_list, caches.allocator, &caches.ids)) {
                                .ok => |ok| indices.appendAssumeCapacity(arena, .{ .ident = ok }),
                                .err => |err| return .{ .err = err },
                            }
                        }

                        break :elements InlineElements{ .indices = indices.items };
                    },
                    .list => |first_elem_list| {
                        var items = try IndexedArena.BoundedArrayList(ElementSegment.Item).initCapacity(
                            arena,
                            1 + elem_contents.remaining.len,
                        );

                        _ = scratch.reset(.retain_capacity);
                        switch (try ElementSegment.Item.parseList(first_elem_list, tree, arena, caches, errors, scratch)) {
                            .ok => |ok| items.appendAssumeCapacity(arena, ok),
                            .err => |err| return .{ .err = err },
                        }

                        while (!elem_contents.isEmpty()) {
                            _ = scratch.reset(.retain_capacity);
                            const parsed_item = try ElementSegment.Item.parse(
                                &elem_contents,
                                tree,
                                elem_list,
                                arena,
                                caches,
                                errors,
                                scratch,
                            );

                            switch (parsed_item) {
                                .ok => |ok| items.appendAssumeCapacity(arena, ok),
                                .err => |err| return .{ .err = err },
                            }
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
            else => return .{ .err = Error.initUnexpectedValue(sexpr.Value.initAtom(type_token), .at_value) },
        };

        table_idx.set(arena, table);

        return .{ .ok = table_idx };
    }
};

pub const GlobalType = struct {
    mut: sexpr.TokenId.Opt,
    val_type: ValType,

    pub fn parse(
        parser: *sexpr.Parser,
        tree: *const sexpr.Tree,
        parent: sexpr.List.Id,
        errors: *Error.List,
    ) error{OutOfMemory}!ParseResult(GlobalType) {
        const value = parser.parseValue() catch return .{
            .err = Error.initUnexpectedValue(sexpr.Value.initList(parent), .at_list_end),
        };

        switch (value.unpacked()) {
            .atom => |type_keyword| return switch (ValType.parseAtom(type_keyword, parser, tree, parent)) {
                .ok => |val_type| .{ .ok = .{ .mut = .none, .val_type = val_type } },
                .err => |err| .{ .err = err },
            },
            .list => |list| {
                var list_contents = sexpr.Parser.init(list.contents(tree).values(tree));
                const mut_keyword = switch (list_contents.parseAtomInList(.keyword_mut, list)) {
                    .ok => |ok| ok,
                    .err => |err| return .{ .err = err },
                };

                if (mut_keyword.tag(tree) != .keyword_mut) return .{
                    .err = Error.initExpectedToken(sexpr.Value.initAtom(mut_keyword), .keyword_mut, .at_value),
                };

                const val_type = switch (ValType.parse(&list_contents, tree, parent)) {
                    .ok => |ok| ok,
                    .err => |err| return .{ .err = err },
                };

                try list_contents.expectEmpty(errors);

                return .{ .ok = .{ .mut = sexpr.TokenId.Opt.init(mut_keyword), .val_type = val_type } };
            },
        }
    }
};

// pub const Global = struct {
//     id: Ident.Symbolic align(4),
//     import_exports: InlineImportExports,
//     global_type: GlobalType,
//     init: Expr,

//     pub fn parseContents(
//         contents: *sexpr.Parser,
//         tree: *const sexpr.Tree,
//         parent: sexpr.List.Id,
//         arena: *IndexedArena,
//         caches: *Caches,
//         errors: *Error.List,
//         scratch: *ArenaAllocator,
//     ) error{OutOfMemory}!ParseResult(IndexedArena.Idx(Global)) {
//         const global = try arena.create(Global);

//         const id = try Ident.Symbolic.parse(contents, tree, caches.allocator, &caches.ids);

//         const import_exports = try InlineImportExports.parseContents(contents, tree, arena, caches, errors, scratch);

//         unreachable; // TODO
//     }
// };

pub const ElementSegment = struct {
    /// An *`elemexpr`*.
    pub const Item = struct {
        /// The `item` keyword.
        keyword: sexpr.TokenId,
        expr: Expr,

        pub fn parseList(
            list: sexpr.List.Id,
            tree: *const sexpr.Tree,
            arena: *IndexedArena,
            caches: *Caches,
            errors: *Error.List,
            scratch: *ArenaAllocator,
        ) error{OutOfMemory}!ParseResult(Item) {
            var contents = sexpr.Parser.init(list.contents(tree).values(tree));
            var item_keyword = switch (contents.parseAtomInList(.keyword_item, list)) {
                .ok => |ok| ok,
                .err => |err| return .{ .err = err },
            };

            if (item_keyword.tag(tree) != .keyword_item) return .{
                .err = Error.initExpectedToken(sexpr.Value.initAtom(item_keyword), .keyword_item, .at_value),
            };

            const expr = try Expr.parseContents(
                &contents,
                tree,
                list,
                arena,
                caches,
                errors,
                scratch,
            );

            std.debug.assert(contents.isEmpty());

            return .{ .ok = .{ .keyword = item_keyword, .expr = expr } };
        }

        pub fn parse(
            contents: *sexpr.Parser,
            tree: *const sexpr.Tree,
            parent: sexpr.List.Id,
            arena: *IndexedArena,
            caches: *Caches,
            errors: *Error.List,
            scratch: *ArenaAllocator,
        ) error{OutOfMemory}!ParseResult(Item) {
            const list = switch (contents.parseListInList(parent)) {
                .ok => |ok| ok,
                .err => |err| return .{ .err = err },
            };

            return parseList(list, tree, arena, caches, errors, scratch);
        }
    };
};

pub fn parseFields(
    contents: *sexpr.Parser,
    tree: *const sexpr.Tree,
    arena: *IndexedArena,
    caches: *Caches,
    errors: *Error.List,
    scratch: *ArenaAllocator,
) error{OutOfMemory}!IndexedArena.Slice(Field) {
    var fields = try IndexedArena.BoundedArrayList(Field).initCapacity(arena, contents.remaining.len);

    arena.ensureUnusedCapacityForBytes(@import("../../size.zig").averageOfFields(Field) *| fields.capacity) catch {};

    while (contents.parseList() catch null) |field_list_result| {
        const field_list: sexpr.List.Id = switch (field_list_result) {
            .ok => |ok| ok,
            .err => |err| {
                try errors.append(err);
                continue;
            },
        };

        var field_contents = sexpr.Parser.init(field_list.contents(tree).values(tree));
        const field_keyword = switch (field_contents.parseAtomInList(.keyword_unknown, field_list)) {
            .ok => |ok| ok,
            .err => |err| {
                try errors.append(err);
                continue;
            },
        };

        _ = scratch.reset(.retain_capacity);
        const module_field: Contents = field: switch (field_keyword.tag(tree)) {
            .keyword_type => {
                const type_def = try arena.create(Type);

                const type_result = try Type.parseContents(
                    &field_contents,
                    tree,
                    field_list,
                    arena,
                    caches,
                    errors,
                    scratch,
                );

                type_def.set(
                    arena,
                    switch (type_result) {
                        .ok => |ok| ok,
                        .err => |err| {
                            try errors.append(err);
                            continue;
                        },
                    },
                );

                break :field .{ .type = type_def };
            },
            .keyword_func => {
                const func = try arena.create(Func);

                const func_result = try Func.parseContents(
                    &field_contents,
                    tree,
                    field_list,
                    arena,
                    caches,
                    errors,
                    scratch,
                );

                func.set(
                    arena,
                    switch (func_result) {
                        .ok => |ok| ok,
                        .err => |err| {
                            try errors.append(err);
                            continue;
                        },
                    },
                );

                break :field .{ .func = func };
            },
            .keyword_table => {
                const parsed_table = try Table.parseContents(
                    &field_contents,
                    tree,
                    field_list,
                    arena,
                    caches,
                    errors,
                    scratch,
                );

                switch (parsed_table) {
                    .ok => |table| break :field .{ .table = table },
                    .err => |err| {
                        try errors.append(err);
                        continue;
                    },
                }
            },
            .keyword_memory => {
                const mem = try arena.create(Mem);
                const parsed_mem = try Mem.parseContents(
                    &field_contents,
                    tree,
                    field_list,
                    arena,
                    caches,
                    errors,
                    scratch,
                );

                switch (parsed_mem) {
                    .ok => |ok| {
                        mem.set(arena, ok);
                        break :field .{ .mem = mem };
                    },
                    .err => |err| {
                        try errors.append(err);
                        continue;
                    },
                }
            },
            else => {
                try errors.append(Error.initUnexpectedValue(sexpr.Value.initAtom(field_keyword), .at_value));
                continue;
            },
        };

        try field_contents.expectEmpty(errors);

        fields.appendAssumeCapacity(
            arena,
            .{ .keyword = field_keyword, .contents = module_field },
        );
    }

    std.debug.assert(contents.isEmpty());

    return fields.items;
}
