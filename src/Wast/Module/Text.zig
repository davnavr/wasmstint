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
    // table: IndexedArena.Idx(Table),
    mem: IndexedArena.Idx(Mem),
};

pub const ValType = struct {
    keyword: sexpr.TokenId, // sexpr.Value // GC proposal support
    type: Types,

    const Types = union { simple: void };

    comptime {
        std.debug.assert(@sizeOf(ValType) <= 8);
    }

    pub fn parse(parser: *sexpr.Parser, tree: *const sexpr.Tree, parent: sexpr.List.Id) ParseResult(ValType) {
        const atom: sexpr.TokenId = switch (parser.parseAtomInList(.keyword_unknown, parent)) {
            .ok => |ok| ok,
            .err => |err| return .{ .err = err },
        };

        switch (atom.tag(tree)) {
            .keyword_i32, .keyword_i64, .keyword_f32, .keyword_f64, .keyword_funcref, .keyword_externref => {},
            else => return .{ .err = Error.initUnexpectedValue(sexpr.Value.initAtom(atom), .at_value) },
        }

        return .{ .ok = .{ .keyword = atom, .type = .{ .simple = {} } } };
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
    /// The `import` keyword.
    keyword: sexpr.TokenId,
    module: Name,
    name: Name,

    pub fn parseContents(
        contents: *sexpr.Parser,
        tree: *const sexpr.Tree,
        arena: *IndexedArena,
        caches: *Caches,
        keyword: sexpr.TokenId,
        parent: sexpr.List.Id,
        scratch: *ArenaAllocator,
    ) error{OutOfMemory}!ParseResult(ImportName) {
        std.debug.assert(keyword.tag(tree) == .keyword_import);

        const module = switch (try Name.parse(contents, tree, caches.allocator, &caches.names, arena, parent, scratch)) {
            .ok => |ok| ok,
            .err => |err| return .{ .err = err },
        };

        _ = scratch.reset(.retain_capacity);
        const name = switch (try Name.parse(contents, tree, caches.allocator, &caches.names, arena, parent, scratch)) {
            .ok => |ok| ok,
            .err => |err| return .{ .err = err },
        };

        return .{ .ok = ImportName{ .keyword = keyword, .module = module, .name = name } };
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

/// Used when parsing memories and tables.
pub const InlineImportExports = struct {
    exports: IndexedArena.Slice(Export),
    import: Import,

    const Import = IndexedArena.Idx(ImportName).Opt;

    pub const none = InlineImportExports{ .exports = .empty, .import = .none };

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

        while (!import_exports.import.some) {
            _ = scratch.reset(.retain_capacity);
            const list = (lookahead.parseValue() catch break).getList() orelse break;
            var list_contents = sexpr.Parser.init(list.contents(tree).values(tree));

            const keyword = (list_contents.parseValue() catch break).getAtom() orelse break;

            switch (keyword.tag(tree)) {
                .keyword_export => {
                    if (import_exports.import.some) break;

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
                    std.debug.assert(!import_exports.import.some);

                    const import = try arena.create(ImportName);
                    const result = try ImportName.parseContents(
                        &list_contents,
                        tree,
                        arena,
                        caches,
                        keyword,
                        list,
                        &scratch,
                    );

                    switch (result) {
                        .ok => |ok| {
                            import.set(arena, ok);
                            import_exports.import = Import.init(import);
                        },
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
    ) error{OutOfMemory}!ParseResult(MemType) {
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
    import_exports: InlineImportExports,
    table_type: TableType,
    inline_element_segment: struct {
        /// The `elem` keyword.
        ///
        /// If `.none`, then an inline element segment was not specified.
        keyword: sexpr.TokenId.Opt,
        /// If `keyword == .none`, this must not be accessed.
        elements: InlineElements,
    },

    pub const InlineElements = union(enum) {
        expressions: IndexedArena.Slice(ElementSegment.Item),
        indices: IndexedArena.Slice(Ident.Unaligned),

        const unspecified = std.mem.zeroes(InlineElements);
    };

    comptime {
        std.debug.assert(@alignOf(Table) == @alignOf(u32));
    }
};

pub const ElementSegment = struct {
    /// An *`elemexpr`*.
    pub const Item = struct {
        /// The `item` keyword.
        keyword: sexpr.TokenId,
        expr: Expr,
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
