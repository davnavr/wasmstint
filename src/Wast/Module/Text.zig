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
    func: IndexedArena.Idx(Func),
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
    id: Ident.Opt align(4),
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
        const ident = switch (try Ident.Opt.parse(contents, tree, caches.allocator, &caches.ids)) {
            .ok => |ok| ok,
            .err => |err| {
                try errors.append(err);
                return .{ .keyword = keyword, .id = .none, .types = .empty };
            },
        };

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
