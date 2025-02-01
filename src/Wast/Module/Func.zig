const std = @import("std");
const IndexedArena = @import("../../IndexedArena.zig");

const sexpr = @import("../sexpr.zig");
const ParseContext = sexpr.Parser.Context;

const Ident = @import("../ident.zig").Ident;
const Name = @import("../Name.zig");
const Caches = @import("../Caches.zig");

const Text = @import("Text.zig");

id: Ident.Symbolic align(4),
inline_exports: Text.InlineExports,
inline_import: sexpr.TokenId.Opt,
type_use: Text.TypeUse,
locals: IndexedArena.Slice(Text.Local),
body: union {
    defined: Text.Expr,
    inline_import: Text.ImportName,
},

const Func = @This();

pub fn parseContents(
    contents: *sexpr.Parser,
    ctx: *ParseContext,
    parent: sexpr.List.Id,
    arena: *IndexedArena,
    caches: *Caches,
    alloca: *std.heap.ArenaAllocator,
) sexpr.Parser.ParseError!Func {
    // Arena used for allocations that span the lifetime of this function call.
    _ = alloca.reset(.retain_capacity);

    var scratch = std.heap.ArenaAllocator.init(alloca.allocator());

    const id = try Ident.Symbolic.parse(
        contents,
        ctx.tree,
        caches.allocator,
        &caches.ids,
    );

    const import_exports = try Text.InlineImportExports.parseContents(
        contents,
        ctx,
        arena,
        caches,
        &scratch,
    );

    const type_use = try Text.TypeUse.parseContents(
        contents,
        ctx,
        arena,
        caches,
        &scratch,
    );

    scratch = undefined;

    // Allocated in `alloca`.
    var locals = std.SegmentedList(Text.Local, 4){};
    {
        var lookahead = contents.*;
        while (lookahead.parseValue() catch null) |maybe_list| {
            const local_list: sexpr.List.Id = maybe_list.getList() orelse break;
            var local_contents = sexpr.Parser.init(local_list.contents(ctx.tree).values(ctx.tree));
            const local_keyword = (local_contents.parseValue() catch break).getAtom() orelse break;

            if (local_keyword.tag(ctx.tree) != .keyword_local) break;

            const local = try Text.Local.parseContents(
                &local_contents,
                ctx,
                arena,
                caches,
                local_keyword,
                local_list,
            );

            std.debug.assert(local_contents.isEmpty());

            try locals.append(alloca.allocator(), local);

            contents.* = lookahead;
        }
    }

    scratch = undefined;

    var func = Func{
        .id = id,
        .inline_exports = import_exports.exports,
        .inline_import = import_exports.import.keyword,
        .type_use = type_use,
        .locals = try arena.dupeSegmentedList(Text.Local, 4, &locals),
        .body = undefined,
    };

    _ = alloca.reset(.retain_capacity);

    func.body = if (import_exports.import.keyword.some) inline_import: {
        try contents.expectEmpty(ctx);
        break :inline_import .{ .inline_import = import_exports.import.name };
    } else .{
        .defined = try Text.Expr.parseContents(
            contents,
            ctx,
            parent,
            arena,
            caches,
            alloca,
        ),
    };

    return func;
}
