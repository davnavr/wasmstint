const std = @import("std");
const IndexedArena = @import("../../IndexedArena.zig");

const sexpr = @import("../sexpr.zig");
const Error = sexpr.Error;

const Ident = @import("../ident.zig").Ident;
const Name = @import("../Name.zig");
const Caches = @import("../Caches.zig");

const Text = @import("Text.zig");

id: Ident.Symbolic align(4),
inline_exports: Text.InlineExports,
inline_import: sexpr.TokenId.Opt,
parameters: IndexedArena.Slice(Text.Param),
results: IndexedArena.Slice(Text.Result),
locals: IndexedArena.Slice(Text.Local),
body: union {
    defined: Text.Expr,
    inline_import: Text.ImportName,
},

const Func = @This();

pub fn parseContents(
    contents: *sexpr.Parser,
    tree: *const sexpr.Tree,
    parent: sexpr.List.Id,
    arena: *IndexedArena,
    caches: *Caches,
    errors: *Error.List,
    alloca: *std.heap.ArenaAllocator,
) error{OutOfMemory}!sexpr.Parser.Result(Func) {
    // Arena used for allocations that span the lifetime of this function call.
    _ = alloca.reset(.retain_capacity);

    var scratch = std.heap.ArenaAllocator.init(alloca.allocator());

    const id = try Ident.Symbolic.parse(contents, tree, caches.allocator, &caches.ids);

    // All of the `SegmentedList`s are allocated in `alloca`.
    var inline_exports = std.SegmentedList(Text.Export, 1){};
    var inline_import = Text.InlineImport.none;
    var parameters = std.SegmentedList(Text.Param, 4){};
    var results = std.SegmentedList(Text.Result, 1){};
    var locals = std.SegmentedList(Text.Local, 4){};

    before_body: {
        var state: enum {
            start,
            exports,
            import,
            parameters,
            results,
            locals,

            const State = @This();

            fn advance(current: *State, to: State) bool {
                if (@intFromEnum(current.*) <= @intFromEnum(to)) {
                    current.* = to;
                    return true;
                } else {
                    return false;
                }
            }
        } = .start;

        var lookahead = contents.*;
        while (lookahead.parseValue() catch null) |maybe_list| {
            _ = scratch.reset(.retain_capacity);

            const field_list: sexpr.List.Id = maybe_list.getList() orelse break :before_body;
            var list_contents = sexpr.Parser.init(field_list.contents(tree).values(tree));

            var keyword = (list_contents.parseValue() catch break :before_body).getAtom() orelse break :before_body;
            switch (keyword.tag(tree)) {
                .keyword_export => {
                    // Treat an incorrect order of these as an unknown instruction.
                    if (!state.advance(.exports)) break :before_body;

                    const export_result = try Text.Export.parseContents(
                        &list_contents,
                        tree,
                        arena,
                        caches,
                        keyword,
                        field_list,
                        &scratch,
                    );

                    try inline_exports.append(
                        alloca.allocator(),
                        switch (export_result) {
                            .ok => |ok| ok,
                            .err => |err| return .{ .err = err },
                        },
                    );
                },
                .keyword_import => {
                    if (!state.advance(.import)) break :before_body;

                    if (!inline_import.keyword.some) {
                        const import_result = try Text.InlineImport.parseContents(
                            &list_contents,
                            tree,
                            arena,
                            caches,
                            keyword,
                            field_list,
                            &scratch,
                        );

                        switch (import_result) {
                            .ok => |import| inline_import = import,
                            .err => |err| try errors.append(err),
                        }
                    } else {
                        // An extra inline import is not fatal.
                        try errors.append(Error.initUnexpectedValue(sexpr.Value.initAtom(keyword), .at_value));
                    }
                },
                .keyword_param => {
                    if (!state.advance(.parameters)) break :before_body;

                    const param = try Text.Param.parseContents(
                        &list_contents,
                        tree,
                        arena,
                        caches,
                        keyword,
                        field_list,
                        errors,
                    );

                    std.debug.assert(list_contents.isEmpty());

                    try parameters.append(alloca.allocator(), param);
                },
                .keyword_result => {
                    if (!state.advance(.results)) break :before_body;

                    const result = try Text.Result.parseContents(
                        &list_contents,
                        tree,
                        arena,
                        keyword,
                        field_list,
                        errors,
                    );

                    std.debug.assert(list_contents.isEmpty());

                    try results.append(alloca.allocator(), result);
                },
                .keyword_local => {
                    if (!state.advance(.locals)) break :before_body;

                    const local = try Text.Local.parseContents(
                        &list_contents,
                        tree,
                        arena,
                        caches,
                        keyword,
                        field_list,
                        errors,
                    );

                    std.debug.assert(list_contents.isEmpty());

                    try locals.append(alloca.allocator(), local);
                },
                else => break :before_body,
            }

            contents.* = lookahead;
            try list_contents.expectEmpty(errors);
        }
    }

    scratch = undefined;

    var func = Func{
        .id = id,
        .inline_exports = try arena.dupeSegmentedList(Text.Export, 1, &inline_exports),
        .inline_import = inline_import.keyword,
        .parameters = try arena.dupeSegmentedList(Text.Param, 4, &parameters),
        .results = try arena.dupeSegmentedList(Text.Result, 1, &results),
        .locals = try arena.dupeSegmentedList(Text.Local, 4, &locals),
        .body = undefined,
    };

    func.body = if (inline_import.keyword.some) inline_import: {
        try contents.expectEmpty(errors);
        break :inline_import .{ .inline_import = inline_import.name };
    } else .{
        .defined = try Text.Expr.parseContents(
            contents,
            tree,
            parent,
            arena,
            caches,
            errors,
            alloca,
        ),
    };

    return .{ .ok = func };
}
