//! A WebAssembly [*type use*], referring to a type by its index or defining one inline.
//!
//! [*type use*]: https://webassembly.github.io/spec/core/text/modules.html#text-typeuse

const std = @import("std");
const IndexedArena = @import("../../IndexedArena.zig");

const sexpr = @import("../sexpr.zig");
const Error = sexpr.Error;
const Ident = @import("../ident.zig").Ident;
const Text = @import("Text.zig");

pub const Id = struct {
    header: packed struct(u32) {
        /// If `true`, `inner.results.len <= 1`, and the *type use* is used as a *`blocktype`*, then
        /// the block type is the special case of a `void` result or a single result.
        is_inline: bool,
        /// Only set when `is_inline == false`.
        keyword: sexpr.TokenId,
    },
    /// Only set when `is_inline == false`.
    type: Ident align(4),

    pub const @"inline" = Id{
        .header = .{
            .is_inline = true,
            .keyword = undefined,
        },
        .type = undefined,
    };
};

id: Id align(4),
parameters: IndexedArena.Slice(Text.Param),
results: IndexedArena.Slice(Text.Result),

const TypeUse = @This();

comptime {
    std.debug.assert(@alignOf(TypeUse) == @alignOf(u32));
    std.debug.assert(@sizeOf(Id) == 12);
}

const empty = TypeUse{
    .id = .@"inline",
    .parameters = .empty,
    .results = .empty,
};

pub fn parseContents(
    contents: *sexpr.Parser,
    tree: *const sexpr.Tree,
    arena: *IndexedArena,
    caches: *@import("../Caches.zig"),
    errors: *Error.List,
    temporary: *std.heap.ArenaAllocator,
) error{OutOfMemory}!sexpr.Parser.Result(TypeUse) {
    var type_use = empty;

    // Allocated in `temporary`.
    _ = temporary.reset(.retain_capacity);
    var param_buf = std.SegmentedList(Text.Param, 4){};
    var result_buf = std.SegmentedList(Text.Result, 1){};
    var lookahead = contents.*;
    while (@as(?sexpr.Value, lookahead.parseValue() catch null)) |value| {
        const list: sexpr.List.Id = value.getList() orelse break;
        var list_contents = sexpr.Parser.init(list.contents(tree).values(tree));
        const keyword = (list_contents.parseValue() catch break).getAtom() orelse break;
        switch (keyword.tag(tree)) {
            .keyword_type => {
                if (param_buf.len > 0 or result_buf.len > 0 or !type_use.id.header.is_inline) return .{
                    .err = Error.initUnexpectedValue(sexpr.Value.initAtom(keyword), .at_value),
                };

                std.debug.assert(type_use.parameters.isEmpty());

                const id_result = try Ident.parse(
                    &list_contents,
                    tree,
                    list,
                    caches.allocator,
                    &caches.ids,
                );

                const id = switch (id_result) {
                    .ok => |ok| ok,
                    .err => |err| return .{ .err = err },
                };

                type_use.id = Id{
                    .header = .{
                        .is_inline = false,
                        .keyword = keyword,
                    },
                    .type = id,
                };
            },
            .keyword_param => {
                if (result_buf.len > 0) return .{
                    .err = Error.initExpectedToken(sexpr.Value.initAtom(keyword), .keyword_result, .at_value),
                };

                try param_buf.append(
                    temporary.allocator(),
                    try Text.Param.parseContents(
                        &list_contents,
                        tree,
                        arena,
                        caches,
                        keyword,
                        list,
                        errors,
                    ),
                );
            },
            .keyword_result => {
                if (param_buf.len > 0) {
                    std.debug.assert(result_buf.len == 0);

                    // Reuse space in the arena since all parameters have been parsed
                    type_use.parameters = try arena.dupeSegmentedList(Text.Param, 4, &param_buf);
                    param_buf.clearRetainingCapacity();
                    _ = temporary.reset(.retain_capacity);
                }

                try result_buf.append(
                    temporary.allocator(),
                    try Text.Result.parseContents(
                        &list_contents,
                        tree,
                        arena,
                        keyword,
                        list,
                        errors,
                    ),
                );
            },
            else => break,
        }

        contents.* = lookahead;
        std.debug.assert(list_contents.isEmpty());
    }

    if (param_buf.len > 0) {
        // Duplicate code from the `.keyword_result` case.
        std.debug.assert(result_buf.len == 0);
        type_use.parameters = try arena.dupeSegmentedList(Text.Param, 4, &param_buf);
    }

    type_use.results = try arena.dupeSegmentedList(Text.Result, 1, &result_buf);
    return .{ .ok = type_use };
}
