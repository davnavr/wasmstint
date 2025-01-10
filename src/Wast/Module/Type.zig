const std = @import("std");
const IndexedArena = @import("../../IndexedArena.zig");

const sexpr = @import("../sexpr.zig");
const Error = sexpr.Error;

const Ident = @import("../ident.zig").Ident;
const Caches = @import("../Caches.zig");

const Text = @import("Text.zig");

id: Ident.Symbolic align(4),
/// The `func` keyword.
keyword: sexpr.TokenId,
// type: union { func: FuncType },
func: Func,

pub const Func = struct {
    parameters: IndexedArena.Slice(Text.Param),
    results: IndexedArena.Slice(Text.Result),
};

const Type = @This();

pub fn parseContents(
    contents: *sexpr.Parser,
    tree: *const sexpr.Tree,
    parent: sexpr.List.Id,
    arena: *IndexedArena,
    caches: *Caches,
    errors: *Error.List,
    temporary: *std.heap.ArenaAllocator,
) error{OutOfMemory}!sexpr.Parser.Result(Type) {
    const id = try Ident.Symbolic.parse(contents, tree, caches.allocator, &caches.ids);

    const func_list: sexpr.List.Id = switch (contents.parseListInList(parent)) {
        .ok => |ok| ok,
        .err => |err| return .{ .err = err },
    };

    try contents.expectEmpty(errors);

    var func_contents = sexpr.Parser.init(func_list.contents(tree).values(tree));

    const func_keyword: sexpr.TokenId = switch (func_contents.parseAtomInList(.keyword_func, func_list)) {
        .ok => |ok| ok,
        .err => |err| return .{ .err = err },
    };

    if (func_keyword.tag(tree) != .keyword_func) return .{
        .err = Error.initExpectedToken(sexpr.Value.initAtom(func_keyword), .keyword_func, .at_value),
    };

    _ = temporary.reset(.retain_capacity);
    var parameters = IndexedArena.Slice(Text.Param).empty;
    var params_buf = std.SegmentedList(Text.Param, 8){};
    var results_buf = std.SegmentedList(Text.Result, 1){};

    while (@as(?sexpr.Parser.Result(sexpr.List.Id), func_contents.parseList() catch null)) |parsed_param_or_result| {
        const param_or_result_list: sexpr.List.Id = switch (parsed_param_or_result) {
            .ok => |ok| ok,
            .err => |err| {
                try errors.append(err);
                break;
            },
        };

        var param_or_result_contents = sexpr.Parser.init(param_or_result_list.contents(tree).values(tree));
        const param_or_result_keyword = switch (param_or_result_contents.parseAtomInList(null, param_or_result_list)) {
            .ok => |ok| ok,
            .err => |err| {
                try errors.append(err);
                break;
            },
        };

        const wrong_keyword = Error.initUnexpectedValue(sexpr.Value.initAtom(param_or_result_keyword), .at_value);
        switch (param_or_result_keyword.tag(tree)) {
            .keyword_param => {
                if (results_buf.len > 0) {
                    try errors.append(wrong_keyword);
                    break;
                }

                const param = try Text.Param.parseContents(
                    &param_or_result_contents,
                    tree,
                    arena,
                    caches,
                    param_or_result_keyword,
                    func_list,
                    errors,
                );

                std.debug.assert(parameters.len == 0);
                try params_buf.append(temporary.allocator(), param);
            },
            .keyword_result => {
                if (params_buf.len > 0) {
                    parameters = try arena.dupeSegmentedList(Text.Param, 8, &params_buf);
                    params_buf.clearRetainingCapacity();
                    _ = temporary.reset(.retain_capacity);
                }

                const result = try Text.Result.parseContents(
                    &param_or_result_contents,
                    tree,
                    arena,
                    param_or_result_keyword,
                    func_list,
                    errors,
                );

                try results_buf.append(temporary.allocator(), result);
            },
            else => {
                try errors.append(wrong_keyword);
                break;
            },
        }
    }

    if (params_buf.len > 0) {
        parameters = try arena.dupeSegmentedList(Text.Param, 8, &params_buf);
    }

    const func = Func{
        .parameters = parameters,
        .results = try arena.dupeSegmentedList(Text.Result, 1, &results_buf),
    };

    return .{ .ok = Type{ .id = id, .keyword = func_keyword, .func = func } };
}
