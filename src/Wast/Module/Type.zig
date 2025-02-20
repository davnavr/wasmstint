const std = @import("std");
const IndexedArena = @import("../../IndexedArena.zig");

const sexpr = @import("../sexpr.zig");
const ParseContext = sexpr.Parser.Context;

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
    parameters_count: u32,
    results_count: u32,

    pub const empty = Func{
        .parameters = .empty,
        .results = .empty,
        .parameters_count = 0,
        .results_count = 0,
    };
};

const Type = @This();

pub fn parseContents(
    contents: *sexpr.Parser,
    ctx: *ParseContext,
    parent: sexpr.List.Id,
    arena: *IndexedArena,
    caches: *Caches,
    temporary: *std.heap.ArenaAllocator,
) sexpr.Parser.ParseError!Type {
    const id = try Ident.Symbolic.parse(
        contents,
        ctx.tree,
        caches.allocator,
        &caches.ids,
    );

    const func_list = try contents.parseListInList(parent, ctx);

    try contents.expectEmpty(ctx);

    var func_contents = sexpr.Parser.init(func_list.contents(ctx.tree).values(ctx.tree));

    const func_keyword = try func_contents.parseAtomInList(func_list, ctx, "'func' keyword");

    if (func_keyword.tag(ctx.tree) != .keyword_func) {
        return (try ctx.errorAtToken(
            func_keyword,
            "expected 'func' keyword",
            @errorReturnTrace(),
        )).err;
    }

    _ = temporary.reset(.retain_capacity);
    var parameters = IndexedArena.Slice(Text.Param).empty;
    var parameters_count: u32 = 0;
    var params_buf = std.SegmentedList(Text.Param, 8){};
    var results_count: u32 = 0;
    var results_buf = std.SegmentedList(Text.Result, 1){};

    while (true) {
        const param_or_result = func_contents.parseList(ctx) catch |e| switch (e) {
            error.OutOfMemory => |oom| return oom,
            error.ReportedParserError, error.EndOfStream => break,
        };

        var param_or_result_contents = sexpr.Parser.init(param_or_result.contents(ctx.tree).values(ctx.tree));
        const param_or_result_keyword = param_or_result_contents.parseAtomInList(
            param_or_result,
            ctx,
            "'param' or 'result' keyword",
        ) catch |e| switch (e) {
            error.OutOfMemory => |oom| return oom,
            error.ReportedParserError => break,
        };

        const wrong_keyword_msg = "expected 'param' or 'result' keyword";
        switch (param_or_result_keyword.tag(ctx.tree)) {
            .keyword_param => {
                if (results_buf.len > 0) {
                    _ = try ctx.errorAtToken(
                        param_or_result_keyword,
                        wrong_keyword_msg,
                        @errorReturnTrace(),
                    );
                    break;
                }

                const param = try Text.Param.parseContents(
                    &param_or_result_contents,
                    ctx,
                    arena,
                    caches,
                    param_or_result_keyword,
                    func_list,
                );

                std.debug.assert(parameters.len == 0);

                parameters_count = std.math.add(u32, parameters_count, param.types.len) catch
                    return error.OutOfMemory;

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
                    ctx,
                    arena,
                    param_or_result_keyword,
                    func_list,
                );

                results_count = std.math.add(u32, results_count, result.types.len) catch
                    return error.OutOfMemory;

                try results_buf.append(temporary.allocator(), result);
            },
            else => {
                _ = try ctx.errorAtToken(
                    param_or_result_keyword,
                    wrong_keyword_msg,
                    @errorReturnTrace(),
                );
                break;
            },
        }
    }

    if (params_buf.len > 0) {
        parameters = try arena.dupeSegmentedList(Text.Param, 8, &params_buf);
    }

    return Type{
        .id = id,
        .keyword = func_keyword,
        .func = Func{
            .parameters = parameters,
            .results = try arena.dupeSegmentedList(Text.Result, 1, &results_buf),
            .parameters_count = parameters_count,
            .results_count = results_count,
        },
    };
}
