const std = @import("std");
const Allocator = std.mem.Allocator;
const LineCol = @import("LineCol.zig");
const sexpr = @import("sexpr.zig");

pub const Message = struct {
    loc: LineCol,
    msg: []const u8,
    src: Src,

    pub const Src = struct {
        line: []const u8,
        start: u32,
        end: u32,

        pub fn init(tree: *const sexpr.Tree, offset: *const sexpr.Offset) Src {
            std.debug.assert(offset.start <= offset.end);
            const newlines: []const u8 = "\r\n";

            const line_start = if (std.mem.lastIndexOfAny(u8, tree.source[0..offset.start], newlines)) |i| start: {
                break :start @min(offset.start, i + 1);
            } else 0;

            const line_end = if (std.mem.indexOfAny(u8, tree.source[offset.end..], newlines)) |i| end: {
                break :end offset.end + i;
            } else tree.source.len;

            std.debug.assert(line_start <= offset.start);
            std.debug.assert(offset.end <= line_end);

            return Src{
                .line = tree.source[line_start..line_end],
                .end = std.math.cast(u32, offset.end - line_start) orelse std.math.maxInt(u32),
                .start = std.math.cast(u32, offset.start - line_start) orelse std.math.maxInt(u32),
            };
        }

        pub fn print(src: *const Src, writer: anytype) !void {
            // This naively assumes ASCII input, and does not calculate the visual width of code-points/grapheme clusters
            try writer.print("\n{s}", .{src.line});
            try writer.writeByte('\n');
            if (src.start < src.end) {
                try writer.writeByteNTimes(' ', src.start);
                try writer.writeByteNTimes('^', src.end - src.start);
                try writer.writeByte('\n');
            }
        }
    };
};

list: std.SegmentedList(Message, 0),
arena: std.heap.ArenaAllocator,

const Errors = @This();

pub fn init(gpa: Allocator) Errors {
    return Errors{
        .list = .{},
        .arena = std.heap.ArenaAllocator.init(gpa),
    };
}

pub fn reset(errors: *Errors) void {
    const saved_len = errors.list.len;
    errors.list = undefined;
    _ = errors.arena.reset(.retain_capacity);
    errors.list = .{};
    errors.list.setCapacity(errors.arena.allocator(), saved_len) catch unreachable;
}

pub fn deinit(errors: *Errors) void {
    errors.arena.deinit();
    errors.* = undefined;
}

pub const ReportedError = error{ReportedParserError};

pub const Report = struct {
    err: ReportedError,
    do_not_initialize_outside_of_report_function: void,
};

// Want to return `Allocator.Error!error{ReportedParserError}`; the `Report` struct is a workaround for this.
// See https://github.com/ziglang/zig/issues/14698

pub fn report(errors: *Errors, loc: LineCol, msg: []const u8, src: Message.Src) Allocator.Error!Report {
    std.debug.assert(std.unicode.utf8ValidateSlice(msg));
    std.debug.assert(std.unicode.utf8ValidateSlice(src.line));

    try errors.list.append(
        errors.arena.allocator(),
        Message{ .loc = loc, .msg = msg, .src = src },
    );

    return .{
        .err = error.ReportedParserError,
        .do_not_initialize_outside_of_report_function = {},
    };
}

pub fn reportFmt(
    errors: *Errors,
    loc: LineCol,
    comptime fmt: []const u8,
    args: anytype,
    src: Message.Src,
) Allocator.Error!Report {
    return errors.report(
        loc,
        try std.fmt.allocPrint(errors.arena.allocator(), fmt, args),
        src,
    );
}

pub fn reportAtOffset(
    errors: *Errors,
    offset: *const sexpr.Offset,
    tree: *const sexpr.Tree,
    locator: *LineCol.FromOffset,
    msg: []const u8,
) Allocator.Error!Report {
    return errors.report(
        locator.locate(tree.source, offset.start),
        msg,
        Message.Src.init(tree, offset),
    );
}

pub fn reportAtToken(
    errors: *Errors,
    token: sexpr.TokenId,
    tree: *const sexpr.Tree,
    locator: *LineCol.FromOffset,
    msg: []const u8,
) Allocator.Error!Report {
    return errors.reportAtOffset(token.offset(tree), tree, locator, msg);
}

pub const ListParenthesis = enum {
    start,
    end,

    pub fn offset(position: ListParenthesis, list: sexpr.List.Id, tree: *const sexpr.Tree) sexpr.Offset {
        const offsets = list.parenthesis(tree);
        return switch (position) {
            .start => .{ .start = offsets.start, .end = offsets.start +| 1 },
            .end => .{ .start = offsets.end -| 1, .end = offsets.end },
        };
    }
};

pub fn reportAtList(
    errors: *Errors,
    list: sexpr.List.Id,
    position: ListParenthesis,
    tree: *const sexpr.Tree,
    locator: *LineCol.FromOffset,
    msg: []const u8,
) Allocator.Error!Report {
    const offset = position.offset(list, tree);
    return errors.reportAtOffset(&offset, tree, locator, msg);
}

pub fn reportFmtAtOffset(
    errors: *Errors,
    offset: *const sexpr.Offset,
    tree: *const sexpr.Tree,
    locator: *LineCol.FromOffset,
    comptime fmt: []const u8,
    args: anytype,
) Allocator.Error!Report {
    return errors.reportFmt(
        locator.locate(tree.source, offset.start),
        fmt,
        args,
        Message.Src.init(tree, offset),
    );
}

pub fn reportFmtAtToken(
    errors: *Errors,
    token: sexpr.TokenId,
    tree: *const sexpr.Tree,
    locator: *LineCol.FromOffset,
    comptime fmt: []const u8,
    args: anytype,
) Allocator.Error!Report {
    return errors.reportFmtAtOffset(
        token.offset(tree),
        tree,
        locator,
        fmt,
        args,
    );
}

pub fn reportFmtAtList(
    errors: *Errors,
    list: sexpr.List.Id,
    position: ListParenthesis,
    tree: *const sexpr.Tree,
    locator: *LineCol.FromOffset,
    comptime fmt: []const u8,
    args: anytype,
) Allocator.Error!Report {
    const offset = position.offset(list, tree);
    return errors.reportFmtAtOffset(&offset, tree, locator, fmt, args);
}

pub fn reportUnexpectedToken(
    errors: *Errors,
    token: sexpr.TokenId,
    tree: *const sexpr.Tree,
    locator: *LineCol.FromOffset,
) Allocator.Error!Report {
    return errors.reportAtToken(
        token,
        tree,
        locator,
        "unexpected token",
    );
}

pub fn reportExpectedListAtToken(
    errors: *Errors,
    token: sexpr.TokenId,
    tree: *const sexpr.Tree,
    locator: *LineCol.FromOffset,
) Allocator.Error!Report {
    return errors.reportAtToken(
        token,
        tree,
        locator,
        "expected closing parenthesis, but got token",
    );
}
