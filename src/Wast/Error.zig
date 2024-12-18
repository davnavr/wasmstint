const std = @import("std");
const Allocator = std.mem.Allocator;
const sexpr = @import("sexpr.zig");
const Value = sexpr.Value;
const Token = sexpr.Token;

value: Value,
tag: Tag,
extra: union {
    /// Set when `.tag == Tag.expected_token`.
    expected_token: Token.Tag,
} = undefined,

pub const Tag = enum {
    unexpected,
    // missing_closing_quotation_mark,
    // missing_block_comment_end,
    missing_closing_parenthesis,
    expected_token,
};

const Error = @This();

pub const List = struct {
    list: std.SegmentedList(Error, 0),
    allocator: Allocator,

    pub fn init(allocator: Allocator) List {
        return .{ .list = .{}, .allocator = allocator };
    }

    pub fn append(errors: *List, err: Error) Allocator.Error!void {
        try errors.list.append(errors.allocator, err);
    }

    pub fn appendUnexpected(errors: *List, value: Value) Allocator.Error!void {
        try errors.append(.{ .value = value, .tag = .unexpected });
    }

    pub fn deinit(errors: List) void {
        errors.list.deinit(errors.allocator);
    }
};
