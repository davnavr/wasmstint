const std = @import("std");
const Allocator = std.mem.Allocator;
const sexpr = @import("sexpr.zig");
const Value = sexpr.Value;
const Token = sexpr.Token;

value: Value,
tag: Tag,
extra: union {
    unexpected_value: ExpectedLocation,
    expected_token: struct {
        tag: Token.Tag,
        location: ExpectedLocation,
    },
    integer_literal_overflow: struct { width: u8 },
},

pub const ExpectedLocation = enum {
    at_value,
    /// The `value` is a list, and a specific token was expected at its end.
    at_list_end,
};

pub const Tag = enum {
    unexpected_value,
    // missing_closing_quotation_mark,
    // missing_block_comment_end,
    missing_closing_parenthesis,
    expected_token,
    invalid_utf8,
    integer_literal_overflow,
};

const Error = @This();

comptime {
    std.debug.assert(@sizeOf(Error) == 12);
}

pub fn initUnexpectedValue(value: Value, location: ExpectedLocation) Error {
    return .{
        .value = value,
        .tag = .unexpected_value,
        .extra = .{ .unexpected_value = location },
    };
}

pub fn initInvalidUtf8(string: Value) Error {
    return .{
        .value = string,
        .tag = .invalid_utf8,
        .extra = undefined,
    };
}

pub fn initExpectedToken(value: Value, expected: Token.Tag, location: ExpectedLocation) Error {
    return .{
        .value = value,
        .tag = .expected_token,
        .extra = .{
            .expected_token = .{
                .tag = expected,
                .location = location,
            },
        },
    };
}

pub fn initIntegerLiteralOverflow(integer: sexpr.TokenId, width: u8) Error {
    std.debug.assert(width > 0);
    return .{
        .value = Value.initAtom(integer),
        .tag = .integer_literal_overflow,
        .extra = .{ .integer_literal_overflow = .{ .width = width } },
    };
}

pub const List = struct {
    list: std.SegmentedList(Error, 0),
    allocator: Allocator,

    pub fn init(allocator: Allocator) List {
        return .{ .list = .{}, .allocator = allocator };
    }

    pub fn append(errors: *List, err: Error) Allocator.Error!void {
        try errors.list.append(errors.allocator, err);
    }

    pub fn deinit(errors: List) void {
        errors.list.deinit(errors.allocator);
    }
};
