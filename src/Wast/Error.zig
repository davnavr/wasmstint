const std = @import("std");
const Allocator = std.mem.Allocator;
const sexpr = @import("sexpr.zig");
const Value = sexpr.Value;
const Token = sexpr.Token;
const LineCol = @import("LineCol.zig");

value: Value,
tag: Tag,
extra: union {
    unexpected_value: ExpectedLocation,
    expected_token: struct {
        tag: Token.Tag,
        location: ExpectedLocation,
    },
    integer_literal_overflow: struct { width: u16 },
},

pub const ExpectedLocation = enum {
    at_value,
    /// The `value` is a list, and a specific token was expected at its end.
    at_list_end,

    fn print(loc: ExpectedLocation, writer: anytype) !void {
        switch (loc) {
            .at_value => {},
            .at_list_end => {
                _ = try writer.write(" at end of containing list");
            },
        }
    }
};

pub const Tag = enum {
    unexpected_value,
    expected_token,
    invalid_utf8,
    integer_literal_overflow,
    invalid_nan_payload,
    // missing_closing_quotation_mark,
    // missing_block_comment_end,
    // missing_closing_parenthesis,
    missing_folded_then,
};

const Error = @This();

pub fn offset(err: *const Error, tree: *const sexpr.Tree) *const sexpr.Offset {
    return switch (err.value.tag) {
        .atom => err.value.case.atom.offset(tree),
        .list => err.value.case.list.parenthesis(tree),
    };
}

pub fn print(err: *const Error, tree: *const sexpr.Tree, writer: anytype) !void {
    switch (err.tag) {
        .unexpected_value => {
            _ = try writer.write("unexpected ");
            switch (err.value.tag) {
                .list => {
                    _ = try writer.write("list");
                },
                .atom => {
                    try writer.print("token {s}", .{@tagName(err.value.case.atom.tag(tree))});
                },
            }

            try err.extra.unexpected_value.print(writer);
        },
        .expected_token => {
            const expected_token = err.extra.expected_token;
            try writer.print("expected token {}, but got ", .{expected_token.tag});
            switch (err.value.tag) {
                .list => {
                    _ = try writer.write("list");
                },
                .atom => {
                    try writer.print("token {s}", .{@tagName(err.value.case.atom.tag(tree))});
                },
            }

            try err.extra.expected_token.location.print(writer);
        },
        .invalid_utf8 => {
            _ = try writer.write("name string literal must be valid UTF-8");
        },
        .integer_literal_overflow => {
            _ = try writer.print("not a valid literal for {}-bit integers", .{err.extra.integer_literal_overflow.width});
        },
        .invalid_nan_payload => {
            _ = try writer.write("invalid NaN literal payload");
        },
        .missing_folded_then => {
            _ = try writer.write("missing then branch in folded if instruction");
        },
    }
}

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

pub fn initInvalidUtf8(string: sexpr.TokenId) Error {
    return .{
        .value = Value.initAtom(string),
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

pub fn initIntegerLiteralOverflow(integer: sexpr.TokenId, width: u16) Error {
    std.debug.assert(width > 0);
    return .{
        .value = Value.initAtom(integer),
        .tag = .integer_literal_overflow,
        .extra = .{ .integer_literal_overflow = .{ .width = width } },
    };
}

pub fn initInvalidNanPayload(float: sexpr.TokenId) Error {
    return .{
        .value = Value.initAtom(float),
        .tag = .invalid_nan_payload,
        .extra = undefined,
    };
}

pub fn initMissingFoldedThen(if_instr: sexpr.List.Id) Error {
    return .{
        .value = Value.initList(if_instr),
        .tag = .missing_folded_then,
        .extra = undefined,
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
