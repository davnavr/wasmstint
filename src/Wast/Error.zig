const std = @import("std");
const Allocator = std.mem.Allocator;
const LineCol = @import("LineCol.zig");
const sexpr = @import("sexpr.zig");
const Value = sexpr.Value;
const Token = sexpr.Token;
const Ident = @import("ident.zig").Ident;

// pub const Payload = union {
//     literal: []const u8,
//     uint: usize,
//     location: Value,
// };
// value: Value, payload: IndexedArena.Slice(Payload),

value: Value,
tag: Tag,
extra: union {
    unexpected_value: ExpectedLocation,
    expected_token: struct {
        tag: Token.Tag,
        location: ExpectedLocation,
    },
    integer_literal_overflow: struct { width: u16 },
    duplicate_ident: struct { original: sexpr.TokenId },
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
    mem_arg_align_non_power_of_two,

    duplicate_ident,
    undefined_ident,
    import_after_definition,
    type_use_mismatch,
    // label_mismatch
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
            try writer.writeAll("unexpected ");
            switch (err.value.tag) {
                .list => {
                    try writer.writeAll("list");
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
            try writer.writeAll("name string literal must be valid UTF-8");
        },
        .integer_literal_overflow => {
            try writer.print("not a valid literal for {}-bit integers", .{err.extra.integer_literal_overflow.width});
        },
        .invalid_nan_payload => {
            try writer.writeAll("invalid NaN literal payload");
        },
        .missing_folded_then => {
            try writer.writeAll("missing then branch in folded if instruction");
        },
        .mem_arg_align_non_power_of_two => {
            try writer.writeAll("alignment must be power-of-two");
        },

        .undefined_ident => {
            try writer.writeAll("undefined variable");
        },
        .duplicate_ident => {
            // const duplicate_ident = err.extra.duplicate_ident;
            try writer.writeAll("identifier defined twice");
        },
        .import_after_definition => try writer.writeAll("imports must occur before all non-import definitions"),
        .type_use_mismatch => try writer.writeAll("type use does not match its definition"),
    }
}

comptime {
    std.debug.assert(@sizeOf(Error) == switch (@import("builtin").mode) {
        .Debug, .ReleaseSafe => 16,
        .ReleaseFast, .ReleaseSmall => 12,
    });
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

pub fn initMemArgAlignNonPowerOfTwo(align_token: sexpr.TokenId) Error {
    return .{
        .value = Value.initAtom(align_token),
        .tag = .mem_arg_align_non_power_of_two,
        .extra = undefined,
    };
}

pub fn initUndefinedIdent(ident: sexpr.TokenId) Error {
    return .{
        .value = Value.initAtom(ident),
        .tag = .undefined_ident,
        .extra = undefined,
    };
}

pub fn initDuplicateIdent(id: Ident.Symbolic, original: sexpr.TokenId) Error {
    return .{
        .value = Value.initAtom(id.token),
        .tag = .duplicate_ident,
        .extra = .{ .duplicate_ident = .{ .original = original } },
    };
}

pub fn initImportAfterDefinition(import_keyword: sexpr.TokenId) Error {
    return .{
        .value = Value.initAtom(import_keyword),
        .tag = .import_after_definition,
        .extra = undefined,
    };
}

pub fn initTypeUseMismatch(id: Ident) Error {
    return .{
        .value = Value.initAtom(id.token),
        .tag = .type_use_mismatch,
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
