const std = @import("std");
const sexpr = @import("../sexpr.zig");
const Value = sexpr.Value;
const Error = sexpr.Error;
const Token = sexpr.Token;
const TokenId = sexpr.TokenId;
const List = sexpr.List;
const Tree = sexpr.Tree;
const parse_value = @import("../value.zig");
const floating_point = @import("../../float.zig");

remaining: []const Value,

const Parser = @This();

pub fn init(values: []const Value) Parser {
    return .{ .remaining = values };
}

pub fn Result(comptime T: type) type {
    return union(enum) { ok: T, err: Error };
}

pub inline fn isEmpty(parser: *const Parser) bool {
    return parser.remaining.len == 0;
}

pub fn parseValue(parser: *Parser) error{EndOfStream}!Value {
    if (parser.isEmpty()) return error.EndOfStream;

    const value = parser.remaining[0];
    parser.remaining = parser.remaining[1..];
    return value;
}

pub fn parseAtom(parser: *Parser, expected: ?Token.Tag) error{EndOfStream}!Result(TokenId) {
    const value = try parser.parseValue();
    return if (value.getAtom()) |atom|
        .{ .ok = atom }
    else
        .{
            .err = if (expected) |expected_tag|
                Error.initExpectedToken(value, expected_tag, .at_value)
            else
                Error.initUnexpectedValue(value, .at_value),
        };
}

pub fn parseList(parser: *Parser) error{EndOfStream}!Result(List.Id) {
    const value = try parser.parseValue();
    return if (value.getList()) |list|
        .{ .ok = list }
    else
        .{ .err = Error.initUnexpectedValue(value, .at_value) };
}

pub fn parseAtomInList(parser: *Parser, expected: ?Token.Tag, list: List.Id) Result(TokenId) {
    return parser.parseAtom(expected) catch |e| switch (e) {
        error.EndOfStream => err: {
            const list_value = Value.initList(list);
            break :err .{
                .err = if (expected) |expected_tag|
                    Error.initExpectedToken(list_value, expected_tag, .at_list_end)
                else
                    Error.initUnexpectedValue(list_value, .at_list_end),
            };
        },
    };
}

pub fn parseListInList(parser: *Parser, list: List.Id) Result(List.Id) {
    return parser.parseList() catch |e| switch (e) {
        error.EndOfStream => .{ .err = Error.initUnexpectedValue(Value.initList(list), .at_list_end) },
    };
}

fn ParsedToken(comptime T: type) type {
    return struct { token: TokenId, value: T };
}

pub fn parseUninterpretedInteger(
    parser: *Parser,
    comptime T: type,
    tree: *const Tree,
) error{EndOfStream}!Result(ParsedToken(T)) {
    const atom: TokenId = switch (try parser.parseAtom(.integer)) {
        .ok => |ok| ok,
        .err => |err| return .{ .err = err },
    };

    return switch (atom.tag(tree)) {
        .integer => .{
            .ok = .{
                .token = atom,
                .value = parse_value.uninterpretedInteger(T, atom.contents(tree)) catch |e| switch (e) {
                    error.Overflow => return .{ .err = Error.initIntegerLiteralOverflow(atom, @typeInfo(T).int.bits) },
                },
            },
        },
        else => .{ .err = Error.initExpectedToken(Value.initAtom(atom), .integer, .at_value) },
    };
}

pub fn parseUninterpretedIntegerInList(
    parser: *Parser,
    comptime T: type,
    list: List.Id,
    tree: *const Tree,
) Result(ParsedToken(T)) {
    return parser.parseUninterpretedInteger(T, tree) catch |e| switch (e) {
        error.EndOfStream => .{ .err = Error.initExpectedToken(Value.initList(list), .integer, .at_list_end) },
    };
}

pub fn parseFloat(
    parser: *Parser,
    comptime F: type,
    tree: *const Tree,
) error{EndOfStream}!Result(ParsedToken(floating_point.Bits(F))) {
    const atom: TokenId = switch (try parser.parseAtom(.integer)) {
        .ok => |ok| ok,
        .err => |err| return .{ .err = err },
    };

    const contents = atom.contents(tree);
    switch (atom.tag(tree)) {
        .integer,
        .float,
        .keyword_inf,
        .keyword_nan,
        .@"keyword_nan:canonical",
        .@"keyword_nan:arithmetic",
        => {},
        else => |tag| {
            const err = Result(ParsedToken(floating_point.Bits(F))){
                .err = Error.initExpectedToken(
                    Value.initAtom(atom),
                    .integer,
                    .at_value,
                ),
            };

            if (tag == .keyword_unknown and std.mem.startsWith(u8, contents, "nan:0x")) {
                const digits = contents[6..];

                if (digits.len == 0 or digits[0] == '_' or digits[digits.len - 1] == '_')
                    return err;

                if (std.mem.indexOfNone(u8, digits, "0123456789_abcdefABCDEF")) |_|
                    return err;
            } else {
                return err;
            }
        },
    }

    const f = parse_value.float(F, contents) catch |e| switch (e) {
        error.InvalidNanPayload => return .{ .err = Error.initInvalidNanPayload(atom) },
    };

    return .{ .ok = .{ .token = atom, .value = @bitCast(f) } };
}

pub fn parseFloatInList(
    parser: *Parser,
    comptime F: type,
    list: List.Id,
    tree: *const Tree,
) Result(ParsedToken(floating_point.Bits(F))) {
    return parser.parseFloat(F, tree) catch |e| switch (e) {
        error.EndOfStream => .{ .err = Error.initExpectedToken(Value.initList(list), .float, .at_list_end) },
    };
}

// pub fn parseListWithAtom

/// Moves the parser to the end of the list of `Value`s.
pub fn empty(parser: *Parser) []const Value {
    const remainder = parser.remaining;
    parser.remaining = remainder[remainder.len..];
    return remainder;
}

/// Appends an `Error` for every remaining `Value` that has not yet been parsed.
pub fn expectEmpty(parser: *Parser, errors: *Error.List) error{OutOfMemory}!void {
    for (parser.remaining) |value| {
        try errors.append(Error.initUnexpectedValue(value, .at_value));
    }

    _ = parser.empty();
}

pub fn dumpRemainingToStderr(parser: *const Parser, tree: *const Tree, title: [:0]const u8) void {
    std.debug.print("BEGIN DUMP {s}\n", .{title});
    for (parser.remaining) |value| {
        switch (value.unpacked()) {
            .atom => |atom| std.debug.print("  {}\n", .{atom.tag(tree)}),
            .list => |list| std.debug.print("  ({} values)\n", .{list.contents(tree).count}),
        }
    }
    std.debug.print("END DUMP\n", .{});
}
