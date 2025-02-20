const std = @import("std");
const AllocatorError = std.mem.Allocator.Error;
const sexpr = @import("../sexpr.zig");
const Value = sexpr.Value;
const Token = sexpr.Token;
const TokenId = sexpr.TokenId;
const List = sexpr.List;
const Tree = sexpr.Tree;

const parse_value = @import("../value.zig");
const floating_point = @import("../../float.zig");
const Errors = @import("../Errors.zig");
const LineCol = @import("../LineCol.zig");

remaining: []const Value,

const Parser = @This();

pub fn init(values: []const Value) Parser {
    return .{ .remaining = values };
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

pub const ParseError = Errors.ReportedError || AllocatorError;
pub const ParseOrEofError = error{EndOfStream} || ParseError;

pub const Context = struct {
    tree: *const sexpr.Tree,
    locator: LineCol.FromOffset = .init,
    errors: *Errors,

    pub fn errorAtToken(
        ctx: *Context,
        token: sexpr.TokenId,
        msg: []const u8,
        stack_trace: ?*const std.builtin.StackTrace,
    ) AllocatorError!Errors.Report {
        return ctx.errors.reportAtToken(
            token,
            ctx.tree,
            &ctx.locator,
            msg,
            stack_trace,
        );
    }

    pub fn errorAtList(
        ctx: *Context,
        list: sexpr.List.Id,
        position: Errors.ListParenthesis,
        msg: []const u8,
        stack_trace: ?*const std.builtin.StackTrace,
    ) AllocatorError!Errors.Report {
        return ctx.errors.reportAtList(
            list,
            position,
            ctx.tree,
            &ctx.locator,
            msg,
            stack_trace,
        );
    }

    pub fn errorFmtAtToken(
        ctx: *Context,
        token: sexpr.TokenId,
        comptime fmt: []const u8,
        args: anytype,
        stack_trace: ?*const std.builtin.StackTrace,
    ) AllocatorError!Errors.Report {
        return ctx.errors.reportFmtAtToken(
            token,
            ctx.tree,
            &ctx.locator,
            fmt,
            args,
            stack_trace,
        );
    }

    pub fn errorFmtAtList(
        ctx: *Context,
        list: sexpr.List.Id,
        position: Errors.ListParenthesis,
        comptime fmt: []const u8,
        args: anytype,
        stack_trace: ?*const std.builtin.StackTrace,
    ) AllocatorError!Errors.Report {
        return ctx.errors.reportFmtAtList(
            list,
            position,
            ctx.tree,
            &ctx.locator,
            fmt,
            args,
            stack_trace,
        );
    }

    pub fn errorUnexpectedToken(
        ctx: *Context,
        token: sexpr.TokenId,
        stack_trace: ?*const std.builtin.StackTrace,
    ) AllocatorError!Errors.Report {
        return ctx.errors.reportUnexpectedToken(
            token,
            ctx.tree,
            &ctx.locator,
            stack_trace,
        );
    }
};

pub fn parseAtom(
    parser: *Parser,
    ctx: *Context,
    expected: []const u8,
) ParseOrEofError!TokenId {
    const value = try parser.parseValue();
    return if (value.getAtom()) |atom|
        atom
    else
        (try ctx.errorFmtAtList(
            value.getList().?,
            .start,
            "expected {s}",
            .{expected},
            @errorReturnTrace(),
        )).err;
}

pub fn parseList(parser: *Parser, ctx: *Context) ParseOrEofError!List.Id {
    const value = try parser.parseValue();
    return if (value.getList()) |list|
        list
    else
        (try ctx.errorAtToken(
            value.getAtom().?,
            "expected opening parenthesis",
            @errorReturnTrace(),
        )).err;
}

pub fn parseAtomInList(parser: *Parser, list: List.Id, ctx: *Context, expected: []const u8) ParseError!TokenId {
    return parser.parseAtom(ctx, expected) catch |e| switch (e) {
        error.EndOfStream => (try ctx.errorFmtAtList(
            list,
            .end,
            "expected {s}, but got closing parenthesis",
            .{expected},
            @errorReturnTrace(),
        )).err,
        else => |err| err,
    };
}

pub fn parseListInList(parser: *Parser, list: List.Id, ctx: *Context) ParseError!List.Id {
    return parser.parseList(ctx) catch |e| switch (e) {
        error.EndOfStream => (try ctx.errorAtList(
            list,
            .end,
            "expected opening parenthesis, but got closing parenthesis",
            @errorReturnTrace(),
        )).err,
        else => |err| err,
    };
}

fn ParsedToken(comptime T: type) type {
    return struct { token: TokenId, value: T };
}

pub fn parseUninterpretedInteger(
    parser: *Parser,
    comptime T: type,
    ctx: *Context,
) ParseOrEofError!ParsedToken(T) {
    const atom = try parser.parseAtom(ctx, @typeName(T) ++ " literal");
    return if (atom.tag(ctx.tree) == .integer)
        .{
            .token = atom,
            .value = parse_value.uninterpretedInteger(T, atom.contents(ctx.tree)) catch |e| switch (e) {
                error.Overflow => return (try ctx.errorAtToken(
                    atom,
                    "value cannot fit into an " ++ @typeName(T) ++ " literal",
                    @errorReturnTrace(),
                )).err,
            },
        }
    else
        (try ctx.errorAtToken(
            atom,
            "expected " ++ @typeName(T) ++ " literal",
            @errorReturnTrace(),
        )).err;
}

pub fn parseUninterpretedIntegerInList(
    parser: *Parser,
    comptime T: type,
    list: List.Id,
    ctx: *Context,
) ParseError!ParsedToken(T) {
    return parser.parseUninterpretedInteger(T, ctx) catch |e| switch (e) {
        error.EndOfStream => (try ctx.errorAtList(
            list,
            .end,
            "expected " ++ @typeName(T) ++ " literal, but got closing parenthesis",
            @errorReturnTrace(),
        )).err,
        else => |err| err,
    };
}

pub fn ParsedFloat(comptime F: type) type {
    return struct {
        token: TokenId,
        bits_or_undefined: floating_point.Bits(F),

        pub const Value = union(enum) {
            nan_canonical,
            nan_arithmetic,
            bits: floating_point.Bits(F),
        };

        const Float = @This();

        pub fn value(float: Float, tree: *const sexpr.Tree) Float.Value {
            return switch (float.token.tag(tree)) {
                .@"keyword_nan:canonical" => .nan_canonical,
                .@"keyword_nan:arithmetic" => .nan_arithmetic,
                else => return .{ .bits = float.bits_or_undefined },
            };
        }

        pub fn expectBits(float: Float, ctx: *Context) ParseError!floating_point.Bits(F) {
            return switch (float.value(ctx.tree)) {
                .bits => |bits| bits,
                .nan_arithmetic, .nan_canonical => (try ctx.errorAtToken(
                    float.token,
                    "invalid " ++ @typeName(F) ++ " literal",
                    @errorReturnTrace(),
                )).err,
            };
        }
    };
}

pub fn parseFloat(
    parser: *Parser,
    comptime F: type,
    ctx: *Context,
) ParseOrEofError!ParsedFloat(F) {
    const atom = try parser.parseAtom(ctx, @typeName(F) ++ " literal");
    const contents = atom.contents(ctx.tree);
    switch (atom.tag(ctx.tree)) {
        .@"keyword_nan:canonical", .@"keyword_nan:arithmetic" => return .{
            .token = atom,
            .bits_or_undefined = undefined,
        },
        .integer,
        .float,
        .keyword_inf,
        .keyword_nan,
        => {},
        else => |tag| {
            if (tag != .keyword_unknown or !std.mem.startsWith(u8, contents, "nan:0x")) {
                return (try ctx.errorAtToken(
                    atom,
                    "expected " ++ @typeName(F) ++ " literal",
                    @errorReturnTrace(),
                )).err;
            }

            const digits = contents[6..];
            const invalid =
                digits.len == 0 or digits[0] == '_' or
                digits[digits.len - 1] == '_' or
                std.mem.indexOfNone(u8, digits, "0123456789_abcdefABCDEF") != null;

            if (invalid)
                return (try ctx.errorAtToken(
                    atom,
                    "invalid " ++ @typeName(F) ++ " literal",
                    @errorReturnTrace(),
                )).err;
        },
    }

    const f = parse_value.float(F, contents) catch |e| switch (e) {
        error.InvalidNanPayload => return (try ctx.errorAtToken(
            atom,
            "invalid NaN literal payload in " ++ @typeName(F) ++ " literal",
            @errorReturnTrace(),
        )).err,
    };

    return .{ .token = atom, .bits_or_undefined = @bitCast(f) };
}

pub fn parseFloatInList(
    parser: *Parser,
    comptime F: type,
    list: List.Id,
    ctx: *Context,
) ParseError!ParsedFloat(F) {
    return parser.parseFloat(F, ctx) catch |e| switch (e) {
        error.EndOfStream => (try ctx.errorAtList(
            list,
            .end,
            "expected " ++ @typeName(F) ++ " literal, but got closing parenthesis",
            @errorReturnTrace(),
        )).err,
        else => |err| err,
    };
}

// pub fn parseListWithAtom

/// Moves the parser to the end of the list of `Value`s.
pub fn empty(parser: *Parser) []const Value {
    const remainder = parser.remaining;
    parser.remaining = remainder[remainder.len..];
    return remainder;
}

/// Appends an `Error` if there are remaining `Value`s that have not been parsed.
pub fn expectEmpty(parser: *Parser, ctx: *Context) error{OutOfMemory}!void {
    if (@as(?Value, parser.parseValue() catch null)) |value| {
        _ = switch (value.unpacked()) {
            .atom => |token| try ctx.errorUnexpectedToken(
                token,
                @errorReturnTrace(),
            ),
            .list => |list| try ctx.errorAtList(
                list,
                .start,
                "unexpected opening parenthesis",
                @errorReturnTrace(),
            ),
        };
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
