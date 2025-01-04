const sexpr = @import("../sexpr.zig");
const Error = sexpr.Error;

/// The token containing the integer literal `min`.
min_token: sexpr.TokenId,
/// If `.none`, then a maximum was not specified.
max_token: sexpr.TokenId.Opt,
min: u64 align(4),
/// Must not be read if `max_token == .none`.
max: u64 align(4),

const Limits = @This();

pub fn parseContents(
    contents: *sexpr.Parser,
    tree: *const sexpr.Tree,
    parent: sexpr.List.Id,
    errors: *Error.List,
) error{OutOfMemory}!sexpr.Parser.Result(Limits) {
    const min = switch (contents.parseUninterpretedIntegerInList(u64, parent, tree)) {
        .ok => |ok| ok,
        .err => |err| return .{ .err = err },
    };

    var limits = Limits{
        .min_token = min.token,
        .min = min.value,
        .max = undefined,
        .max_token = .none,
    };

    var lookahead: sexpr.Parser = contents.*;
    no_max: {
        const max_token = (lookahead.parseValue() catch break :no_max).getAtom() orelse break :no_max;
        if (max_token.tag(tree) != .integer) break :no_max;
        contents.* = lookahead;

        const max_value = @import("../value.zig").unsignedInteger(u64, max_token.contents(tree)) catch {
            try errors.append(Error.initIntegerLiteralOverflow(max_token, 64));
            break :no_max;
        };

        limits.max_token = sexpr.TokenId.Opt.init(max_token);
        limits.max = max_value;
    }

    return .{ .ok = limits };
}
