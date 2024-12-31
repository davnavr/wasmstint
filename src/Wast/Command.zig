const std = @import("std");
const ArenaAllocator = std.heap.ArenaAllocator;
const sexpr = @import("sexpr.zig");
const Arenas = @import("Arenas.zig");
const Caches = @import("Caches.zig");
const Ident = @import("Ident.zig");
const Name = @import("Name.zig");
const Wast = @import("../Wast.zig");
const InlineTaggedUnion = @import("../inline_tagged_union.zig").InlineTaggedUnion;
const Error = sexpr.Error;
const ParseResult = sexpr.Parser.Result;

keyword: sexpr.TokenId,
inner: Inner.Ptr(.@"const"),

pub fn parseConstOrResult(
    parser: *sexpr.Parser,
    comptime T: type,
    tree: *const sexpr.Tree,
    arena: *ArenaAllocator,
    errors: *Error.List,
) error{ OutOfMemory, EndOfStream }!ParseResult(T) {
    comptime std.debug.assert(@typeInfo(T.Value).@"union".tag_type != null);

    _ = arena; // Might be used for large v128 values.

    const list: sexpr.List.Id = switch (try parser.parseList()) {
        .ok => |ok| ok,
        .err => |err| return .{ .err = err },
    };

    var list_parser = sexpr.Parser.init(list.contents(tree).values(tree));

    const keyword: sexpr.TokenId = switch (list_parser.parseAtomInList(.keyword_unknown, list)) {
        .ok => |ok| ok,
        .err => |err| return .{ .err = err },
    };

    const parsed: struct { sexpr.TokenId, T.Value } = switch (keyword.tag(tree)) {
        .@"keyword_i32.const" => switch (list_parser.parseUninterpretedIntegerInList(i32, list, tree)) {
            .ok => |ok| .{ ok.token, T.Value{ .i32 = ok.value } },
            .err => |err| return .{ .err = err },
        },
        .@"keyword_i64.const" => switch (list_parser.parseUninterpretedIntegerInList(i64, list, tree)) {
            .ok => |ok| .{ ok.token, T.Value{ .i64 = ok.value } },
            .err => |err| return .{ .err = err },
        },
        .keyword_unknown => return .{
            .err = Error.initUnexpectedValue(sexpr.Value.initAtom(keyword), .at_value),
        },
        else => return .{
            .err = Error.initExpectedToken(sexpr.Value.initAtom(keyword), .keyword_unknown, .at_value),
        },
    };

    try list_parser.expectEmpty(errors);
    return .{
        .ok = T{
            .keyword = keyword,
            .value_token = parsed.@"0",
            .value = parsed.@"1",
        },
    };
}

pub fn parseConstOrResultList(
    contents: *sexpr.Parser,
    comptime T: type,
    tree: *const sexpr.Tree,
    arena: *ArenaAllocator,
    errors: *Error.List,
) error{OutOfMemory}!std.MultiArrayList(T) {
    var values = std.MultiArrayList(T).empty;
    const count = contents.remaining.len;
    try values.setCapacity(arena.allocator(), count);

    for (0..count) |_| {
        const val_result = parseConstOrResult(contents, T, tree, arena, errors) catch |e| switch (e) {
            error.OutOfMemory => |oom| return oom,
            error.EndOfStream => unreachable,
        };

        switch (val_result) {
            .ok => |val| values.appendAssumeCapacity(val),
            .err => |err| try errors.append(err),
        }
    }

    std.debug.assert(contents.isEmpty());
    return values;
}

pub const Const = struct {
    keyword: sexpr.TokenId,
    value_token: sexpr.TokenId,
    value: Value,

    pub const Value = union(enum) {
        i32: i32,
        f32: u32,
        i64: i64,
        f64: u64,
        // v128: *const [u8; 16],
        // ref_null: enum { func, extern },
        ref_extern: u32,
    };

    comptime {
        std.debug.assert(@sizeOf(Value) <= 16);
    }
};

pub const Result = struct {
    keyword: sexpr.TokenId,
    value_token: sexpr.TokenId,
    value: Value,

    pub const Value = union(enum) {
        i32: i32,
        f32: u32,
        i64: i64,
        f64: u64,
        // v128: *const [u8; 16],
        f32_nan: NanPattern,
        f64_nan: NanPattern,
        // ref_null: enum { func, extern },
        ref_extern: ?u32,
        ref_func,
    };

    pub const NanPattern = enum { canonical, arithmetic };

    comptime {
        std.debug.assert(@sizeOf(Value) <= 16);
    }
};

pub const Register = struct {
    /// The `module` name string used to access values from the registered module.
    name: Name,
    /// Identifies which module to register for imports.
    ///
    /// If `.none`, then the latest initialized module is used.
    id: Ident,
};

pub const Action = struct {
    /// Identifies which module contains the function or global export to invoke or get.
    ///
    /// If `.none`, then the latest initialized module is used.
    module: Ident,
    /// The name of the function or global export to invoke or get.
    name: Name,
    /// The `invoke` or `get` keyword.
    keyword: sexpr.TokenId,
    target: Target,

    pub const Target = union(enum) {
        get,
        invoke: struct {
            arguments: std.MultiArrayList(Const),
        },
    };

    pub fn parseContents(
        contents: *sexpr.Parser,
        tree: *const sexpr.Tree,
        arenas: *Arenas,
        caches: *Caches,
        target: std.meta.Tag(Target),
        target_token: sexpr.TokenId,
        parent_list: sexpr.List.Id,
        errors: *Error.List,
    ) error{OutOfMemory}!ParseResult(*const Action) {
        const action = try arenas.out.allocator().create(Action);

        const module = switch (try Ident.parse(contents, tree, arenas.parse, &caches.ids)) {
            .ok => |ok| ok,
            .err => |err| return .{ .err = err },
        };

        const name = switch (try Name.parse(contents, tree, arenas, &caches.names, parent_list)) {
            .ok => |ok| ok,
            .err => |err| return .{ .err = err },
        };

        const parsed_target: Target = switch (target) {
            .invoke => .{
                .invoke = .{
                    .arguments = try parseConstOrResultList(contents, Const, tree, arenas.out, errors),
                },
            },
            .get => Target.get,
        };

        try contents.expectEmpty(errors);

        action.* = Action{
            .module = module,
            .name = name,
            .keyword = target_token,
            .target = parsed_target,
        };

        return .{ .ok = action };
    }

    pub fn parse(
        parser: *sexpr.Parser,
        tree: *const sexpr.Tree,
        arenas: *Arenas,
        caches: *Caches,
        parent: sexpr.List.Id,
        errors: *Error.List,
    ) error{OutOfMemory}!ParseResult(*const Action) {
        const action_list: sexpr.List.Id = switch (parser.parseListInList(parent)) {
            .ok => |ok| ok,
            .err => |err| return .{ .err = err },
        };

        var contents = sexpr.Parser.init(action_list.contents(tree).values(tree));
        const action_keyword: sexpr.TokenId = switch (contents.parseAtomInList(.keyword_unknown, action_list)) {
            .ok => |ok| ok,
            .err => |err| return .{ .err = err },
        };

        const target: std.meta.Tag(Target) = switch (action_keyword.tag(tree)) {
            .keyword_invoke => .invoke,
            .keyword_get => .get,
            else => return .{ .err = Error.initUnexpectedValue(sexpr.Value.initAtom(action_keyword), .at_value) },
        };

        return parseContents(&contents, tree, arenas, caches, target, action_keyword, action_list, errors);
    }
};

pub const AssertReturn = struct {
    action: *const Action,
    results: std.MultiArrayList(Result),
};

pub const Failure = struct {
    msg: []const u8,

    pub fn parseInList(
        parser: *sexpr.Parser,
        tree: *const sexpr.Tree,
        list: sexpr.List.Id,
        scratch: *ArenaAllocator,
    ) error{OutOfMemory}!ParseResult(Failure) {
        const atom: sexpr.TokenId = switch (parser.parseAtomInList(.string, list)) {
            .ok => |ok| ok,
            .err => |err| return .{ .err = err },
        };

        switch (atom.tag(tree)) {
            .string => {
                const contents = atom.contents(tree);
                const msg = contents[1 .. contents.len - 1];
                std.debug.assert(std.unicode.utf8ValidateSlice(msg));
                return .{ .ok = .{ .msg = msg } };
            },
            .string_raw => {
                const contents = atom.contents(tree);
                const msg = contents[1 .. contents.len - 1];
                const failure = Failure{
                    .msg = (try @import("value.zig").string(msg).allocPrint(scratch.allocator())).items,
                };

                return if (std.unicode.utf8ValidateSlice(failure.msg))
                    .{ .ok = failure }
                else
                    .{ .err = Error.initInvalidUtf8(atom) };
            },
            else => return .{
                .err = Error.initExpectedToken(sexpr.Value.initAtom(atom), .string, .at_value),
            },
        }
    }
};

pub const AssertTrap = struct {
    action: *const Action,
    failure: Failure,
};

pub const AssertExhaustion = struct {
    action: *const Action,
    failure: Failure,
};

/// Asserts that a module does not pass validation.
pub const AssertInvalid = struct {
    module: Wast.Module,
    failure: Failure,
};

pub const Inner = InlineTaggedUnion(union {
    module: Wast.Module,
    register: Register,
    action: Action,
    assert_return: AssertReturn,
    assert_trap: AssertTrap, // TODO: Need assert_trap to also accept <module>
    // assert_exhaustion: AssertExhaustion,
    // assert_malformed: AssertMalformed, // TODO: Since this probably only uses quote/binary module, no need to have separate error list
    assert_invalid: AssertInvalid,
    // assert_unlinkable: AssertUnlinkable,
});

comptime {
    std.debug.assert(@alignOf(Register) == @alignOf(u32));
}
