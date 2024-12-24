//! WebAssembly Text ([WAT]) and WebAssembly Specification Text ([`.wast`]) parsing.
//!
//! [WAT]: https://webassembly.github.io/spec/core/index.html
//! [`.wast`]: https://github.com/WebAssembly/spec/blob/d52e42df1314521c6e4cd7331593f2901e1d7b43/interpreter/README.md

const std = @import("std");
const ArenaAllocator = std.heap.ArenaAllocator;
const InlineTaggedUnion = @import("inline_tagged_union.zig").InlineTaggedUnion;

pub const Lexer = @import("Wast/Lexer.zig");
pub const sexpr = @import("Wast/sexpr.zig");
pub const Ident = @import("Wast/Ident.zig");
pub const Name = @import("Wast/Name.zig");
pub const Error = @import("Wast/Error.zig");
pub const LineCol = @import("Wast/LineCol.zig");

const Arenas = @import("Wast/Arenas.zig");
const value = @import("Wast/value.zig");

const ParseResult = sexpr.Parser.Result;

tree: *const sexpr.Tree,
interned: struct {
    ids: Ident.Cache.Entries,
    names: Name.Cache.Entries,
},
commands: std.MultiArrayList(Command),

const Caches = struct {
    ids: Ident.Cache = .empty,
    names: Name.Cache = .empty,
};

pub const Command = struct {
    keyword: sexpr.TokenId,
    inner: Inner.Ptr(.@"const"),

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
            const action_list_result = parser.parseList() catch |e| switch (e) {
                error.EndOfStream => return .{
                    .err = Error.initExpectedToken(sexpr.Value.initList(parent), .open_paren, .at_list_end),
                },
            };

            const action_list: sexpr.List.Id = switch (action_list_result) {
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
                    const failure = Failure{ .msg = (try value.string(msg).allocPrint(scratch.allocator())).items };
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

    pub const Inner = InlineTaggedUnion(union {
        //module: ,
        register: Register,
        action: Action,
        assert_return: AssertReturn,
        assert_trap: AssertTrap,
        // assert_exhaustion: AssertExhaustion,
    });

    comptime {
        std.debug.assert(@alignOf(Register) == @alignOf(u32));
    }
};

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
    const count = contents.remaining().len;
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

const Wast = @This();

pub fn parse(
    tree: *const sexpr.Tree,
    arena: *ArenaAllocator,
    errors: *Error.List,
    parse_arena: *ArenaAllocator,
) error{OutOfMemory}!Wast {
    // `parse_arena` is used for allocations that live for the rest of this function call.
    var temporary_arena = ArenaAllocator.init(parse_arena.allocator());
    defer temporary_arena.deinit();

    var arenas = Arenas{
        .out = arena,
        .parse = parse_arena,
        .scratch = &temporary_arena,
    };

    const commands_values = tree.values.values(tree);

    var commands = std.MultiArrayList(Command).empty;
    try commands.setCapacity(arenas.out.allocator(), commands_values.len);

    var caches = Caches{};

    for (commands_values) |cmd_value| {
        _ = arenas.scratch.reset(.retain_capacity);

        const cmd_list = cmd_value.getList() orelse {
            try errors.append(Error.initUnexpectedValue(cmd_value, .at_value));
            continue;
        };

        var cmd_parser = sexpr.Parser.init(cmd_list.contents(tree).values(tree));

        const cmd_keyword_id = switch (cmd_parser.parseAtomInList(null, cmd_list)) {
            .ok => |ok| ok,
            .err => |err| {
                try errors.append(err);
                continue;
            },
        };

        const cmd: Command.Inner.Union(.@"const") = cmd: switch (cmd_keyword_id.tag(tree)) {
            // .keyword_module => {
            //     // TODO: Parse id, then check for binary or quote keyword
            //     unreachable;
            // },
            .keyword_register => {
                const register = try Command.Inner.allocate(arenas.out.allocator(), .register);

                const name_result = try Name.parse(&cmd_parser, tree, &arenas, &caches.names, cmd_list);

                const name = switch (name_result) {
                    .ok => |ok| ok,
                    .err => |err| {
                        try errors.append(err);
                        continue;
                    },
                };

                const id = switch (try Ident.parse(&cmd_parser, tree, arenas.parse, &caches.ids)) {
                    .ok => |ok| ok,
                    .err => |err| {
                        try errors.append(err);
                        continue;
                    },
                };

                register.value = Command.Register{ .name = name, .id = id };
                break :cmd .{ .register = &register.value };
            },
            .keyword_invoke => {
                const action_result = try Command.Action.parseContents(
                    &cmd_parser,
                    tree,
                    &arenas,
                    &caches,
                    .invoke,
                    cmd_keyword_id,
                    cmd_list,
                    errors,
                );

                break :cmd .{
                    .action = switch (action_result) {
                        .ok => |action| action,
                        .err => |err| {
                            try errors.append(err);
                            continue;
                        },
                    },
                };
            },
            .keyword_get => {
                const action_result = try Command.Action.parseContents(
                    &cmd_parser,
                    tree,
                    &arenas,
                    &caches,
                    .get,
                    cmd_keyword_id,
                    cmd_list,
                    errors,
                );

                break :cmd .{
                    .action = switch (action_result) {
                        .ok => |action| action,
                        .err => |err| {
                            try errors.append(err);
                            continue;
                        },
                    },
                };
            },
            .keyword_assert_return => {
                const assert_return = try Command.Inner.allocate(arenas.out.allocator(), .assert_return);
                const action_result = try Command.Action.parse(&cmd_parser, tree, &arenas, &caches, cmd_list, errors);

                const action = switch (action_result) {
                    .ok => |ok| ok,
                    .err => |err| {
                        try errors.append(err);
                        continue;
                    },
                };

                assert_return.value = Command.AssertReturn{
                    .action = action,
                    .results = try parseConstOrResultList(&cmd_parser, Result, tree, arenas.out, errors),
                };

                break :cmd .{ .assert_return = &assert_return.value };
            },
            .keyword_assert_trap => {
                const assert_trap = try Command.Inner.allocate(arenas.out.allocator(), .assert_trap);

                const action_result = try Command.Action.parse(
                    &cmd_parser,
                    tree,
                    &arenas,
                    &caches,
                    cmd_list,
                    errors,
                );

                const action = switch (action_result) {
                    .ok => |ok| ok,
                    .err => |err| {
                        try errors.append(err);
                        continue;
                    },
                };

                assert_trap.value = Command.AssertTrap{
                    .action = action,
                    .failure = switch (try Command.Failure.parseInList(&cmd_parser, tree, cmd_list, arenas.scratch)) {
                        .ok => |ok| ok,
                        .err => |err| {
                            try errors.append(err);
                            continue;
                        },
                    },
                };

                break :cmd .{ .assert_trap = &assert_trap.value };
            },
            // .keyword_assert_exhaustion => {},
            // .keyword_assert_malformed => {}, // TODO: Need separate *Module parser
            // .keyword_assert_invalid => {}, // TODO: Need separate *Module parser
            else => {
                try errors.append(Error.initUnexpectedValue(sexpr.Value.initAtom(cmd_keyword_id), .at_value));
                continue;
            },
        };

        commands.appendAssumeCapacity(Command{
            .keyword = cmd_keyword_id,
            .inner = Command.Inner.Ptr(.@"const").init(cmd),
        });

        try cmd_parser.expectEmpty(errors);
    }

    return Wast{
        .tree = tree,
        .interned = .{
            .ids = try caches.ids.entries(arenas.out),
            .names = try caches.names.entries(arenas.out),
        },
        .commands = commands,
    };
}

test {
    _ = Lexer;
    _ = value;
    _ = LineCol;
}
