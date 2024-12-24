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

pub const Module = struct {
    // keyword: sexpr.TokenId,
    name: Ident,
    format: Format.Ptr(.@"const"),

    pub const Format = InlineTaggedUnion(union {
        text: Text,
        binary: Binary,
        quote: Quote,
    });

    /// A module in the [WebAssembly Text] format.
    ///
    /// [WebAssembly Text]: https://webassembly.github.io/spec/core/index.html
    pub const Text = struct {
        fields: std.MultiArrayList(Field),

        pub const Field = struct {
            keyword: sexpr.TokenId,
            contents: Contents.Ptr(.@"const"),
        };

        pub const Contents = InlineTaggedUnion(union {});

        pub fn parseFields(
            contents: *sexpr.Parser,
            tree: *const sexpr.Tree,
            arenas: *Arenas,
            caches: *Caches,
            errors: *Error.List,
        ) error{OutOfMemory}!std.MultiArrayList(Field) {
            var fields = std.MultiArrayList(Field).empty;
            try fields.ensureTotalCapacity(arenas.out.allocator(), contents.remaining().len);

            // TODO: Module parsing
            _ = tree;
            _ = caches;
            _ = errors;

            return fields;
        }
    };

    pub const Binary = struct {
        keyword: sexpr.TokenId,
        contents: []const String,
    };

    pub const Quote = struct {
        keyword: sexpr.TokenId,
        contents: []const String,
    };

    pub const String = struct {
        token: sexpr.TokenId,

        /// The contents of the string literal without translating escape sequences.
        pub fn rawContents(string: String, tree: *const sexpr.Tree) []const u8 {
            switch (string.token.tag(tree)) {
                .string, .string_raw => {},
                else => unreachable,
            }

            const contents = string.token.contents(tree);
            return contents[1 .. contents.len - 1];
        }
    };

    pub fn parseContents(
        contents: *sexpr.Parser,
        tree: *const sexpr.Tree,
        arenas: *Arenas,
        caches: *Caches,
        errors: *Error.List,
    ) error{OutOfMemory}!ParseResult(Module) {
        const name = switch (try Ident.parse(contents, tree, arenas.parse, &caches.ids)) {
            .ok => |ok| ok,
            .err => |err| return .{ .err = err },
        };

        const format: Format.Union(.@"const") = format: {
            text: {
                var lookahead = contents.*;
                const peeked_value = lookahead.parseValue() catch break :text;
                const peeked_atom = peeked_value.getAtom() orelse break :text;

                const quoted_format: Format.Tag = switch (peeked_atom.tag(tree)) {
                    .keyword_binary => .binary,
                    .keyword_quote => .quote,
                    else => return .{ .err = Error.initUnexpectedValue(sexpr.Value.initAtom(peeked_atom), .at_value) },
                };

                contents.* = lookahead;
                lookahead = undefined;

                var strings = try std.ArrayListUnmanaged(String).initCapacity(
                    arenas.out.allocator(),
                    contents.remaining().len,
                );

                for (0..strings.capacity) |_| {
                    const string_atom: sexpr.TokenId = switch (contents.parseAtom(.string) catch break) {
                        .ok => |ok| ok,
                        .err => |err| {
                            try errors.append(err);
                            continue;
                        },
                    };

                    switch (string_atom.tag(tree)) {
                        .string, .string_raw => strings.appendAssumeCapacity(String{ .token = string_atom }),
                        else => try errors.append(
                            Error.initExpectedToken(
                                sexpr.Value.initAtom(string_atom),
                                .string,
                                .at_value,
                            ),
                        ),
                    }
                }

                std.debug.assert(contents.isEmpty());

                switch (quoted_format) {
                    .text => unreachable,
                    inline else => |format_tag| {
                        const quoted = try Format.allocate(arenas.out.allocator(), format_tag);
                        quoted.value = .{ .keyword = peeked_atom, .contents = strings.items };
                        break :format @unionInit(Format.Union(.@"const"), @tagName(format_tag), &quoted.value);
                    },
                }
            }

            const wat = try Format.allocate(arenas.out.allocator(), .text);
            wat.value = Text{ .fields = try Text.parseFields(contents, tree, arenas, caches, errors) };
            break :format .{ .text = &wat.value };
        };

        return .{
            .ok = Module{
                .name = name,
                .format = Format.Ptr(.@"const").init(format),
            },
        };
    }

    pub fn parse(
        parser: *sexpr.Parser,
        tree: *const sexpr.Tree,
        arenas: *Arenas,
        caches: *Caches,
        parent: sexpr.List.Id,
        errors: *Error.List,
    ) error{OutOfMemory}!ParseResult(Module) {
        const module_list: sexpr.List.Id = switch (parser.parseListInList(parent)) {
            .ok => |ok| ok,
            .err => |err| return .{ .err = err },
        };

        var contents = sexpr.Parser.init(module_list.contents(tree).values(tree));

        const module_token: sexpr.TokenId = switch (contents.parseAtomInList(.keyword_module, module_list)) {
            .ok => |ok| ok,
            .err => |err| return .{ .err = err },
        };

        switch (module_token.tag(tree)) {
            .keyword_module => {
                const module = try parseContents(&contents, tree, arenas, caches, errors);
                if (module == .ok)
                    try contents.expectEmpty(errors);
                return module;
            },
            else => return .{
                .err = Error.initExpectedToken(sexpr.Value.initAtom(module_token), .keyword_module, .at_value),
            },
        }
    }
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

    /// Asserts that a module does not pass validation.
    pub const AssertInvalid = struct {
        module: Module,
        failure: Failure,
    };

    pub const Inner = InlineTaggedUnion(union {
        module: Module,
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
            .keyword_module => {
                const module = try Command.Inner.allocate(arenas.out.allocator(), .module);
                module.value = switch (try Module.parseContents(&cmd_parser, tree, &arenas, &caches, errors)) {
                    .ok => |ok| ok,
                    .err => |err| {
                        try errors.append(err);
                        continue;
                    },
                };

                break :cmd .{ .module = &module.value };
            },
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
            // .keyword_assert_malformed => {},
            .keyword_assert_invalid => {
                const assert_invalid = try Command.Inner.allocate(arenas.out.allocator(), .assert_invalid);
                const module = switch (try Module.parse(&cmd_parser, tree, &arenas, &caches, cmd_list, errors)) {
                    .ok => |ok| ok,
                    .err => |err| {
                        try errors.append(err);
                        continue;
                    },
                };

                assert_invalid.value = Command.AssertInvalid{
                    .module = module,
                    .failure = switch (try Command.Failure.parseInList(&cmd_parser, tree, cmd_list, arenas.scratch)) {
                        .ok => |ok| ok,
                        .err => |err| {
                            try errors.append(err);
                            continue;
                        },
                    },
                };

                break :cmd .{ .assert_invalid = &assert_invalid.value };
            },
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
