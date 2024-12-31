//! WebAssembly Text ([WAT]) and WebAssembly Specification Text ([`.wast`]) parsing.
//!
//! [WAT]: https://webassembly.github.io/spec/core/index.html
//! [`.wast`]: https://github.com/WebAssembly/spec/blob/d52e42df1314521c6e4cd7331593f2901e1d7b43/interpreter/README.md

const std = @import("std");
const ArenaAllocator = std.heap.ArenaAllocator;
const InlineTaggedUnion = @import("inline_tagged_union.zig").InlineTaggedUnion;
const CompactMultiSlice = @import("compact_multi_slice.zig").CompactMultiSlice;

pub const Lexer = @import("Wast/Lexer.zig");
pub const sexpr = @import("Wast/sexpr.zig");
pub const Ident = @import("Wast/Ident.zig");
pub const Name = @import("Wast/Name.zig");
pub const Error = @import("Wast/Error.zig");
pub const LineCol = @import("Wast/LineCol.zig");

pub const Module = @import("Wast/Module.zig");
pub const Command = @import("Wast/Command.zig");

const Arenas = @import("Wast/Arenas.zig");
const Caches = @import("Wast/Caches.zig");
const value = @import("Wast/value.zig");

const ParseResult = sexpr.Parser.Result;

tree: *const sexpr.Tree,
interned: struct {
    ids: Ident.Cache.Entries,
    names: Name.Cache.Entries,
},
commands: std.MultiArrayList(Command),

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

                assert_return.value = Command.AssertReturn{
                    .action = action,
                    .results = try Command.parseConstOrResultList(
                        &cmd_parser,
                        Command.Result,
                        tree,
                        arenas.out,
                        errors,
                    ),
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
