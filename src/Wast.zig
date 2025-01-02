//! WebAssembly Text ([WAT]) and WebAssembly Specification Text ([`.wast`]) parsing.
//!
//! [WAT]: https://webassembly.github.io/spec/core/index.html
//! [`.wast`]: https://github.com/WebAssembly/spec/blob/d52e42df1314521c6e4cd7331593f2901e1d7b43/interpreter/README.md

const std = @import("std");
const value = @import("Wast/value.zig");

pub const Arena = @import("IndexedArena.zig");

pub const Lexer = @import("Wast/Lexer.zig");
pub const sexpr = @import("Wast/sexpr.zig");

pub const Error = @import("Wast/Error.zig");
pub const LineCol = @import("Wast/LineCol.zig");

pub const Ident = @import("Wast/Ident.zig");
pub const Name = @import("Wast/Name.zig");
pub const Module = @import("Wast/Module.zig");
pub const Command = @import("Wast/Command.zig");

pub const Caches = @import("Wast/Caches.zig");

tree: *const sexpr.Tree,
arena: *const Arena,
caches: *const Caches,
commands: Arena.Slice(Command),

const Wast = @This();

pub fn parse(
    tree: *const sexpr.Tree,
    arena: *Arena,
    caches: *Caches,
    errors: *Error.List,
    scratch: *std.heap.ArenaAllocator,
) error{OutOfMemory}!Wast {
    const commands_values = tree.values.values(tree);
    var commands = try Arena.BoundedArrayList(Command).initCapacity(arena, commands_values.len);

    arena.ensureUnusedCapacityForBytes(@import("size.zig").averageOfFields(Command.Inner) *| commands_values.len) catch {};

    for (commands_values) |cmd_value| {
        _ = scratch.reset(.retain_capacity);

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

        const cmd: Command.Inner = cmd: switch (cmd_keyword_id.tag(tree)) {
            .keyword_module => {
                const module = try arena.create(Module);
                _ = scratch.reset(.retain_capacity);
                switch (try Module.parseContents(&cmd_parser, tree, arena, caches, errors, scratch)) {
                    .ok => |ok| module.set(arena, ok),
                    .err => |err| {
                        try errors.append(err);
                        continue;
                    },
                }

                break :cmd .{ .module = module };
            },
            .keyword_register => {
                const register = try arena.create(Command.Register);

                const name_result = try Name.parse(
                    &cmd_parser,
                    tree,
                    caches.allocator,
                    &caches.names,
                    arena,
                    cmd_list,
                    scratch,
                );

                const name = switch (name_result) {
                    .ok => |ok| ok,
                    .err => |err| {
                        try errors.append(err);
                        continue;
                    },
                };

                const id = switch (try Ident.parse(&cmd_parser, tree, caches.allocator, &caches.ids)) {
                    .ok => |ok| ok,
                    .err => |err| {
                        try errors.append(err);
                        continue;
                    },
                };

                register.set(arena, .{ .name = name, .id = id });
                break :cmd .{ .register = register };
            },
            .keyword_invoke => {
                const action_result = try Command.Action.parseContents(
                    &cmd_parser,
                    tree,
                    arena,
                    caches,
                    cmd_keyword_id,
                    cmd_list,
                    errors,
                    scratch,
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
                    arena,
                    caches,
                    cmd_keyword_id,
                    cmd_list,
                    errors,
                    scratch,
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
                const assert_return = try arena.create(Command.AssertReturn);
                const action_result = try Command.Action.parse(
                    &cmd_parser,
                    tree,
                    arena,
                    caches,
                    cmd_list,
                    errors,
                    scratch,
                );

                const action = switch (action_result) {
                    .ok => |ok| ok,
                    .err => |err| {
                        try errors.append(err);
                        continue;
                    },
                };

                assert_return.set(
                    arena,
                    .{
                        .action = action,
                        .results = try Command.parseConstOrResultList(&cmd_parser, Command.Result, tree, arena, errors),
                    },
                );

                break :cmd .{ .assert_return = assert_return };
            },
            .keyword_assert_trap => {
                const assert_trap = try arena.create(Command.AssertTrap);

                const action_result = try Command.Action.parse(
                    &cmd_parser,
                    tree,
                    arena,
                    caches,
                    cmd_list,
                    errors,
                    scratch,
                );

                const action = switch (action_result) {
                    .ok => |ok| ok,
                    .err => |err| {
                        try errors.append(err);
                        continue;
                    },
                };

                assert_trap.set(
                    arena,
                    .{
                        .action = action,
                        .failure = switch (try Command.Failure.parseInList(&cmd_parser, tree, arena, cmd_list, scratch)) {
                            .ok => |ok| ok,
                            .err => |err| {
                                try errors.append(err);
                                continue;
                            },
                        },
                    },
                );

                break :cmd .{ .assert_trap = assert_trap };
            },
            // .keyword_assert_exhaustion => {},
            // .keyword_assert_malformed => {},
            .keyword_assert_invalid => {
                const assert_invalid = try arena.create(Command.AssertInvalid);
                const module = switch (try Module.parse(&cmd_parser, tree, arena, caches, cmd_list, errors, scratch)) {
                    .ok => |ok| ok,
                    .err => |err| {
                        try errors.append(err);
                        continue;
                    },
                };

                assert_invalid.set(
                    arena,
                    .{
                        .module = module,
                        .failure = switch (try Command.Failure.parseInList(&cmd_parser, tree, arena, cmd_list, scratch)) {
                            .ok => |ok| ok,
                            .err => |err| {
                                try errors.append(err);
                                continue;
                            },
                        },
                    },
                );

                break :cmd .{ .assert_invalid = assert_invalid };
            },
            else => {
                try errors.append(Error.initUnexpectedValue(sexpr.Value.initAtom(cmd_keyword_id), .at_value));
                continue;
            },
        };

        commands.appendAssumeCapacity(
            arena,
            Command{ .keyword = cmd_keyword_id, .inner = cmd },
        );

        try cmd_parser.expectEmpty(errors);
    }

    return Wast{
        .tree = tree,
        .arena = arena,
        .caches = caches,
        .commands = commands.items,
    };
}

test {
    _ = Lexer;
    _ = value;
    _ = LineCol;
}
