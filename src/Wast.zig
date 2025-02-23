//! WebAssembly Text ([WAT]) and WebAssembly Specification Text ([`.wast`]) parsing.
//!
//! [WAT]: https://webassembly.github.io/spec/core/index.html
//! [`.wast`]: https://github.com/WebAssembly/spec/blob/d52e42df1314521c6e4cd7331593f2901e1d7b43/interpreter/README.md

const std = @import("std");
const value = @import("Wast/value.zig");

pub const Arena = @import("IndexedArena.zig");

pub const Lexer = @import("Wast/Lexer.zig");
pub const sexpr = @import("Wast/sexpr.zig");

pub const Errors = @import("Wast/Errors.zig");
pub const LineCol = @import("Wast/LineCol.zig");

pub const Ident = @import("Wast/ident.zig").Ident;
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
    errors: *Errors,
    scratch: *std.heap.ArenaAllocator,
) error{OutOfMemory}!Wast {
    const commands_values = tree.values.values(tree);
    var commands = try Arena.BoundedArrayList(Command).initCapacity(arena, commands_values.len);

    arena.ensureUnusedCapacityForBytes(@import("size.zig").averageOfFields(Command.Inner) *| commands_values.len) catch {};

    var parser_context = sexpr.Parser.Context{ .tree = tree, .errors = errors };
    for (commands_values) |cmd_value| {
        _ = scratch.reset(.retain_capacity);

        const cmd_list = switch (cmd_value.unpacked()) {
            .list => |list| list,
            .atom => |bad_token| {
                _ = try errors.reportExpectedListAtToken(
                    bad_token,
                    tree,
                    &parser_context.locator,
                    @errorReturnTrace(),
                );
                continue;
            },
        };

        var cmd_parser = sexpr.Parser.init(cmd_list.contents(tree).values(tree));

        const cmd_keyword_id = cmd_parser.parseAtomInList(
            cmd_list,
            &parser_context,
            "command keyword",
        ) catch |e| switch (e) {
            error.OutOfMemory => |oom| return oom,
            error.ReportedParserError => continue,
        };

        const cmd: Command.Inner = cmd: switch (cmd_keyword_id.tag(tree)) {
            .keyword_module => {
                const module = try arena.create(Module);
                _ = scratch.reset(.retain_capacity);

                const parsed_module = Module.parseContents(
                    &cmd_parser,
                    &parser_context,
                    arena,
                    caches,
                    scratch,
                ) catch |e| switch (e) {
                    error.OutOfMemory => |oom| return oom,
                    error.ReportedParserError => continue,
                };

                module.set(arena, parsed_module);
                break :cmd .{ .module = module };
            },
            .keyword_register => {
                const register = try arena.create(Command.Register);

                const name = Name.parse(
                    &cmd_parser,
                    &parser_context,
                    caches.allocator,
                    &caches.names,
                    arena,
                    cmd_list,
                    scratch,
                ) catch |e| switch (e) {
                    error.OutOfMemory => |oom| return oom,
                    error.ReportedParserError => continue,
                };

                const id = Ident.Opt.parse(
                    &cmd_parser,
                    &parser_context,
                    caches.allocator,
                    &caches.ids,
                ) catch |e| switch (e) {
                    error.OutOfMemory => |oom| return oom,
                    error.ReportedParserError => continue,
                };

                register.set(arena, .{ .name = name, .id = id });
                break :cmd .{ .register = register };
            },
            .keyword_invoke => {
                const action = Command.Action.parseContents(
                    &cmd_parser,
                    &parser_context,
                    arena,
                    caches,
                    cmd_keyword_id,
                    cmd_list,
                    scratch,
                ) catch |e| switch (e) {
                    error.OutOfMemory => |oom| return oom,
                    error.ReportedParserError => continue,
                };

                break :cmd .{ .action = action };
            },
            .keyword_get => {
                const action = Command.Action.parseContents(
                    &cmd_parser,
                    &parser_context,
                    arena,
                    caches,
                    cmd_keyword_id,
                    cmd_list,
                    scratch,
                ) catch |e| switch (e) {
                    error.OutOfMemory => |oom| return oom,
                    error.ReportedParserError => continue,
                };

                break :cmd .{ .action = action };
            },
            .keyword_assert_return => {
                const assert_return = try arena.create(Command.AssertReturn);
                const action = Command.Action.parse(
                    &cmd_parser,
                    &parser_context,
                    arena,
                    caches,
                    cmd_list,
                    scratch,
                ) catch |e| switch (e) {
                    error.OutOfMemory => |oom| return oom,
                    error.ReportedParserError => continue,
                };

                assert_return.set(
                    arena,
                    .{
                        .action = action,
                        .results = try Command.parseConstOrResultList(
                            &cmd_parser,
                            Command.Result,
                            &parser_context,
                            arena,
                        ),
                    },
                );

                break :cmd .{ .assert_return = assert_return };
            },
            .keyword_assert_trap => .{
                .assert_trap = Command.AssertTrap.parseContents(
                    &cmd_parser,
                    &parser_context,
                    arena,
                    caches,
                    cmd_list,
                    scratch,
                ) catch |e| switch (e) {
                    error.OutOfMemory => |oom| return oom,
                    error.ReportedParserError => continue,
                },
            },
            .keyword_assert_exhaustion => {
                // Duplicate code taken from `assert_trap`.
                const assert_exhaustion = try arena.create(Command.AssertExhaustion);
                const action = Command.Action.parse(
                    &cmd_parser,
                    &parser_context,
                    arena,
                    caches,
                    cmd_list,
                    scratch,
                ) catch |e| switch (e) {
                    error.OutOfMemory => |oom| return oom,
                    error.ReportedParserError => continue,
                };

                assert_exhaustion.set(
                    arena,
                    .{
                        .action = action,
                        .failure = Command.Failure.parseInList(
                            &cmd_parser,
                            &parser_context,
                            arena,
                            cmd_list,
                            scratch,
                        ) catch |e| switch (e) {
                            error.OutOfMemory => |oom| return oom,
                            error.ReportedParserError => continue,
                        },
                    },
                );

                break :cmd .{ .assert_exhaustion = assert_exhaustion };
            },
            // .keyword_assert_malformed => {},
            .keyword_assert_malformed => {
                // Copied from `.keyword_assert_invalid` case.
                const assert_malformed = try arena.create(Command.AssertMalformed);
                const module = Module.parse(
                    &cmd_parser,
                    &parser_context,
                    arena,
                    caches,
                    cmd_list,
                    scratch,
                ) catch |e| switch (e) {
                    error.OutOfMemory => |oom| return oom,
                    error.ReportedParserError => continue,
                };

                assert_malformed.set(
                    arena,
                    .{
                        .module = module,
                        .failure = Command.Failure.parseInList(
                            &cmd_parser,
                            &parser_context,
                            arena,
                            cmd_list,
                            scratch,
                        ) catch |e| switch (e) {
                            error.OutOfMemory => |oom| return oom,
                            error.ReportedParserError => continue,
                        },
                    },
                );

                break :cmd .{ .assert_malformed = assert_malformed };
            },
            .keyword_assert_invalid => {
                const assert_invalid = try arena.create(Command.AssertInvalid);
                const module = Module.parse(
                    &cmd_parser,
                    &parser_context,
                    arena,
                    caches,
                    cmd_list,
                    scratch,
                ) catch |e| switch (e) {
                    error.OutOfMemory => |oom| return oom,
                    error.ReportedParserError => continue,
                };

                assert_invalid.set(
                    arena,
                    .{
                        .module = module,
                        .failure = Command.Failure.parseInList(
                            &cmd_parser,
                            &parser_context,
                            arena,
                            cmd_list,
                            scratch,
                        ) catch |e| switch (e) {
                            error.OutOfMemory => |oom| return oom,
                            error.ReportedParserError => continue,
                        },
                    },
                );

                break :cmd .{ .assert_invalid = assert_invalid };
            },
            else => {
                _ = try errors.reportAtToken(
                    cmd_keyword_id,
                    tree,
                    &parser_context.locator,
                    "unknown command keyword",
                    @errorReturnTrace(),
                );
                continue;
            },
        };

        commands.appendAssumeCapacity(
            arena,
            Command{ .keyword = cmd_keyword_id, .inner = cmd },
        );

        try cmd_parser.expectEmpty(&parser_context);
    }

    return Wast{
        .tree = tree,
        .arena = arena,
        .caches = caches,
        .commands = commands.items,
    };
}

pub fn nameContents(wast: *const Wast, name: Name.Id) []const u8 {
    return name.bytes(wast.arena, &wast.caches.names);
}

pub fn identContents(wast: *const Wast, ident: Ident.Interned) []const u8 {
    return ident.get(wast.tree, &wast.caches.ids);
}

test {
    _ = Lexer;
    _ = value;
    _ = LineCol;
}
