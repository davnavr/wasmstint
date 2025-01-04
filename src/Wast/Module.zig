const std = @import("std");
const ArenaAllocator = std.heap.ArenaAllocator;
const IndexedArena = @import("../IndexedArena.zig");

const sexpr = @import("sexpr.zig");
const Error = sexpr.Error;
const ParseResult = sexpr.Parser.Result;

const Ident = @import("ident.zig").Ident;
const Name = @import("Name.zig");

const Caches = @import("Caches.zig");

pub const Text = @import("Module/Text.zig");

name: Ident.Symbolic align(4),
format_keyword: sexpr.TokenId.Opt,
format: Format,

const Module = @This();

pub const Format = union {
    text: IndexedArena.Idx(Text),
    binary: IndexedArena.Idx(Binary),
    quote: IndexedArena.Idx(Quote),
};

comptime {
    std.debug.assert(@alignOf(Module) == @alignOf(u32));
    std.debug.assert(@sizeOf(Module) == switch (@import("builtin").mode) {
        .Debug, .ReleaseSafe => 20,
        .ReleaseFast, .ReleaseSmall => 16,
    });
}

pub const Binary = struct {
    contents: IndexedArena.Slice(String),
};

pub const Quote = struct {
    contents: IndexedArena.Slice(String),
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
    arena: *IndexedArena,
    caches: *Caches,
    errors: *Error.List,
    scratch: *ArenaAllocator,
) error{OutOfMemory}!ParseResult(Module) {
    const name = try Ident.Symbolic.parse(contents, tree, caches.allocator, &caches.ids);

    var format_keyword = sexpr.TokenId.Opt.none;
    const format: Format = format: {
        text: {
            var lookahead = contents.*;
            const peeked_value = lookahead.parseValue() catch break :text;
            const peeked_atom = peeked_value.getAtom() orelse break :text;
            const format_tag = peeked_atom.tag(tree);
            switch (format_tag) {
                .keyword_binary, .keyword_quote => format_keyword = sexpr.TokenId.Opt.init(peeked_atom),
                else => return .{
                    .err = Error.initUnexpectedValue(sexpr.Value.initAtom(peeked_atom), .at_value),
                },
            }

            contents.* = lookahead;
            lookahead = undefined;

            var strings = try IndexedArena.BoundedArrayList(String).initCapacity(arena, contents.remaining.len);
            for (0..strings.capacity) |_| {
                const string_atom: sexpr.TokenId = switch (contents.parseAtom(.string) catch break) {
                    .ok => |ok| ok,
                    .err => |err| {
                        try errors.append(err);
                        continue;
                    },
                };

                switch (string_atom.tag(tree)) {
                    .string, .string_raw => strings.appendAssumeCapacity(arena, String{ .token = string_atom }),
                    else => try errors.append(
                        Error.initExpectedToken(sexpr.Value.initAtom(string_atom), .string, .at_value),
                    ),
                }
            }

            std.debug.assert(contents.isEmpty());

            switch (format_tag) {
                .keyword_binary => {
                    const binary = try arena.create(Binary);
                    binary.set(arena, .{ .contents = strings.items });
                    break :format .{ .binary = binary };
                },
                .keyword_quote => {
                    const quoted = try arena.create(Quote);
                    quoted.set(arena, .{ .contents = strings.items });
                    break :format .{ .quote = quoted };
                },
                else => unreachable,
            }

            comptime unreachable;
        }

        const wat = try arena.create(Module.Text);
        _ = scratch.reset(.retain_capacity);
        wat.set(
            arena,
            .{
                .fields = try Text.parseFields(
                    contents,
                    tree,
                    arena,
                    caches,
                    errors,
                    scratch,
                ),
            },
        );

        break :format .{ .text = wat };
    };

    return .{ .ok = Module{ .name = name, .format_keyword = format_keyword, .format = format } };
}

pub fn parse(
    parser: *sexpr.Parser,
    tree: *const sexpr.Tree,
    arena: *IndexedArena,
    caches: *Caches,
    parent: sexpr.List.Id,
    errors: *Error.List,
    scratch: *ArenaAllocator,
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
            const module = try parseContents(&contents, tree, arena, caches, errors, scratch);
            if (module == .ok)
                try contents.expectEmpty(errors);

            return module;
        },
        else => return .{
            .err = Error.initExpectedToken(sexpr.Value.initAtom(module_token), .keyword_module, .at_value),
        },
    }
}
