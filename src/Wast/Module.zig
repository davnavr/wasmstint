const std = @import("std");
const ArenaAllocator = std.heap.ArenaAllocator;
const IndexedArena = @import("../IndexedArena.zig");

const sexpr = @import("sexpr.zig");
const ParseContext = sexpr.Parser.Context;

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

pub const TaggedFormat = @Type(std.builtin.Type{
    .@"union" = .{
        .layout = .auto,
        .tag_type = std.meta.FieldEnum(Format),
        .fields = @typeInfo(Format).@"union".fields,
        .decls = &[0]std.builtin.Type.Declaration{},
    },
});

pub fn taggedFormat(module: *const Module, tree: *const sexpr.Tree) TaggedFormat {
    return if (module.format_keyword.get()) |format_keyword|
        switch (format_keyword.tag(tree)) {
            .keyword_quote => .{ .quote = module.format.quote },
            .keyword_binary => .{ .binary = module.format.binary },
            else => unreachable,
        }
    else
        .{ .text = module.format.text };
}

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
    ctx: *ParseContext,
    arena: *IndexedArena,
    caches: *Caches,
    scratch: *ArenaAllocator,
) sexpr.Parser.ParseError!Module {
    const name = try Ident.Symbolic.parse(
        contents,
        ctx.tree,
        caches.allocator,
        &caches.ids,
    );

    var format_keyword = sexpr.TokenId.Opt.none;
    const format: Format = format: {
        text: {
            var lookahead = contents.*;
            const peeked_value = lookahead.parseValue() catch break :text;
            const peeked_atom = peeked_value.getAtom() orelse break :text;
            const format_tag = peeked_atom.tag(ctx.tree);
            switch (format_tag) {
                .keyword_binary, .keyword_quote => format_keyword = sexpr.TokenId.Opt.init(peeked_atom),
                else => return (try ctx.errorAtToken(
                    peeked_atom,
                    "expected 'binary' or 'quote' keyword",
                    @errorReturnTrace(),
                )).err,
            }

            contents.* = lookahead;
            lookahead = undefined;

            var strings = try IndexedArena.BoundedArrayList(String).initCapacity(
                arena,
                contents.remaining.len,
            );
            for (0..strings.capacity) |_| {
                const string_atom = contents.parseAtom(ctx, "string literal") catch |e| switch (e) {
                    error.EndOfStream => break,
                    else => |err| return err,
                };

                switch (string_atom.tag(ctx.tree)) {
                    .string, .string_raw => strings.appendAssumeCapacity(arena, String{ .token = string_atom }),
                    else => return (try ctx.errorAtToken(
                        string_atom,
                        "expected string literal",
                        @errorReturnTrace(),
                    )).err,
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
                    ctx,
                    arena,
                    caches,
                    scratch,
                ),
            },
        );

        break :format .{ .text = wat };
    };

    return Module{ .name = name, .format_keyword = format_keyword, .format = format };
}

pub fn parseOrEmpty(
    parser: *sexpr.Parser,
    ctx: *ParseContext,
    arena: *IndexedArena,
    caches: *Caches,
    scratch: *ArenaAllocator,
) sexpr.Parser.ParseOrEofError!Module {
    const module_list = try parser.parseList(ctx);

    var contents = sexpr.Parser.init(module_list.contents(ctx.tree).values(ctx.tree));

    // TODO: Darn, spec allows abbreviation where module fields can be allowed!
    const module_token = try contents.parseAtomInList(module_list, ctx, "'module' keyword");

    switch (module_token.tag(ctx.tree)) {
        .keyword_module => {
            const module = try parseContents(&contents, ctx, arena, caches, scratch);
            try contents.expectEmpty(ctx);
            return module;
        },
        else => return (try ctx.errorAtToken(
            module_token,
            "expected 'module' (TODO: handle module field parsing)",
            @errorReturnTrace(),
        )).err,
    }
}

pub fn parse(
    parser: *sexpr.Parser,
    ctx: *ParseContext,
    arena: *IndexedArena,
    caches: *Caches,
    parent: sexpr.List.Id,
    scratch: *ArenaAllocator,
) sexpr.Parser.ParseError!Module {
    return parseOrEmpty(parser, ctx, arena, caches, scratch) catch |e| switch (e) {
        error.EndOfStream => (try ctx.errorAtList(
            parent,
            .end,
            "expected a module",
            @errorReturnTrace(),
        )).err,
        else => |err| err,
    };
}

pub const encode = @import("Module/encode.zig").encode;
