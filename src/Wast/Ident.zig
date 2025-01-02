//! An WebAssembly [*id*entifier].
//!
//! [*id*entifier]: https://webassembly.github.io/spec/core/text/values.html#text-id

const std = @import("std");
const Allocator = std.mem.Allocator;
const sexpr = @import("sexpr.zig");
const value = @import("value.zig");

inner: packed struct(u64) {
    some: bool,
    token: sexpr.TokenId,
    index: packed union {
        symbolic: Interned,
        numeric: u32,
    },
} align(@alignOf(u32)),

const Ident = @This();

comptime {
    std.debug.assert(@alignOf(Ident) == @alignOf(u32));
}

pub const none = Ident{
    .inner = .{
        .some = false,
        .token = undefined,
        .index = undefined,
    },
};

/// `tok` must refer to a token with `tok.tag(tree) == .id`.
pub fn initSymbolic(tok: sexpr.TokenId, ident: Interned) Ident {
    return .{
        .inner = .{
            .some = true,
            .token = tok,
            .index = .{ .symbolic = ident },
        },
    };
}

pub fn initNumeric(tok: sexpr.TokenId, n: u32) Ident {
    return .{
        .inner = .{
            .some = true,
            .token = tok,
            .index = .{ .numeric = n },
        },
    };
}

pub fn token(ident: Ident) ?sexpr.TokenId {
    return if (ident.inner.some) ident.inner.token else null;
}

pub const Index = union(enum) {
    omitted,
    symbolic: Interned,
    numeric: u32,
};

pub fn index(ident: Ident, tree: *const sexpr.Tree) Index {
    if (ident.inner.some) {
        return switch (ident.inner.token.tag(tree)) {
            .integer => .{ .numeric = ident.inner.index.numeric },
            .id => .{ .symbolic = ident.inner.index.symbolic },
            else => unreachable,
        };
    } else return .omitted;
}

pub fn parseRequired(
    parser: *sexpr.Parser,
    tree: *const sexpr.Tree,
    parent: sexpr.List.Id,
    cache_allocator: Allocator,
    cache: *Cache,
) Allocator.Error!sexpr.Parser.Result(Ident) {
    const atom: sexpr.TokenId = switch (parser.parseAtomInList(.id, parent)) {
        .ok => |ok| ok,
        .err => |err| return .{ .err = err },
    };

    switch (atom.tag(tree)) {
        // Mostly copied from the optional `parse()` version.
        .id => {
            const ident = try cache.intern(cache_allocator, tree, atom);
            return .{ .ok = Ident.initSymbolic(atom, ident) };
        },
        .integer => {
            const n = value.unsignedInteger(u32, atom.contents(tree)) catch |e| switch (e) {
                error.Overflow => return .{
                    .err = sexpr.Error.initIntegerLiteralOverflow(atom, 32),
                },
            };

            return .{ .ok = Ident.initNumeric(atom, n) };
        },
        else => return .{
            .err = sexpr.Error.initExpectedToken(sexpr.Value.initAtom(atom), .id, .at_value),
        },
    }
}

pub fn parse(
    parser: *sexpr.Parser,
    tree: *const sexpr.Tree,
    cache_allocator: Allocator,
    cache: *Cache,
) Allocator.Error!sexpr.Parser.Result(Ident) {
    var lookahead = parser.*;
    const atom = (lookahead.parseValue() catch return .{ .ok = Ident.none }).getAtom() orelse
        return .{ .ok = Ident.none };

    switch (atom.tag(tree)) {
        .id => {
            parser.* = lookahead;
            const ident = try cache.intern(cache_allocator, tree, atom);
            return .{ .ok = Ident.initSymbolic(atom, ident) };
        },
        .integer => {
            parser.* = lookahead;
            const n = value.unsignedInteger(u32, atom.contents(tree)) catch |e| switch (e) {
                error.Overflow => return .{
                    .err = sexpr.Error.initIntegerLiteralOverflow(atom, 32),
                },
            };

            return .{ .ok = Ident.initNumeric(atom, n) };
        },
        else => return .{ .ok = Ident.none },
    }
}

pub const Interned = enum(u32) {
    _,

    pub fn get(id: Interned, tree: *const sexpr.Tree, cache: *const Cache) []const u8 {
        return Cache.idTokenContents(tree, cache.lookup.keys()[@intFromEnum(id)]);
    }
};

pub const Cache = struct {
    fn idTokenContents(tree: *const sexpr.Tree, tok: sexpr.TokenId) []const u8 {
        std.debug.assert(tok.tag(tree) == .id);
        return tok.contents(tree)[1..];
    }

    const LookupContext = struct {
        tree: *const sexpr.Tree,
        // hash_seed: u64,

        pub fn eql(ctx: LookupContext, a: sexpr.TokenId, b: sexpr.TokenId, _: usize) bool {
            return std.mem.eql(u8, idTokenContents(ctx.tree, a), idTokenContents(ctx.tree, b));
        }

        pub fn hash(ctx: LookupContext, key: sexpr.TokenId) u32 {
            return @truncate(std.hash.Wyhash.hash(0, idTokenContents(ctx.tree, key)));
        }
    };

    lookup: std.ArrayHashMapUnmanaged(sexpr.TokenId, void, LookupContext, true),
    // hash_seed: u64,

    pub const empty = Cache{ .lookup = .empty };

    pub fn intern(cache: *Cache, allocator: Allocator, tree: *const sexpr.Tree, tok: sexpr.TokenId) Allocator.Error!Interned {
        const entry = try cache.lookup.getOrPutContext(allocator, tok, .{ .tree = tree });
        if (!entry.found_existing and entry.index > std.math.maxInt(std.meta.Tag(Interned))) {
            _ = cache.lookup.pop();
            return error.OutOfMemory;
        } else {
            // `getOrPutContext` should automatically write the correct key.
            std.debug.assert(std.mem.eql(u8, tok.contents(tree), entry.key_ptr.contents(tree)));
            return @enumFromInt(@as(std.meta.Tag(Interned), @intCast(entry.index)));
        }
    }

    pub fn deinit(cache: *Cache, allocator: Allocator) void {
        cache.lookup.deinit(allocator);
    }
};
