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
},

const Ident = @This();

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

pub fn parse(
    parser: *sexpr.Parser,
    tree: *const sexpr.Tree,
    cache: *Cache,
    cache_allocator: Allocator,
) Allocator.Error!sexpr.Parser.Result(Ident) {
    var lookahead = parser.*;
    const atom = (lookahead.parseValue() catch return .{ .ok = Ident.none }).getAtom() orelse
        return .{ .ok = Ident.none };

    const contents = atom.contents(tree);
    switch (atom.tag(tree)) {
        .id => {
            parser.* = lookahead;
            const ident = try cache.intern(contents[1..], cache_allocator);
            return .{ .ok = Ident.initSymbolic(atom, ident) };
        },
        .integer => {
            parser.* = lookahead;
            const n = value.unsignedInteger(u32, contents) catch |e| switch (e) {
                error.Overflow => return .{
                    .err = sexpr.Error.initIntegerLiteralOverflow(sexpr.Value.initAtom(atom), 32),
                },
            };

            return .{ .ok = Ident.initNumeric(atom, n) };
        },
        else => return .{ .ok = Ident.none },
    }
}

pub const Interned = enum(u32) {
    _,

    pub fn get(id: Interned, cache: *const Cache) []const u8 {
        return cache.lookup.keys()[@intFromEnum(id)];
    }
};

pub const Cache = struct {
    lookup: std.StringArrayHashMapUnmanaged(void),

    pub const empty = Cache{ .lookup = .empty };

    pub fn intern(cache: *Cache, ident: []const u8, gpa: Allocator) Allocator.Error!Interned {
        const entry = try cache.lookup.getOrPut(gpa, ident);
        if (!entry.found_existing and entry.index > std.math.maxInt(std.meta.Tag(Interned))) {
            _ = cache.lookup.pop();
            return error.OutOfMemory;
        } else {
            return @enumFromInt(@as(std.meta.Tag(Interned), @intCast(entry.index)));
        }
    }

    pub fn deinit(cache: *Cache, gpa: Allocator) void {
        cache.lookup.deinit(gpa);
        cache.* = undefined;
    }
};
