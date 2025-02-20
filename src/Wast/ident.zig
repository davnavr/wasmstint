const std = @import("std");
const Allocator = std.mem.Allocator;
const sexpr = @import("sexpr.zig");
const ParseContext = sexpr.Parser.Context;
const value = @import("value.zig");

/// An WebAssembly [*id*entifier].
///
/// [*id*entifier]: https://webassembly.github.io/spec/core/text/values.html#text-id
pub const Ident = packed struct(u63) {
    inner_index: packed union {
        symbolic: Interned,
        numeric: u32,
    },
    token: sexpr.TokenId,

    comptime {
        std.debug.assert(@sizeOf(Ident) == 8);
    }

    /// `tok` must refer to a token with `tok.tag(tree) == .id`.
    pub fn initSymbolic(tok: sexpr.TokenId, id: Interned) Ident {
        return .{ .token = tok, .inner_index = .{ .symbolic = id } };
    }

    pub fn initNumeric(tok: sexpr.TokenId, n: u32) Ident {
        return .{ .token = tok, .inner_index = .{ .numeric = n } };
    }

    pub fn index(id: Ident, tree: *const sexpr.Tree) union(enum) { symbolic: Interned, numeric: u32 } {
        return switch (id.token.tag(tree)) {
            .integer => .{ .numeric = id.inner_index.numeric },
            .id => .{ .symbolic = id.inner_index.symbolic },
            else => unreachable,
        };
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

        pub fn intern(
            cache: *Cache,
            allocator: Allocator,
            tree: *const sexpr.Tree,
            tok: sexpr.TokenId,
        ) Allocator.Error!Interned {
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

    pub const Opt = packed struct(u64) {
        inner_ident: Ident,
        some: bool,

        comptime {
            std.debug.assert(@sizeOf(Opt) == 8);
        }

        pub const none = Opt{ .some = false, .inner_ident = undefined };

        pub fn init(id: ?Ident) Opt {
            return if (id) |ident| .{ .some = true, .inner_ident = ident } else .none;
        }

        pub inline fn get(id: Opt) ?Ident {
            return if (id.some) id.inner_ident else null;
        }

        pub fn parseAtom(
            atom: sexpr.TokenId,
            ctx: *ParseContext,
            cache_allocator: Allocator,
            cache: *Cache,
        ) sexpr.Parser.ParseError!Opt {
            switch (atom.tag(ctx.tree)) {
                .id => {
                    const ident = try cache.intern(cache_allocator, ctx.tree, atom);
                    return Opt.init(Ident.initSymbolic(atom, ident));
                },
                .integer => {
                    const n = value.unsignedInteger(u32, atom.contents(ctx.tree)) catch |e| switch (e) {
                        error.Overflow => return (try ctx.errorAtToken(
                            atom,
                            "invalid numeric",
                            @errorReturnTrace(),
                        )).err,
                    };

                    return Opt.init(Ident.initNumeric(atom, n));
                },
                else => return .none,
            }
        }

        pub fn parse(
            parser: *sexpr.Parser,
            ctx: *ParseContext,
            cache_allocator: Allocator,
            cache: *Cache,
        ) sexpr.Parser.ParseError!Opt {
            var lookahead: sexpr.Parser = parser.*;
            const atom = (lookahead.parseValue() catch return .none).getAtom() orelse return .none;
            const ident = try Opt.parseAtom(atom, ctx, cache_allocator, cache);
            if (ident.some) {
                parser.* = lookahead;
            }

            return ident;
        }
    };

    const expected_msg = "expected symbolic or numeric identifier";

    pub fn parseAtom(
        atom: sexpr.TokenId,
        ctx: *ParseContext,
        cache_allocator: Allocator,
        cache: *Cache,
    ) sexpr.Parser.ParseError!Ident {
        const ident = try Opt.parseAtom(atom, ctx, cache_allocator, cache);
        return ident.get() orelse (try ctx.errorAtToken(
            atom,
            expected_msg,
            @errorReturnTrace(),
        )).err;
    }

    pub fn parse(
        parser: *sexpr.Parser,
        ctx: *ParseContext,
        parent: sexpr.List.Id,
        cache_allocator: Allocator,
        cache: *Cache,
    ) sexpr.Parser.ParseError!Ident {
        const atom = try parser.parseAtomInList(parent, ctx, "identifier");
        const ident = try Opt.parseAtom(atom, ctx, cache_allocator, cache);
        return ident.get() orelse (try ctx.errorAtToken(
            atom,
            expected_msg,
            @errorReturnTrace(),
        )).err;
    }

    pub const Union = union(enum) {
        symbolic: Interned,
        numeric: u32,
    };

    pub fn toUnion(ident: Ident, tree: *const sexpr.Tree) Union {
        return switch (ident.token.tag(tree)) {
            .id => .{ .symbolic = ident.inner_index.symbolic },
            .integer => .{ .numeric = ident.inner_index.numeric },
            else => unreachable,
        };
    }

    pub const Symbolic = packed struct(u64) {
        ident: Interned,
        token: sexpr.TokenId,
        some: bool,

        pub const none = Symbolic{
            .some = false,
            .ident = undefined,
            .token = undefined,
        };

        pub fn parse(
            parser: *sexpr.Parser,
            tree: *const sexpr.Tree,
            cache_allocator: Allocator,
            cache: *Cache,
        ) Allocator.Error!Symbolic {
            var lookahead: sexpr.Parser = parser.*;
            const token = (lookahead.parseValue() catch return .none).getAtom() orelse return .none;
            if (token.tag(tree) != .id) return .none;

            parser.* = lookahead;
            lookahead = undefined;

            const ident = try cache.intern(cache_allocator, tree, token);
            return .{ .ident = ident, .token = token, .some = true };
        }
    };
};
