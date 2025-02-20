const std = @import("std");
const ArenaAllocator = std.heap.ArenaAllocator;
const IndexedArena = @import("../../../IndexedArena.zig");
const Wast = @import("../../../Wast.zig");
const sexpr = Wast.sexpr;
const Ident = Wast.Ident;
const Text = Wast.Module.Text;

pub const RawIdentLookup = struct {
    map: std.AutoHashMapUnmanaged(Ident.Interned, Value),

    const Value = struct { id: sexpr.TokenId, index: u32 };

    const empty = RawIdentLookup{ .map = .empty };

    fn insert(
        lookup: *RawIdentLookup,
        ctx: *sexpr.Parser.Context,
        id: Ident.Symbolic,
        index: u32,
        alloca: *ArenaAllocator,
    ) std.mem.Allocator.Error!void {
        if (!id.some) return;

        const entry = try lookup.map.getOrPut(alloca.allocator(), id.ident);
        if (entry.found_existing) {
            _ = try ctx.errorAtToken(
                id.token,
                "identifier defined twice (TODO: include original location)",
                @errorReturnTrace(),
            );
        } else {
            entry.value_ptr.* = Value{ .id = id.token, .index = index };
        }
    }

    fn get(
        lookup: *const RawIdentLookup,
        ctx: *sexpr.Parser.Context,
        id: Ident.Interned,
        token: sexpr.TokenId,
    ) sexpr.Parser.ParseError!u32 {
        return if (lookup.map.get(id)) |value|
            value.index
        else
            (try ctx.errorAtToken(
                token,
                "undefined variable",
                @errorReturnTrace(),
            )).err;
    }
};

/// Maps an interned symbolic identifier to where it is first defined.
///
/// Note that the text format requires that all imports come before all definitions.
pub fn IdentLookup(comptime Idx: type) type {
    return struct {
        inner: RawIdentLookup,

        const Self = @This();

        pub const empty = Self{ .inner = .empty };

        pub fn insert(
            lookup: *Self,
            ctx: *sexpr.Parser.Context,
            id: Ident.Symbolic,
            index: Idx,
            alloca: *ArenaAllocator,
        ) error{OutOfMemory}!void {
            return lookup.inner.insert(ctx, id, @intFromEnum(index), alloca);
        }

        pub fn get(
            lookup: *const Self,
            ctx: *sexpr.Parser.Context,
            id: Ident.Interned,
            token: sexpr.TokenId,
        ) sexpr.Parser.ParseError!Idx {
            return @enumFromInt(try lookup.inner.get(ctx, id, token));
        }

        pub fn getFromIdent(
            lookup: *const Self,
            ctx: *sexpr.Parser.Context,
            ident: Ident,
        ) std.mem.Allocator.Error!Idx {
            return switch (ident.toUnion(ctx.tree)) {
                .symbolic => |interned| lookup.get(ctx, interned, ident.token) catch |e| switch (e) {
                    error.OutOfMemory => |oom| oom,
                    error.ReportedParserError => Idx.probably_invalid,
                },
                .numeric => |idx| @enumFromInt(idx),
            };
        }
    };
}
