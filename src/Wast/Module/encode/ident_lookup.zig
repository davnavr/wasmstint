const std = @import("std");
const ArenaAllocator = std.heap.ArenaAllocator;
const IndexedArena = @import("../../../IndexedArena.zig");
const Wast = @import("../../../Wast.zig");
const sexpr = Wast.sexpr;
const Error = sexpr.Error;
const Ident = Wast.Ident;
const Text = Wast.Module.Text;

pub const RawIdentLookup = struct {
    map: std.AutoHashMapUnmanaged(Ident.Interned, Value),

    const Value = struct { id: sexpr.TokenId, index: u32 };

    const empty = RawIdentLookup{ .map = .empty };

    fn insert(
        lookup: *RawIdentLookup,
        id: Ident.Symbolic,
        index: u32,
        alloca: *ArenaAllocator,
        errors: *Error.List,
    ) error{OutOfMemory}!void {
        if (!id.some) return;

        const entry = try lookup.map.getOrPut(alloca.allocator(), id.ident);
        if (entry.found_existing) {
            try errors.append(Error.initDuplicateIdent(id, entry.value_ptr.id));
        } else {
            entry.value_ptr.* = Value{ .id = id.token, .index = index };
        }
    }

    fn get(lookup: *const RawIdentLookup, id: Ident.Interned, token: sexpr.TokenId) sexpr.Parser.Result(u32) {
        return if (lookup.map.get(id)) |value|
            .{ .ok = value.index }
        else
            .{ .err = Error.initUndefinedIdent(token) };
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
            id: Ident.Symbolic,
            index: Idx,
            alloca: *ArenaAllocator,
            errors: *Error.List,
        ) error{OutOfMemory}!void {
            return lookup.inner.insert(id, @intFromEnum(index), alloca, errors);
        }

        pub fn get(lookup: *const Self, id: Ident.Interned, token: sexpr.TokenId) sexpr.Parser.Result(Idx) {
            return switch (lookup.inner.get(id, token)) {
                .ok => |raw_idx| .{ .ok = @enumFromInt(raw_idx) },
                .err => |err| .{ .err = err },
            };
        }
    };
}
