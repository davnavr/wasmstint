//! A WebAssembly [*name*], a UTF-8 string literal.
//!
//! [*name*]: https://webassembly.github.io/spec/core/text/values.html#names

const std = @import("std");
const Allocator = std.mem.Allocator;
const sexpr = @import("sexpr.zig");
const value = @import("value.zig");

token: sexpr.TokenId,
id: Id,

pub const Id = enum(u32) {
    _,

    pub fn bytes(id: Id, cache: *const Cache) []const u8 {
        return cache.lookup.keys()[@intFromEnum(id)];
    }
};

pub const Cache = struct {
    lookup: std.StringArrayHashMapUnmanaged(void),

    pub const empty = Cache{ .lookup = .empty };

    pub fn intern(
        cache: *Cache,
        allocator: Allocator,
        string_arena: *std.heap.ArenaAllocator,
        token: sexpr.TokenId,
        tree: *const sexpr.Tree,
        scratch: *std.heap.ArenaAllocator,
    ) error{ OutOfMemory, InvalidUtf8 }!Id {
        const actual_name: []const u8 = name: {
            const quoted = quoted: {
                const contents = token.contents(tree);
                break :quoted contents[1 .. contents.len - 1];
            };

            switch (token.tag(tree)) {
                .string => break :name quoted,
                .string_raw => {
                    const buf = try value.string(quoted).allocPrint(scratch.allocator());
                    if (!std.unicode.utf8ValidateSlice(buf.items)) return error.InvalidUtf8;
                    break :name try string_arena.allocator().dupe(u8, buf.items);
                },
                else => unreachable,
            }
        };

        const entry = try cache.lookup.getOrPut(allocator, actual_name);
        if (!entry.found_existing and entry.index > std.math.maxInt(std.meta.Tag(Id))) {
            cache.lookup.pop();
            return error.OutOfMemory;
        } else {
            return @enumFromInt(@as(u32, @intCast(entry.index)));
        }
    }

    pub fn deinit(cache: *Cache, allocator: Allocator) void {
        cache.lookup.deinit(allocator);
        cache.* = undefined;
    }
};

pub fn parse(
    values: *[]const sexpr.Value,
    tree: *const sexpr.Tree,
    cache_allocator: Allocator,
    cache_string_arena: *std.heap.ArenaAllocator,
    cache: *Cache,
    scratch: *std.heap.ArenaAllocator,
) error{ OutOfMemory, EndOfStream, InvalidUtf8, InvalidParse }!Id {
    const atom = try sexpr.parseAtom(values);
    return switch (atom.tag(tree)) {
        .string, .string_raw => try cache.intern(
            cache_allocator,
            cache_string_arena,
            atom,
            tree,
            scratch,
        ),
        else => error.InvalidParse,
    };
}
