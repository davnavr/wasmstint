//! A WebAssembly [*name*], a UTF-8 string literal.
//!
//! [*name*]: https://webassembly.github.io/spec/core/text/values.html#names

const std = @import("std");
const Allocator = std.mem.Allocator;
const ArenaAllocator = std.heap.ArenaAllocator;
const sexpr = @import("sexpr.zig");
const value = @import("value.zig");

token: sexpr.TokenId,
id: Id,

pub const Id = enum(u32) {
    _,

    pub fn bytes(id: Id, cache: Cache.Entries) []const u8 {
        return cache.names[@intFromEnum(id)];
    }
};

pub const Cache = struct {
    lookup: std.StringArrayHashMapUnmanaged(void),

    pub const empty = Cache{ .lookup = .empty };

    pub fn intern(
        cache: *Cache,
        arena: *ArenaAllocator,
        token: sexpr.TokenId,
        name_arena: *ArenaAllocator,
        tree: *const sexpr.Tree,
        scratch: *ArenaAllocator,
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
                    break :name try name_arena.allocator().dupe(u8, buf.items);
                },
                else => unreachable,
            }
        };

        const entry = try cache.lookup.getOrPut(arena.allocator(), actual_name);
        if (!entry.found_existing and entry.index > std.math.maxInt(std.meta.Tag(Id))) {
            _ = cache.lookup.pop();
            return error.OutOfMemory;
        } else {
            return @enumFromInt(@as(u32, @intCast(entry.index)));
        }
    }

    pub fn get(cache: *const Cache, id: Id) []const u8 {
        return cache.lookup.keys()[@intFromEnum(id)];
    }

    pub fn entries(cache: *const Cache, arena: *ArenaAllocator) Allocator.Error!Entries {
        return .{ .names = try arena.allocator().dupe([]const u8, cache.lookup.keys()) };
    }

    pub const Entries = struct {
        names: []const []const u8,
    };
};

pub fn parse(
    parser: *sexpr.Parser,
    tree: *const sexpr.Tree,
    cache_arena: *ArenaAllocator,
    cache: *Cache,
    name_arena: *ArenaAllocator,
    parent: sexpr.List.Id,
    scratch: *ArenaAllocator,
) error{OutOfMemory}!sexpr.Parser.Result(Id) {
    const atom: sexpr.TokenId = switch (parser.parseAtomInList(.string, parent)) {
        .ok => |ok| ok,
        .err => |err| return .{ .err = err },
    };

    switch (atom.tag(tree)) {
        .string, .string_raw => {
            const id = cache.intern(cache_arena, atom, name_arena, tree, scratch) catch |e| return switch (e) {
                error.OutOfMemory => |oom| oom,
                error.InvalidUtf8 => .{ .err = sexpr.Error.initInvalidUtf8(sexpr.Value.initAtom(atom)) },
            };

            return .{ .ok = id };
        },
        else => return .{
            .err = sexpr.Error.initExpectedToken(
                sexpr.Value.initAtom(atom),
                .string,
                .at_value,
            ),
        },
    }
}
