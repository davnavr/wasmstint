//! A WebAssembly [*name*], a UTF-8 string literal.
//!
//! [*name*]: https://webassembly.github.io/spec/core/text/values.html#names

const std = @import("std");
const Allocator = std.mem.Allocator;
const IndexedArena = @import("../IndexedArena.zig");
const sexpr = @import("sexpr.zig");
const value = @import("value.zig");

token: sexpr.TokenId,
id: Id,

const Name = @This();

pub const Id = enum(u32) {
    _,

    pub fn bytes(id: Id, arena: *const IndexedArena, cache: *const Cache) []const u8 {
        return cache.lookup.keys()[@intFromEnum(id)].slice(arena);
    }
};

pub const Cache = struct {
    const String = @import("String.zig");

    const LookupContext = struct {
        arena: *const IndexedArena,
        // hash_seed: u64,

        pub fn eql(ctx: LookupContext, a: []const u8, b: String, _: usize) bool {
            return (a.len == b.len) and std.mem.eql(u8, a, b.slice(ctx.arena));
        }

        pub fn hash(_: LookupContext, key: []const u8) u32 {
            return @truncate(std.hash.Wyhash.hash(0, key));
        }
    };

    lookup: std.ArrayHashMapUnmanaged(String, void, void, true),
    // hash_seed: u64,

    pub const empty = Cache{ .lookup = .empty };

    pub fn intern(
        cache: *Cache,
        allocator: Allocator,
        arena: *IndexedArena,
        token: sexpr.TokenId,
        tree: *const sexpr.Tree,
        scratch: *std.heap.ArenaAllocator,
    ) error{ OutOfMemory, InvalidUtf8 }!Id {
        const actual_name: struct { bytes: []const u8, allocate: bool } = name: {
            const quoted = quoted: {
                const contents = token.contents(tree);
                break :quoted contents[1 .. contents.len - 1];
            };

            switch (token.tag(tree)) {
                .string => break :name .{ .bytes = quoted, .allocate = false },
                .string_raw => {
                    _ = scratch.reset(.retain_capacity);
                    const buf = try value.string(quoted).allocPrint(scratch.allocator());
                    if (!std.unicode.utf8ValidateSlice(buf.items)) return error.InvalidUtf8;
                    break :name .{ .bytes = buf.items, .allocate = true };
                },
                else => unreachable,
            }
        };

        const name_len = std.math.cast(u32, actual_name.bytes.len) orelse return error.OutOfMemory;

        const entry = try cache.lookup.getOrPutAdapted(
            allocator,
            actual_name.bytes,
            LookupContext{ .arena = arena },
        );

        if (!entry.found_existing) {
            errdefer _ = cache.lookup.pop();
            if (entry.index > std.math.maxInt(std.meta.Tag(Id))) return error.OutOfMemory;

            entry.key_ptr.* = String{
                .len = name_len,
                .ptr = if (actual_name.allocate) null else actual_name.bytes.ptr,
                .idx = if (actual_name.allocate)
                    (try arena.dupe(u8, actual_name.bytes)).idx
                else
                    undefined,
            };
        }

        return @enumFromInt(@as(u32, @intCast(entry.index)));
    }
};

pub fn parse(
    parser: *sexpr.Parser,
    tree: *const sexpr.Tree,
    cache_allocator: Allocator,
    cache: *Cache,
    arena: *IndexedArena,
    parent: sexpr.List.Id,
    scratch: *std.heap.ArenaAllocator,
) Allocator.Error!sexpr.Parser.Result(Name) {
    const atom: sexpr.TokenId = switch (parser.parseAtomInList(.string, parent)) {
        .ok => |ok| ok,
        .err => |err| return .{ .err = err },
    };

    switch (atom.tag(tree)) {
        .string, .string_raw => {
            const id = cache.intern(cache_allocator, arena, atom, tree, scratch) catch |e| return switch (e) {
                error.OutOfMemory => |oom| oom,
                error.InvalidUtf8 => .{ .err = sexpr.Error.initInvalidUtf8(atom) },
            };

            return .{ .ok = .{ .token = atom, .id = id } };
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

comptime {
    std.debug.assert(@sizeOf(Name) == 8);
    std.debug.assert(@alignOf(Name) == 4);
}
