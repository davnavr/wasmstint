//! A WebAssembly [*name*], a UTF-8 string literal.
//!
//! [*name*]: https://webassembly.github.io/spec/core/text/values.html#names

const std = @import("std");
const sexpr = @import("sexpr.zig");
const value = @import("value.zig");
const Arenas = @import("Arenas.zig");

token: sexpr.TokenId,
id: Id,

const Name = @This();

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
        arenas: *Arenas,
        token: sexpr.TokenId,
        tree: *const sexpr.Tree,
    ) error{ OutOfMemory, InvalidUtf8 }!Id {
        const actual_name: []const u8 = name: {
            const quoted = quoted: {
                const contents = token.contents(tree);
                break :quoted contents[1 .. contents.len - 1];
            };

            switch (token.tag(tree)) {
                .string => break :name quoted,
                .string_raw => {
                    _ = arenas.scratch.reset(.retain_capacity);
                    const buf = try value.string(quoted).allocPrint(arenas.scratch.allocator());
                    if (!std.unicode.utf8ValidateSlice(buf.items)) return error.InvalidUtf8;
                    break :name try arenas.out.allocator().dupe(u8, buf.items);
                },
                else => unreachable,
            }
        };

        const entry = try cache.lookup.getOrPut(arenas.parse.allocator(), actual_name);
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

    pub fn entries(cache: *const Cache, arena: *std.heap.ArenaAllocator) error{OutOfMemory}!Entries {
        return .{ .names = try arena.allocator().dupe([]const u8, cache.lookup.keys()) };
    }

    pub const Entries = struct {
        names: []const []const u8,
    };
};

pub fn parse(
    parser: *sexpr.Parser,
    tree: *const sexpr.Tree,
    arenas: *Arenas,
    cache: *Cache,
    parent: sexpr.List.Id,
) error{OutOfMemory}!sexpr.Parser.Result(Name) {
    const atom: sexpr.TokenId = switch (parser.parseAtomInList(.string, parent)) {
        .ok => |ok| ok,
        .err => |err| return .{ .err = err },
    };

    switch (atom.tag(tree)) {
        .string, .string_raw => {
            const id = cache.intern(arenas, atom, tree) catch |e| return switch (e) {
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

// TODO: Remove, this is unused!
pub const Opt = struct {
    inner: packed struct(u64) {
        is_some: bool,
        token: sexpr.TokenId,
        id: Id,
    } align(@alignOf(u32)),

    pub const none = Opt{
        .inner = .{
            .is_some = false,
            .token = undefined,
            .id = undefined,
        },
    };

    pub fn init(name: ?Name) Opt {
        return if (name) |some| .{
            .inner = .{
                .is_some = true,
                .token = some.token,
                .id = some.id,
            },
        } else .none;
    }

    pub fn option(opt: Opt) ?Name {
        return if (opt.inner.is_some) Name{
            .token = opt.inner.token,
            .id = opt.inner.id,
        } else null;
    }
};

comptime {
    std.debug.assert(@sizeOf(Name) == 8);
    std.debug.assert(@alignOf(Name) == 4);
}
