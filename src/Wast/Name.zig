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

    pub fn bytes(id: Id, interner: *const Interner) []const u8 {
        return interner.lookup.keys()[@intFromEnum(id)];
    }
};

pub const Interner = struct {
    lookup: std.StringArrayHashMapUnmanaged(void),

    pub fn intern(
        interner: *Interner,
        allocator: Allocator,
        string_arena: *std.heap.ArenaAllocator,
        token: sexpr.TokenId,
        tree: *const sexpr.Tree,
        scratch: *std.heap.ArenaAllocator,
    ) Allocator.Error!Id {
        const actual_name: []const u8 = name: {
            const quoted = quoted: {
                const contents = token.contents(tree);
                break :quoted contents[1 .. contents.len - 1];
            };

            switch (token.tag(tree)) {
                .string_literal => break :name quoted,
                .string_escaped => {
                    const buf = try value.string(quoted).allocPrint(scratch.allocator());
                    break :name try string_arena.allocator().dupe(u8, buf.items);
                },
                else => unreachable,
            }
        };

        const entry = try interner.lookup.getOrPut(allocator, actual_name);
        if (!entry.found_existing and entry.index > std.math.maxInt(std.meta.Tag(Id))) {
            interner.lookup.pop();
            return error.OutOfMemory;
        } else {
            return @enumFromInt(@as(u32, @intCast(entry.index)));
        }
    }

    pub fn deinit(interner: *Interner, allocator: Allocator) void {
        interner.lookup.deinit(allocator);
        interner.* = undefined;
    }
};
