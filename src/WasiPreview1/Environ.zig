//! Environment variable data to pass to the application.

ptr: [*]const Pair,
count: u32,
/// Total size, in bytes, of all argument data including null-terminators.
size: u32,

const Environ = @This();

pub const empty = Environ{
    .ptr = @as([]const Pair, &.{}).ptr,
    .count = 0,
    .size = 0,
};

pub fn entries(environ: Environ) []const Pair {
    std.debug.assert(environ.size >= environ.count);
    return environ.ptr[0..environ.count];
}

pub const Pair = struct {
    /// Invariant that this contains at least one (1) equals (`=`) character.
    ///
    /// `Char` guarantees no null-terminators are present.
    ptr: [*]const Char,
    len: u32,
    key_len: u32,

    pub const max_len = std.math.maxInt(u32) - 1; // only need room for null-terminator

    fn checkInvariants(pair: Pair) void {
        std.debug.assert(pair.len <= max_len);
        std.debug.assert(pair.key_len < pair.len);
        std.debug.assert(pair.ptr[pair.key_len] == .@"=");
    }

    /// Takes a slice of the given string (with the length truncated to `max_len`) up to the first
    /// encountered null-terminator (`\x00`), and splits it into a key/value pair separated by
    /// an equals sign ('=').
    pub fn initTruncated(s: []const u8) error{MissingEqualsSign}!Pair {
        const trunc = std.mem.sliceTo(s[0..@min(max_len, s.len)], 0);
        const key = std.mem.sliceTo(trunc, '=');
        if (key.len == trunc.len) {
            return error.MissingEqualsSign;
        }

        std.debug.assert(trunc[key.len] == '=');
        const pair = Pair{
            .ptr = @ptrCast(trunc.ptr),
            .len = @intCast(trunc.len),
            .key_len = @intCast(key.len),
        };
        pair.checkInvariants();
        return pair;
    }

    fn chars(pair: Pair) []const Char {
        pair.checkInvariants();
        return @ptrCast(pair.ptr[0..pair.len]);
    }

    pub fn bytes(pair: Pair) []const u8 {
        return @ptrCast(pair.chars());
    }

    pub fn lenWithNullTerminator(pair: Pair) u32 {
        pair.checkInvariants();
        return pair.len;
    }

    pub fn dupe(pair: Pair, allocator: Allocator) Allocator.Error!Pair {
        const new = Pair{
            .ptr = (try allocator.dupe(Char, pair.chars())).ptr,
            .len = pair.len,
            .key_len = pair.key_len,
        };
        new.checkInvariants();
        return new;
    }

    /// Names are not allowed to contain an equals sign (`=`) character or a null-terminator
    /// (`\x00`).
    pub fn name(pair: Pair) [:'=']const u8 {
        return pair.bytes()[0..pair.key_len :'='];
    }

    pub fn value(pair: Pair) []const u8 {
        pair.checkInvariants();
        return pair.bytes()[pair.key_len + 1 ..];
    }

    pub fn format(pair: Pair, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        return writer.writeAll(pair.bytes());
    }
};

/// Growable `Environ` list.
pub const List = struct {
    ptr: [*]Pair,
    count: u32,
    size: u32,
    /// How many `Pair`s can be stored before a reallocation is needed.
    capacity: u32,

    pub const empty = List{
        .ptr = @as([]Pair, &.{}).ptr,
        .count = 0,
        .size = 0,
        .capacity = 0,
    };

    const initial_capacity = std.atomic.cache_line / @sizeOf(Pair);

    fn allocatedSlice(list: *const List) []Pair {
        std.debug.assert(list.count <= list.capacity);
        return list.ptr[0..list.capacity];
    }

    fn slice(list: *const List) []Pair {
        return list.allocatedSlice()[0..list.count];
    }

    fn grow(list: *List, allocator: Allocator) Allocator.Error!void {
        std.debug.assert(list.count == list.capacity);
        const new_capacity = @max(
            initial_capacity,
            std.math.mul(u32, list.capacity, 2) catch return error.OutOfMemory,
        );
        std.debug.assert(list.count + 1 <= new_capacity);

        const old = list.allocatedSlice();
        if (allocator.remap(old, new_capacity)) |remap| {
            list.ptr = remap.ptr;
            std.debug.assert(remap.len == new_capacity);
        } else {
            const new = try allocator.alloc(Pair, new_capacity);
            @memcpy(new[0..list.count], old[0..list.count]);
            allocator.free(old);
            list.ptr = new.ptr;
            std.debug.assert(new.len == new_capacity);
        }
        list.capacity = new_capacity;
    }

    pub fn append(list: *List, allocator: Allocator, pair: Pair) Allocator.Error!void {
        const new_count = std.math.add(u32, list.count, 1) catch return error.OutOfMemory;
        const new_size = std.math.add(u32, list.size, pair.lenWithNullTerminator()) catch
            return error.OutOfMemory; // bad new size

        if (list.count == list.capacity) {
            @branchHint(.unlikely);
            try list.grow(allocator);
        }

        list.allocatedSlice()[list.count] = pair;
        list.count = new_count;
        list.size = new_size;
    }

    pub fn at(list: *List, idx: u32) Pair {
        return list.slice()[idx];
    }

    pub fn replaceAt(list: *List, idx: u32, with: Pair) Allocator.Error!Pair {
        const elem = &list.slice()[idx];
        const existing = elem.*;
        list.size = std.math.add(u32, list.size - existing.len(), with.len()) catch
            return error.OutOfMemory; // total size overflow
        elem.* = with;
        return existing;
    }

    pub fn environ(list: *const List) Environ {
        return .{
            .ptr = list.ptr,
            .count = list.count,
            .size = list.size,
        };
    }

    pub fn dupe(list: *const List, allocator: Allocator) Allocator.Error!List {
        return .{
            .ptr = (try allocator.dupe(Pair, list.slice())).ptr,
            .count = list.count,
            .size = list.size,
            .capacity = list.count,
        };
    }
};

const std = @import("std");
const Allocator = std.mem.Allocator;
const Char = @import("char.zig").Char;
