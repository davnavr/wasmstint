/// A string allocated in an `IndexedArena`, or one already present in a WASM binary.
const std = @import("std");
const IndexedArena = @import("../IndexedArena.zig");

len: u32,
idx: IndexedArena.Idx(u8),
ptr: ?[*]const u8,

const String = @This();

pub fn slice(s: *const String, arena: anytype) []const u8 {
    return if (s.ptr) |ptr|
        ptr[0..s.len]
    else
        (IndexedArena.Slice(u8){ .idx = s.idx, .len = s.len }).items(arena);
}

pub fn initSlice(s: []const u8) error{OutOfMemory}!String {
    return .{
        .len = std.math.cast(u32, s.len) orelse return error.OutOfMemory,
        .idx = undefined,
        .ptr = s.ptr,
    };
}

pub fn initAllocated(s: IndexedArena.Slice(u8)) String {
    return .{
        .len = s.len,
        .idx = s.idx,
        .ptr = null,
    };
}
