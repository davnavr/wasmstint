const std = @import("std");
const Allocator = std.mem.Allocator;
const Error = Allocator.Error;

pub const Word = enum(u32) { _ };

data: std.ArrayListAlignedUnmanaged(Word, max_alignment),

const IndexedArena = @This();

pub const empty = IndexedArena{ .data = .empty };

pub const max_alignment = 16;

fn byteSizeToWordCount(size: usize) error{Overflow}!usize {
    return (try std.math.add(usize, size, comptime (@sizeOf(Word) - 1))) / @sizeOf(Word);
}

pub fn Idx(comptime T: type) type {
    if (@sizeOf(T) == 0) {
        @compileError(@typeName(T) ++ " has a size of zero, which is not supported");
    }

    return enum(u32) {
        _,

        const Self = @This();

        pub const elem_word_len = byteSizeToWordCount(@sizeOf(T)) catch unreachable;

        pub fn getPtr(idx: Self, arena: *const IndexedArena) *align(@min(@max(@alignOf(Word), @alignOf(T)), max_alignment)) T {
            const words: []Word = arena.data.items[@intFromEnum(idx)..][0..elem_word_len];
            return @alignCast(@ptrCast(words.ptr));
        }

        pub inline fn get(idx: Self, arena: *const IndexedArena) T {
            return idx.getPtr(arena).*;
        }

        pub inline fn cast(idx: Self, comptime U: type) Idx(U) {
            return @enumFromInt(@intFromEnum(idx));
        }
    };
}

pub fn Slice(comptime T: type) type {
    return struct {
        idx: Idx(T),
        len: u32,

        const Self = @This();

        pub const empty = Self{ .idx = @enumFromInt(0), .len = 0 };

        fn byteSize(self: Self) usize {
            // When slice is constructed, this is already checked to ensure no overflow occurs.
            return @sizeOf(T) * @as(usize, self.len);
        }

        fn wordLen(self: Self) usize {
            // Construction of slice ensures whole slice fits in a valid number of `Word`s.
            return byteSizeToWordCount(self.byteSize()) catch unreachable;
        }

        pub fn slice(self: Self, arena: *const IndexedArena) []align(@alignOf(Word)) T {
            const words: []Word = arena.data.items[@intFromEnum(self.idx)..][0..self.wordLen()];
            const base_ptr: [*]align(@alignOf(Word)) T = @ptrCast(words.ptr);
            return base_ptr[0..self.len];
        }
    };
}

fn allocWithAlignment(arena: *IndexedArena, allocator: Allocator, size: usize, comptime natural_alignment: u29) Error!Idx(Word) {
    std.debug.assert(size > 0);

    const alignment: u29 = @min(@as(u29, max_alignment), @max(natural_alignment, @alignOf(Word)));
    const word_alignment = alignment / @sizeOf(Word);

    const base_word_count = byteSizeToWordCount(size) catch return Error.OutOfMemory;
    const align_word_count = std.mem.alignForwardAnyAlign(usize, arena.data.items.len, word_alignment) - arena.data.items.len;
    const total_word_count = std.math.add(usize, align_word_count, base_word_count) catch return Error.OutOfMemory;

    const idx_after_align = std.math.add(usize, arena.data.items.len, align_word_count) catch return Error.OutOfMemory;
    const base_idx = std.math.cast(u32, idx_after_align) orelse return Error.OutOfMemory;

    try arena.data.appendNTimes(allocator, undefined, total_word_count);
    return @enumFromInt(base_idx);
}

pub fn create(arena: *IndexedArena, allocator: Allocator, comptime T: type) Error!Idx(T) {
    return (try arena.allocWithAlignment(allocator, @sizeOf(T), @alignOf(T))).cast(T);
}

pub fn alloc(arena: *IndexedArena, allocator: Allocator, comptime T: type, n: anytype) Error!Slice(T) {
    const len = std.math.cast(u32, n) orelse return Error.OutOfMemory;
    const byte_size = std.math.mul(usize, @sizeOf(T), len) catch return Error.OutOfMemory;
    const idx = try arena.allocWithAlignment(allocator, byte_size, @alignOf(T));
    return .{ .idx = idx.cast(T), .len = len };
}

pub fn dupe(arena: *IndexedArena, allocator: Allocator, comptime T: type, m: []const T) Error!Slice(T) {
    const idx = try arena.alloc(allocator, T, m.len);
    @memcpy(idx.slice(arena), m);
    return idx;
}

/// Invalidates all indices into this arena.
pub fn reset(arena: *IndexedArena) void {
    arena.data.clearRetainingCapacity();
}

pub fn deinit(arena: *IndexedArena, allocator: Allocator) void {
    arena.data.deinit(allocator);
}

test {
    var arena = IndexedArena.empty;
    defer arena.deinit(std.testing.allocator);

    const thing_0 = try arena.create(std.testing.allocator, u32);
    thing_0.getPtr(&arena).* = 42;
    try std.testing.expectEqual(*u32, @TypeOf(thing_0.getPtr(&arena)));

    const thing_1 = try arena.create(std.testing.allocator, u64);
    thing_1.getPtr(&arena).* = 0xABBA;
    try std.testing.expectEqual(*u64, @TypeOf(thing_1.getPtr(&arena)));

    const str = try arena.dupe(std.testing.allocator, u8, "Hello!");

    try std.testing.expectEqual(42, thing_0.get(&arena));
    try std.testing.expectEqualStrings("Hello!", str.slice(&arena));
    try std.testing.expectEqual(0xABBA, thing_1.get(&arena));
    try std.testing.expectEqual(6, arena.data.items.len);
}
