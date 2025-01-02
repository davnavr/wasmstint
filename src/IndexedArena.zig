const std = @import("std");
const Error = std.mem.Allocator.Error;

pub const Word = enum(u32) { _ };

data: std.ArrayListAligned(Word, max_alignment),

const IndexedArena = @This();

pub const max_alignment = 16;

pub fn init(allocator: std.mem.Allocator) IndexedArena {
    return .{ .data = std.ArrayListAligned(Word, max_alignment).init(allocator) };
}

fn byteSizeToWordCount(size: usize) error{Overflow}!usize {
    return (try std.math.add(usize, size, comptime (@sizeOf(Word) - 1))) / @sizeOf(Word);
}

fn elementAlignment(natural_alignment: u29) u29 {
    return @min(@max(@as(u29, @alignOf(Word)), natural_alignment), @as(u29, max_alignment));
}

const IdxInt = u31;

pub fn Idx(comptime T: type) type {
    if (@sizeOf(T) == 0) {
        @compileError(@typeName(T) ++ " has a size of zero, which is not supported");
    }

    return enum(IdxInt) {
        _,

        const Self = @This();

        pub const elem_word_len = byteSizeToWordCount(@sizeOf(T)) catch unreachable;

        pub fn getPtr(idx: Self, arena: *const IndexedArena) *align(elementAlignment(@alignOf(T))) T {
            const words: []Word = arena.data.items[@intFromEnum(idx)..][0..elem_word_len];
            return @alignCast(@ptrCast(words.ptr));
        }

        pub fn get(idx: Self, arena: *const IndexedArena) T {
            return idx.getPtr(arena).*;
        }

        pub inline fn set(idx: Self, arena: *const IndexedArena, value: T) void {
            idx.getPtr(arena).* = value;
        }

        pub inline fn cast(idx: Self, comptime U: type) Idx(U) {
            return @enumFromInt(@as(IdxInt, @intFromEnum(idx)));
        }

        pub const Opt = packed struct(u32) {
            some: bool,
            inner_idx: Self,

            pub const none = Opt{ .some = false, .inner_idx = undefined };

            pub inline fn init(id: ?Self) Opt {
                return if (id) |some| Opt{ .some = true, .inner_idx = some } else .none;
            }

            pub inline fn get(id: Opt) ?Self {
                return if (id.some) id.inner_idx else null;
            }
        };
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

        pub fn items(self: Self, arena: *const IndexedArena) []align(elementAlignment(@alignOf(T))) T {
            const words: []Word = arena.data.items[@intFromEnum(self.idx)..][0..self.wordLen()];
            const base_ptr: [*]align(elementAlignment(@alignOf(T))) T = @alignCast(@ptrCast(words.ptr));
            return base_ptr[0..self.len];
        }

        // /// Only works if `sizeOf(T)` is exactly a multiple of `@sizeOf(Word)`.
        // pub inline fn at(self: Self, idx: usize) Idx(T) {
        //     std.debug.assert(idx < self.len);
        //     return @enumFromInt(@as(IdxInt, @intFromEnum(self.idx) + @as(IdxInt, @intCast(idx))));
        // }

        pub inline fn getPtr(self: Self, idx: usize, arena: *const IndexedArena) *align(elementAlignment(@alignOf(T))) T {
            return &self.items(arena)[idx];
        }

        pub inline fn get(self: Self, idx: usize, arena: *const IndexedArena) T {
            return self.getPtr(idx, arena).*;
        }

        pub inline fn set(self: Self, idx: usize, arena: *const IndexedArena, value: T) void {
            self.getPtr(idx, arena).* = value;
        }

        pub fn slice(self: Self, start: usize, end: usize) Self {
            std.debug.assert(start < end);
            std.debug.assert(end <= self.len);
            return .{
                .idx = @enumFromInt(@as(IdxInt, @intCast(@intFromEnum(self.idx) + start))),
                .len = @intCast(end - start),
            };
        }

        pub fn eql(self: Self, other: Self, arena: *const IndexedArena) bool {
            return (self.len == other.len and @intFromEnum(self.idx) == @intFromEnum(other.idx)) or
                std.mem.eql(T, self.items(arena), other.items(arena));
        }
    };
}

fn elementSizeWithAlignment(
    arena: *const IndexedArena,
    size: usize,
    comptime natural_alignment: u29,
) error{Overflow}!struct { align_words: usize, total_words: usize } {
    const alignment: u29 = elementAlignment(natural_alignment);
    const word_alignment = alignment / @sizeOf(Word);

    const base_word_count = try byteSizeToWordCount(size);
    const align_word_count = std.mem.alignForwardAnyAlign(usize, arena.data.items.len, word_alignment) - arena.data.items.len;

    return .{
        .total_words = try std.math.add(usize, align_word_count, base_word_count),
        .align_words = align_word_count,
    };
}

fn allocWithAlignment(arena: *IndexedArena, size: usize, comptime natural_alignment: u29) Error!Idx(Word) {
    const elem_size = arena.elementSizeWithAlignment(size, natural_alignment) catch return Error.OutOfMemory;
    const idx_after_align = std.math.add(usize, arena.data.items.len, elem_size.align_words) catch return Error.OutOfMemory;
    const base_idx = std.math.cast(IdxInt, idx_after_align) orelse return Error.OutOfMemory;

    try arena.data.appendNTimes(undefined, elem_size.total_words);
    return @enumFromInt(base_idx);
}

pub fn create(arena: *IndexedArena, comptime T: type) Error!Idx(T) {
    comptime std.debug.assert(@sizeOf(T) > 0);
    return (try arena.allocWithAlignment(@sizeOf(T), @alignOf(T))).cast(T);
}

pub fn alloc(arena: *IndexedArena, comptime T: type, n: usize) Error!Slice(T) {
    const len = std.math.cast(u32, n) orelse return Error.OutOfMemory;
    const byte_size = std.math.mul(usize, @sizeOf(T), len) catch return Error.OutOfMemory;
    const idx = try arena.allocWithAlignment(byte_size, @alignOf(T));
    return .{ .idx = idx.cast(T), .len = len };
}

// pub fn ensureUnusedCapacity(arena: *IndexedArena, comptime T: type, n: usize) Error!void {
//     const bytes = std.math.mul(usize, @sizeOf(T), n) catch return Error.OutOfMemory;
//     try arena.data.ensureUnusedCapacity(arena.elementSizeWithAlignment(bytes, @alignOf(T)) catch return Error.OutOfMemory);
// }

pub fn ensureUnusedCapacityForBytes(arena: *IndexedArena, bytes: usize) Error!void {
    try arena.data.ensureUnusedCapacity(byteSizeToWordCount(bytes) catch return Error.OutOfMemory);
}

pub fn dupe(arena: *IndexedArena, comptime T: type, m: []const T) Error!Slice(T) {
    const idx = try arena.alloc(T, m.len);
    @memcpy(idx.items(arena), m);
    return idx;
}

pub fn dupeSegmentedList(
    arena: *IndexedArena,
    comptime T: type,
    comptime prealloc_count: usize,
    list: *const std.SegmentedList(T, prealloc_count),
) Error!Slice(T) {
    const dst = try arena.alloc(T, list.count());
    @constCast(list).writeToSlice(dst.items(arena), 0);
    return dst;
}

/// Used to construct lists with a known upper bound for its length.
pub fn BoundedArrayList(comptime T: type) type {
    return struct {
        items: Slice(T),
        capacity: u32,

        const Self = @This();

        pub fn initCapacity(arena: *IndexedArena, capacity: usize) Error!Self {
            const items = try arena.alloc(T, capacity);
            errdefer comptime unreachable;
            return .{
                .items = .{ .idx = items.idx, .len = 0 },
                .capacity = items.len,
            };
        }

        pub fn appendAssumeCapacity(self: *Self, arena: *IndexedArena, item: T) void {
            std.debug.assert(self.items.len < self.capacity);
            self.items.len += 1;
            self.items.set(self.items.len - 1, arena, item);
        }
    };
}

/// Invalidates all indices into this arena.
pub fn reset(arena: *IndexedArena) void {
    arena.data.clearRetainingCapacity();
}

pub fn deinit(arena: IndexedArena) void {
    arena.data.deinit();
}

test "arena operations" {
    var arena = IndexedArena.init(std.testing.allocator);
    defer arena.deinit();

    const thing_0 = try arena.create(u32);
    thing_0.set(&arena, 42);
    try std.testing.expectEqual(*u32, @TypeOf(thing_0.getPtr(&arena)));

    const thing_1 = try arena.create(u64);
    thing_1.set(&arena, 0xABBA);
    try std.testing.expectEqual(*u64, @TypeOf(thing_1.getPtr(&arena)));

    const str = try arena.dupe(u8, "Hello!");

    try std.testing.expectEqual(42, thing_0.get(&arena));
    try std.testing.expectEqualStrings("Hello!", str.items(&arena));
    try std.testing.expectEqual(0xABBA, thing_1.get(&arena));
    try std.testing.expectEqual(6, arena.data.items.len);
    try std.testing.expectEqual('o', str.get(4, &arena));
}
