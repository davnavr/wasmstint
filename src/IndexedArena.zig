const std = @import("std");
const Error = std.mem.Allocator.Error;

pub const Word = enum(u32) { _ };

data: std.ArrayListAligned(Word, max_alignment),

const IndexedArena = @This();

pub const min_alignment = @alignOf(Word);
pub const max_alignment = 16;

comptime {
    std.debug.assert(min_alignment < max_alignment);
}

pub fn init(allocator: std.mem.Allocator) IndexedArena {
    return .{ .data = std.ArrayListAligned(Word, max_alignment).init(allocator) };
}

pub fn byteSizeToWordCount(size: usize) Error!usize {
    return (std.math.add(usize, size, comptime (@sizeOf(Word) - 1)) catch return Error.OutOfMemory) / @sizeOf(Word);
}

/// Selects an alignment between the minimum and maximum that is closest to the desired alignment.
pub fn arenaAlignment(desired_alignment: u8) u8 {
    return @min(@max(@as(u8, min_alignment), desired_alignment), @as(u8, max_alignment));
}

pub const IdxInt = u31;

fn IdxPtr(
    comptime Arena: type,
    comptime size: std.builtin.Type.Pointer.Size,
    comptime alignment: u8,
    comptime Child: type,
) type {
    return @Type(.{
        .pointer = .{
            .size = size,
            .is_const = switch (Arena) {
                *IndexedArena => false,
                *const IndexedArena => true,
                else => unreachable,
            },
            .is_volatile = false,
            .alignment = alignment,
            .address_space = .generic,
            .child = Child,
            .is_allowzero = false,
            .sentinel = null,
        },
    });
}

/// A word offset into an `IndexedArena` pointing to a value of type `T` with the given `alignment`.
pub fn IdxAligned(comptime T: type, comptime alignment: u8) type {
    if (@sizeOf(T) == 0) {
        @compileError(@typeName(T) ++ " has a size of zero, which is not supported");
    }

    if (alignment < min_alignment) {
        @compileError(@typeName(T) ++ " has an alignment that is too small");
    }

    if (max_alignment < alignment) {
        @compileError(@typeName(T) ++ " has an alignment that is too large");
    }

    return enum(IdxInt) {
        _,

        const Self = @This();

        comptime {
            std.debug.assert(@sizeOf(Self) == 4);
        }

        pub inline fn fromInt(int: IdxInt) Self {
            std.debug.assert((int * @sizeOf(Word)) % alignment == 0);
            return @enumFromInt(int);
        }

        pub fn Ptr(comptime Arena: type) type {
            return IdxPtr(Arena, .One, alignment, T);
        }

        /// The length, in words, of the data pointed to.
        pub const word_len = byteSizeToWordCount(@sizeOf(T)) catch unreachable;

        pub inline fn getPtr(idx: Self, arena: anytype) Ptr(@TypeOf(arena)) {
            const WordSlice = IdxPtr(@TypeOf(arena), .Slice, alignment, Word);
            const words: WordSlice = @alignCast(arena.data.items[@intFromEnum(idx)..][0..word_len]);
            return @ptrCast(words.ptr);
        }

        pub inline fn get(idx: Self, arena: *const IndexedArena) T {
            return idx.getPtr(arena).*;
        }

        pub inline fn set(idx: Self, arena: *IndexedArena, value: T) void {
            idx.getPtr(arena).* = value;
        }

        pub inline fn ptrCast(idx: Self, comptime U: type) IdxAligned(U, alignment) {
            return @enumFromInt(@as(IdxInt, @intFromEnum(idx)));
        }

        // pub inline fn alignCast(idx: Self, comptime new_alignment: u8) IdxAligned(T, new_alignment)

        pub const Opt = packed struct(u32) {
            some: bool,
            inner_idx: Self,

            pub const none = Opt{
                .some = false,
                .inner_idx = @enumFromInt(0),
            };

            pub inline fn init(id: ?Self) Opt {
                return if (id) |some| Opt{ .some = true, .inner_idx = some } else .none;
            }

            pub inline fn opt(id: Opt) ?Self {
                return if (id.some) id.inner_idx else null;
            }
        };
    };
}

/// A word offset into an `IndexedArena`.
pub fn Idx(comptime T: type) type {
    return IdxAligned(T, arenaAlignment(@alignOf(T)));
}

pub fn SliceAligned(comptime T: type, comptime alignment: u8) type {
    return struct {
        idx: IdxAligned(T, alignment),
        len: u32,

        const Self = @This();

        comptime {
            std.debug.assert(@sizeOf(Self) == 8);
        }

        pub const empty = Self{
            .idx = @enumFromInt(0),
            .len = 0,
        };

        pub inline fn isEmpty(self: Self) bool {
            return self.len == 0;
        }

        fn byteSize(self: Self) usize {
            // When slice is constructed, this is already checked to ensure no overflow occurs.
            return @sizeOf(T) * @as(usize, self.len);
        }

        fn wordLen(self: Self) usize {
            // Construction of slice ensures whole slice fits in a valid number of `Word`s.
            return byteSizeToWordCount(self.byteSize()) catch unreachable;
        }

        pub fn Items(comptime Arena: type) type {
            return IdxPtr(Arena, .Slice, alignment, T);
        }

        pub fn items(self: Self, arena: anytype) Items(@TypeOf(arena)) {
            const WordSlice = IdxPtr(@TypeOf(arena), .Slice, alignment, Word);
            const words: WordSlice = @alignCast(arena.data.items[@intFromEnum(self.idx)..][0..self.wordLen()]);

            const BasePtr = IdxPtr(@TypeOf(arena), .Many, alignment, T);
            const base_ptr: BasePtr = @ptrCast(words.ptr);
            return base_ptr[0..self.len];
        }

        // /// Only works if `sizeOf(T)` (aka the stride) is exactly a multiple of `@sizeOf(Word)`.
        // pub inline fn at(self: Self, idx: usize) Idx(T) {
        //     std.debug.assert(idx < self.len);
        //     return @enumFromInt(@as(IdxInt, @intFromEnum(self.idx) + @as(IdxInt, @intCast(idx))));
        // }

        pub inline fn ptrAt(
            self: Self,
            idx: usize,
            arena: anytype,
        ) IdxAligned(T, alignment).Ptr(@TypeOf(arena)) {
            return &self.items(arena)[idx];
        }

        pub inline fn getAt(self: Self, idx: usize, arena: *const IndexedArena) T {
            return self.ptrAt(idx, arena).*;
        }

        pub inline fn setAt(self: Self, idx: usize, arena: *IndexedArena, value: T) void {
            self.ptrAt(idx, arena).* = value;
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

        pub const Opt = struct {
            idx: IdxAligned(T, alignment).Opt,
            len: u32,

            pub const none = Opt{ .idx = .none, .len = 0 };

            pub fn init(s: ?Self) Opt {
                return if (s) |some|
                    .{ .idx = Idx(T).Opt.init(some.idx), .len = some.len }
                else
                    .none;
            }

            pub inline fn opt(self: Opt) ?Self {
                return if (self.idx.opt()) |idx|
                    .{ .idx = idx, .len = self.len }
                else
                    null;
            }

            comptime {
                std.debug.assert(@sizeOf(Opt) == 8);
            }
        };
    };
}

pub fn Slice(comptime T: type) type {
    return SliceAligned(T, arenaAlignment(@alignOf(T)));
}

/// Calculates the number of words that need to be allocated for a given byte `size` and alignment.
fn calculateSizeWithAlignment(
    arena: *const IndexedArena,
    size: usize,
    comptime desired_alignment: u8,
) Error!struct { align_words: usize, total_words: usize } {
    if (desired_alignment > max_alignment) return Error.OutOfMemory;

    const alignment: u8 = @min(@max(min_alignment, desired_alignment), @as(u8, max_alignment));
    const word_alignment = alignment / @sizeOf(Word);

    const base_word_count = try byteSizeToWordCount(size);
    const align_word_count = std.mem.alignForwardAnyAlign(
        usize,
        arena.data.items.len,
        word_alignment,
    ) - arena.data.items.len;

    return .{
        .total_words = std.math.add(usize, align_word_count, base_word_count) catch return Error.OutOfMemory,
        .align_words = align_word_count,
    };
}

fn allocSizeWithAlignment(
    arena: *IndexedArena,
    size: usize,
    comptime alignment: u8,
) Error!IdxInt {
    const elem_size = try arena.calculateSizeWithAlignment(size, alignment);
    const idx_after_align = std.math.add(usize, arena.data.items.len, elem_size.align_words) catch return Error.OutOfMemory;
    const base_idx = std.math.cast(IdxInt, idx_after_align) orelse return Error.OutOfMemory;
    try arena.data.appendNTimes(undefined, elem_size.total_words);
    return base_idx;
}

pub fn alignedCreate(
    arena: *IndexedArena,
    comptime T: type,
    comptime alignment: u8,
) Error!IdxAligned(T, alignment) {
    const base_idx = try arena.allocSizeWithAlignment(@sizeOf(T), alignment);
    return IdxAligned(T, alignment).fromInt(base_idx);
}

pub fn create(arena: *IndexedArena, comptime T: type) Error!Idx(T) {
    return arena.alignedCreate(T, arenaAlignment(@alignOf(T)));
}

pub fn alignedAlloc(
    arena: *IndexedArena,
    comptime T: type,
    comptime alignment: u8,
    n: usize,
) Error!SliceAligned(T, alignment) {
    const len = std.math.cast(u32, n) orelse return Error.OutOfMemory;
    const byte_size = std.math.mul(usize, @sizeOf(T), len) catch return Error.OutOfMemory;
    const base_idx = try arena.allocSizeWithAlignment(byte_size, alignment);
    return .{ .idx = IdxAligned(T, alignment).fromInt(base_idx), .len = len };
}

pub fn alloc(arena: *IndexedArena, comptime T: type, n: usize) Error!Slice(T) {
    return arena.alignedAlloc(T, arenaAlignment(@alignOf(T)), n);
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

pub fn BoundedArrayListAligned(comptime T: type, comptime alignment: u8) type {
    return struct {
        items: SliceAligned(T, alignment),
        capacity: u32,

        const Self = @This();

        pub fn initCapacity(arena: *IndexedArena, capacity: usize) Error!Self {
            const items = try arena.alignedAlloc(T, alignment, capacity);
            errdefer comptime unreachable;
            return .{
                .items = .{ .idx = items.idx, .len = 0 },
                .capacity = items.len,
            };
        }

        pub fn appendAssumeCapacity(self: *Self, arena: *IndexedArena, item: T) void {
            std.debug.assert(self.items.len < self.capacity);
            self.items.len += 1;
            self.items.setAt(self.items.len - 1, arena, item);
        }
    };
}

/// Used to construct lists with a known upper bound for its length.
pub fn BoundedArrayList(comptime T: type) type {
    return BoundedArrayListAligned(T, arenaAlignment(@alignOf(T)));
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
