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

pub const Data = []align(max_alignment) Word;
pub const ConstData = []align(max_alignment) const Word;

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
                *IndexedArena,
                []align(max_alignment) Word,
                => false,
                *const IndexedArena,
                ConstData,
                => true,
                else => @compileError(@typeName(Arena) ++ " is not a valid arena type"),
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

pub fn dataSlice(arena: anytype) IdxPtr(@TypeOf(arena), .Slice, max_alignment, Word) {
    return switch (@TypeOf(arena)) {
        *IndexedArena,
        *const IndexedArena,
        => arena.data.items,
        []align(max_alignment) Word,
        ConstData,
        => arena,
        else => unreachable,
    };
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

        inline fn toInt(idx: Self) IdxInt {
            return @intFromEnum(idx);
        }

        pub fn Ptr(comptime Arena: type) type {
            return IdxPtr(Arena, .One, alignment, T);
        }

        /// The length, in words, of the data pointed to.
        pub const word_len = byteSizeToWordCount(@sizeOf(T)) catch unreachable;

        pub inline fn getPtr(idx: Self, arena: anytype) Ptr(@TypeOf(arena)) {
            const WordSlice = IdxPtr(@TypeOf(arena), .Slice, alignment, Word);
            const words: WordSlice = @alignCast(dataSlice(arena)[@intFromEnum(idx)..][0..word_len]);
            return @ptrCast(words.ptr);
        }

        pub inline fn get(idx: Self, arena: anytype) T {
            return idx.getPtr(arena).*;
        }

        pub inline fn set(idx: Self, arena: anytype, value: T) void {
            idx.getPtr(arena).* = value;
        }

        pub inline fn ptrCast(idx: Self, comptime U: type) IdxAligned(U, alignment) {
            return @enumFromInt(idx.toInt());
        }

        pub inline fn alignCast(idx: Self, comptime new_alignment: u8) IdxAligned(T, new_alignment) {
            const int = idx.toInt();
            std.debug.assert(int % new_alignment == 0);
            return @enumFromInt(int);
        }

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
        idx: ElemIdx,
        len: u32,

        const Self = @This();

        pub const ElemIdx = IdxAligned(T, alignment);
        pub const Elem = T;

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
            const words: WordSlice = @alignCast(dataSlice(arena)[@intFromEnum(self.idx)..][0..self.wordLen()]);

            const BasePtr = IdxPtr(@TypeOf(arena), .Many, alignment, T);
            const base_ptr: BasePtr = @ptrCast(words.ptr);
            return base_ptr[0..self.len];
        }

        pub fn Ptr(comptime Arena: type) type {
            return IdxPtr(Arena, .Many, alignment, T);
        }

        pub fn ptr(self: Self, arena: anytype) Ptr(@TypeOf(arena)) {
            return self.items(arena).ptr;
        }

        /// Gets an index to the element of this slice.
        ///
        /// Only works if `sizeOf(T)` (aka the stride) is exactly a multiple of `@sizeOf(Word)`.
        pub fn at(self: Self, idx: usize) Idx(T) {
            comptime std.debug.assert(@sizeOf(T) % @sizeOf(Word) == 0);

            std.debug.assert(idx < self.len);
            const offset: IdxInt = @intCast(@divExact(@sizeOf(T) * idx, @sizeOf(Word)));
            return Idx(T).fromInt(@as(IdxInt, @intFromEnum(self.idx) + offset));
        }

        pub fn PtrAt(comptime Arena: type) type {
            return IdxPtr(Arena, .One, @min(@alignOf(T), alignment), T);
        }

        pub inline fn ptrAt(
            self: Self,
            idx: usize,
            arena: anytype,
        ) PtrAt(@TypeOf(arena)) {
            return &self.items(arena)[idx];
        }

        pub inline fn getAt(self: Self, idx: usize, arena: anytype) T {
            return self.ptrAt(idx, arena).*;
        }

        pub inline fn setAt(self: Self, idx: usize, arena: anytype, value: T) void {
            self.ptrAt(idx, arena).* = value;
        }

        pub fn slice(self: Self, start: usize, end: usize) Self {
            std.debug.assert(start <= end);
            std.debug.assert(end <= self.len);
            return .{
                .idx = @enumFromInt(@as(IdxInt, @intCast(@intFromEnum(self.idx) + start))),
                .len = @intCast(end - start),
            };
        }

        pub fn eql(self: Self, other: Self, arena: anytype) bool {
            return (self.len == other.len and @intFromEnum(self.idx) == @intFromEnum(other.idx)) or
                std.mem.eql(T, self.items(arena), other.items(arena));
        }

        pub const Opt = extern struct {
            idx: ElemIdx.Opt,
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
    desired_alignment: u8,
) Error!struct { align_words: usize, total_words: usize } {
    if (desired_alignment > max_alignment) return Error.OutOfMemory;

    const alignment: u8 = @min(@max(min_alignment, desired_alignment), @as(u8, max_alignment));
    const word_alignment = alignment / @sizeOf(Word);

    const base_word_count = try byteSizeToWordCount(size);
    const unaligned_base_idx = dataSlice(arena).len;
    const align_word_count = std.mem.alignForward(usize, unaligned_base_idx, word_alignment) - unaligned_base_idx;

    return .{
        .total_words = std.math.add(usize, align_word_count, base_word_count) catch return Error.OutOfMemory,
        .align_words = align_word_count,
    };
}

pub fn rawAlloc(
    arena: *IndexedArena,
    size: usize,
    alignment: u8,
) Error!IdxInt {
    const elem_size = try arena.calculateSizeWithAlignment(size, alignment);
    const idx_after_align = std.math.add(usize, dataSlice(arena).len, elem_size.align_words) catch return Error.OutOfMemory;
    const base_idx = std.math.cast(IdxInt, idx_after_align) orelse return Error.OutOfMemory;
    try arena.data.appendNTimes(undefined, elem_size.total_words);
    return base_idx;
}

pub fn alignedCreate(
    arena: *IndexedArena,
    comptime T: type,
    comptime alignment: u8,
) Error!IdxAligned(T, alignment) {
    const base_idx = try arena.rawAlloc(@sizeOf(T), alignment);
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
    const base_idx = try arena.rawAlloc(byte_size, alignment);
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
    try std.testing.expectEqual(6, arena.dataSlice().len);
    try std.testing.expectEqual('o', str.getAt(4, &arena));

    const Thing = struct {
        a: u32,
        b: u32,
    };

    const stuff = try arena.dupe(Thing, &[2]Thing{
        .{ .a = 1, .b = 2 },
        .{ .a = 3, .b = 4 },
    });

    const second = stuff.at(1);
    try std.testing.expectEqual(Thing{ .a = 3, .b = 4 }, second.get(&arena));
}
