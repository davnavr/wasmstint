/// A singly linked list where nodes contain multiple elements.
///
/// Works best when `@sizeOf(T)` is a power of two, and `size` ensures a `Node` is (or is close to)
/// the CPU cache line size.
///
/// Serves as a replacement for the removed `std.SegmentedList(T, usize)`, may they rest in peace.
pub fn UnrolledLinkedList(
    comptime T: type,
    /// Minimum number of elements in an individual `Node`.
    comptime min_size: comptime_int,
) type {
    return struct {
        comptime {
            std.debug.assert(@sizeOf(T) > 0);
            std.debug.assert(min_size > 0);
        }

        pub const Node = struct {
            const size_in_ptrs = (std.math.divCeil(
                usize,
                min_size * @sizeOf(T),
                @sizeOf(usize),
            ) catch unreachable) + 1;

            const capacity_in_bytes = (size_in_ptrs - 1) * @sizeOf(usize);

            const alignment = std.mem.Alignment.fromByteUnits(
                @max(@alignOf(?*Node), std.math.floorPowerOfTwo(usize, size_in_ptrs)),
            );

            const elems_len = @divFloor(capacity_in_bytes, @sizeOf(T));
            const Elems = [elems_len]T;

            elems: Elems align(alignment.toByteUnits()),
            padding: [capacity_in_bytes - @sizeOf(Elems)]u8 = undefined,
            prev: ?*Node,

            pub const Pool = std.heap.MemoryPoolAligned(Node, alignment);

            const empty = Node{ .elems = undefined, .prev = null };

            const Len = std.math.IntFittingRange(0, Node.elems_len);

            comptime {
                std.debug.assert(@sizeOf(Node) == size_in_ptrs * @sizeOf(usize));
                std.debug.assert(@alignOf(Node) == alignment.toByteUnits());
            }
        };

        tail: ?*Node,
        /// Number of elements in the `tail` node.
        tail_count: Node.Len,
        /// Total number of elements in the list.
        total_count: u32,

        const Self = @This();

        pub const empty = Self{ .tail = null, .tail_count = 0, .total_count = 0 };

        pub const AllocationMode = enum {
            allocator,
            pooled,

            fn Type(comptime mode: AllocationMode) type {
                return switch (mode) {
                    .allocator => Allocator,
                    .pooled => *Node.Pool,
                };
            }

            fn create(comptime mode: AllocationMode, memory: mode.Type()) Oom!*Node {
                const created: *Node = switch (mode) {
                    .allocator => try Allocator.create(memory, Node),
                    .pooled => try Node.Pool.create(memory),
                };

                created.* = Node.empty;
                return created;
            }
        };

        fn currentNode(
            list: *Self,
            comptime mode: AllocationMode,
            memory: mode.Type(),
        ) Oom!*Node {
            if (list.tail == null) {
                @branchHint(.cold);
                std.debug.assert(list.total_count == 0);
                std.debug.assert(list.tail_count == 0);
                list.tail = try mode.create(memory);
            }

            return list.tail.?;
        }

        pub fn addOne(list: *Self, comptime mode: AllocationMode, memory: mode.Type()) Oom!*T {
            const dst: *Node = if (list.tail_count < Node.elems_len)
                try list.currentNode(mode, memory)
            else if (list.total_count == std.math.maxInt(u32))
                return error.OutOfMemory
            else new: {
                @branchHint(.unlikely);
                std.debug.assert(list.tail_count == Node.elems_len);
                const new = try mode.create(memory);
                new.prev = list.tail;
                list.tail = new;
                list.tail_count = 0;
                break :new new;
            };

            errdefer comptime unreachable;

            const elem: *T = &dst.elems[list.tail_count];
            list.total_count += 1;
            list.tail_count += 1;
            return elem;
        }

        pub fn append(
            list: *Self,
            comptime mode: AllocationMode,
            memory: mode.Type(),
            item: T,
        ) Oom!void {
            const dst = try list.addOne(mode, memory);
            dst.* = item;
        }

        pub fn deinit(list: *Self, comptime mode: AllocationMode, memory: mode.Type()) void {
            var current = list.tail;
            while (current) |node| {
                current = node.prev;
                switch (mode) {
                    .allocator => Allocator.destroy(memory, node),
                    .pooled => Node.Pool.destroy(memory, node),
                }
            }
            list.* = undefined;
        }

        pub fn copyToSlice(list: *const Self, dst: []T) void {
            std.debug.assert(list.total_count == dst.len);

            // Copy tail first
            const tail = list.tail orelse {
                std.debug.assert(list.total_count == 0);
                std.debug.assert(list.tail_count == 0);
                return;
            };
            const dst_tail_idx = dst.len - list.tail_count;
            @memcpy(dst[dst_tail_idx..], tail.elems[0..list.tail_count]);

            // Remaining nodes all have the same size
            const dst_remaining = dst[0..dst_tail_idx];
            std.debug.assert(dst_remaining.len % Node.elems_len == 0);
            std.debug.assert(dst_remaining.len == list.total_count - list.tail_count);
            const dst_remaining_arrays: [][Node.elems_len]T = @ptrCast(dst_remaining);
            var remaining: ?*Node = tail.prev;
            for (0..dst_remaining_arrays.len) |i| {
                const dst_slice: *[Node.elems_len]T =
                    &dst_remaining_arrays[dst_remaining_arrays.len - i - 1];

                @memmove(dst_slice, &remaining.?.elems);
                remaining = remaining.?.prev;
            }

            std.debug.assert(remaining == null);
        }

        pub fn allocSlice(list: *const Self, allocator: Allocator) Oom![]T {
            const dst = try allocator.alloc(T, list.total_count);
            list.copyToSlice(dst);
            return dst;
        }
    };
}

fn basicTest(comptime mode: UnrolledLinkedList(usize, 15).AllocationMode) !void {
    const List = UnrolledLinkedList(usize, 15);
    comptime {
        std.debug.assert(List.Node.elems_len == 15);
    }

    var pool_or_allocator = switch (mode) {
        .allocator => std.testing.allocator,
        .pooled => List.Node.Pool.init(std.testing.allocator),
    };
    const memory = switch (mode) {
        .allocator => pool_or_allocator,
        .pooled => &pool_or_allocator,
    };
    defer if (mode == .pooled) List.Node.Pool.deinit(memory);

    var list = List.empty;
    defer list.deinit(mode, memory);
    {
        try list.append(mode, memory, 0x1111);
        var actual: [1]usize = undefined;
        list.copyToSlice(&actual);
        try std.testing.expectEqual([1]usize{0x1111}, actual);
    }
    {
        try list.append(mode, memory, 0x2222);
        try list.append(mode, memory, 0x3333);
        var actual: [3]usize = undefined;
        list.copyToSlice(&actual);
        try std.testing.expectEqual([3]usize{ 0x1111, 0x2222, 0x3333 }, actual);
    }
    {
        for (4..16) |i| {
            try list.append(mode, memory, i);
        }
        try std.testing.expectEqual(15, list.total_count);
        try std.testing.expectEqual(15, list.tail_count);

        try list.append(mode, memory, 0xABBA_ABBA);
        try list.append(mode, memory, 0xBABA_BABA);
        try std.testing.expectEqual(17, list.total_count);
        try std.testing.expectEqual(2, list.tail_count);

        var actual: [17]usize = undefined;
        list.copyToSlice(&actual);
        try std.testing.expectEqual(
            [17]usize{
                0x1111,      0x2222,      0x3333, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                0xABBA_ABBA, 0xBABA_BABA,
            },
            actual,
        );
    }
}

test "in allocator" {
    try basicTest(.allocator);
}

test "in pool" {
    try basicTest(.pooled);
}

const std = @import("std");
const Allocator = std.mem.Allocator;
const Oom = Allocator.Error;
