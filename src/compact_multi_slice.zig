const std = @import("std");
const Allocator = std.mem.Allocator;

pub fn CompactMultiSlice(comptime T: type) type {
    return struct {
        bytes: [*]align(@alignOf(T)) u8,
        len: usize,

        const MultiArrayList = std.MultiArrayList(T);
        pub const Slice = MultiArrayList.Slice;
        pub const Field = MultiArrayList.Field;

        const Self = @This();

        pub fn initExact(multi_array_list: MultiArrayList) Self {
            std.debug.assert(multi_array_list.len == multi_array_list.capacity);
            return Self{
                .bytes = multi_array_list.bytes,
                .len = multi_array_list.len,
            };
        }

        pub fn toMultiArrayList(self: Self) MultiArrayList {
            return .{
                .bytes = self.bytes,
                .len = self.len,
                .capacity = self.len,
            };
        }

        pub fn slice(self: Self) Slice {
            return self.toMultiArrayList().slice();
        }

        fn cloneSegmentedListWithPreallocCount(
            comptime prealloc_count: usize,
            list: *const std.SegmentedList(T, prealloc_count),
            gpa: Allocator,
        ) Allocator.Error!Self {
            var destination = MultiArrayList.empty;
            try destination.setCapacity(gpa, list.len);
            var items = list.constIterator(0);
            for (0..list.len) |_| destination.appendAssumeCapacity((items.next() orelse unreachable).*);
            return Self.initExact(destination);
        }

        pub fn cloneSegmentedList(list: anytype, gpa: Allocator) Allocator.Error!Self {
            return Self.cloneSegmentedListWithPreallocCount(
                @field(@typeInfo(@TypeOf(list)).pointer.child, "prealloc_count"),
                list,
                gpa,
            );
        }
    };
}
