//! Memory allocators for not you and me!

pub const LimitedAllocator = @import("allocators/LimitedAllocator.zig");
pub const Reservation = @import("allocators/Reservation.zig");
pub const virtual_memory = @import("allocators/virtual_memory.zig");
pub const PageAllocation = @import("allocators/PageAllocation.zig");

const std = @import("std");
const Allocator = std.mem.Allocator;

pub fn allocBytes(
    allocator: Allocator,
    size: usize,
    alignment: std.mem.Alignment,
) Allocator.Error![]u8 {
    if (size == 0) {
        return @as([*]u8, @ptrFromInt(alignment.backward(std.math.maxInt(usize))))[0..0];
    } else {
        const base = allocator.rawAlloc(size, alignment, @returnAddress()) orelse
            return error.OutOfMemory;

        return base[0..size];
    }
}

test {
    _ = LimitedAllocator;
    _ = virtual_memory;
    _ = PageAllocation;
}
