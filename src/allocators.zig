//! Memory allocators for not you and me!

pub const LimitedAllocator = @import("allocators/LimitedAllocator.zig");
const reservation_allocator = @import("allocators/reservation_allocator.zig");
pub const ReservationAllocator = reservation_allocator.ReservationAllocator;
pub const ArenaFallbackAllocator = @import("allocators/ArenaFallbackAllocator.zig");
pub const virtual_memory = @import("allocators/virtual_memory.zig");
pub const PageAllocation = @import("allocators/PageAllocation.zig");
pub const UnrolledLinkedList = @import("allocators/unrolled_linked_list.zig").UnrolledLinkedList;

test {
    _ = LimitedAllocator;
    _ = reservation_allocator;
    _ = ArenaFallbackAllocator;
    _ = virtual_memory;
    _ = PageAllocation;
    _ = UnrolledLinkedList;
}
