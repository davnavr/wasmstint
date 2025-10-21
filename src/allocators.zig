//! Memory allocators for not you and me!

pub const LimitedAllocator = @import("allocators/LimitedAllocator.zig");
const reservation_allocator = @import("allocators/reservation_allocator.zig");
pub const ReservationAllocator = reservation_allocator.ReservationAllocator;
pub const ArenaFallbackAllocator = @import("allocators/ArenaFallbackAllocator.zig");
pub const virtual_memory = @import("allocators/virtual_memory.zig");

test {
    _ = LimitedAllocator;
    _ = reservation_allocator;
    _ = ArenaFallbackAllocator;
}
