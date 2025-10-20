/// A memory allocator into a buffer of a precalculated size and a maximum supported alignment.
pub fn ReservationAllocator(
    comptime max_alignment: Alignment,
) type {
    return struct {
        const Self = @This();

        bytes: usize,

        pub const zero = Self{ .bytes = 0 };

        const max_align_bytes = max_alignment.toByteUnits();

        pub fn alignUpTo(reservation: *Self, comptime new_alignment: Alignment) Oom!void {
            const new_alignment_bytes = comptime new_alignment.toByteUnits();

            reservation.bytes = std.mem.alignBackward(
                usize,
                std.math.add(usize, reservation.bytes, new_alignment_bytes - 1) catch
                    return Oom.OutOfMemory,
                new_alignment_bytes,
            );

            std.debug.assert(reservation.bytes % new_alignment_bytes == 0);
        }

        pub inline fn reserveUnaligned(
            reservation: *Self,
            comptime T: type,
            count: usize,
        ) Oom!void {
            reservation.bytes = std.math.add(
                usize,
                reservation.bytes,
                std.math.mul(usize, @sizeOf(T), count) catch return Oom.OutOfMemory,
            ) catch return Oom.OutOfMemory;
        }

        /// Asserts at compile time that the alignment of `T` does not exceed `max_alignment`.
        pub fn reserve(reservation: *Self, comptime T: type, count: usize) Oom!void {
            comptime {
                if (@alignOf(T) > max_align_bytes) @compileError(
                    std.fmt.comptimePrint(
                        @typeName(T) ++ " has an alignment of {} bytes, exceeding the maximum of {}",
                        .{ @alignOf(T), max_align_bytes },
                    ),
                );
            }

            try reservation.alignUpTo(.fromByteUnits(@alignOf(T)));
            try reservation.reserveUnaligned(T, count);
        }

        /// Don't forget to call `backing_allocator.free()` on the returned buffer to deallocate
        /// it!
        pub inline fn bufferAllocator(
            reservation: Self,
            backing_allocator: Allocator,
        ) Oom!FixedBufferAllocator {
            return FixedBufferAllocator.init(
                try backing_allocator.alignedAlloc(u8, max_alignment, reservation.bytes),
            );
        }

        pub fn arenaFallbackAllocator(
            reservation: Self,
            arena: *ArenaAllocator,
        ) Oom!ArenaFallbackAllocator {
            return .{
                .buffer = try reservation.bufferAllocator(arena.allocator()),
                .arena = arena,
            };
        }

        pub fn arenaFallbackAllocatorWithHeaderAligned(
            reservation: Self,
            arena: *ArenaAllocator,
            comptime Header: type,
            comptime header_alignment: Alignment,
        ) Oom!struct {
            inner: *align(@max(max_align_bytes, header_alignment.toByteUnits())) Header,
            alloc: ArenaFallbackAllocator,
        } {
            var new_reservation = reservation;
            try new_reservation.reserveUnaligned(Header, 1);
            std.debug.assert(new_reservation.bytes >= @sizeOf(Header));
            const new_alignment = comptime header_alignment.max(max_alignment);
            try new_reservation.alignUpTo(new_alignment);
            var allocator = ArenaFallbackAllocator{
                .buffer = FixedBufferAllocator.init(
                    try arena.allocator().alignedAlloc(u8, new_alignment, new_reservation.bytes),
                ),
                .arena = arena,
            };

            const inner = allocator.buffer.allocator().alignedAlloc(Header, new_alignment, 1) catch
                unreachable;

            return .{ .inner = &inner[0], .alloc = allocator };
        }
    };
}

test {
    _ = ReservationAllocator(.@"16");
}

const std = @import("std");
const Allocator = std.mem.Allocator;
const Alignment = std.mem.Alignment;
const Oom = Allocator.Error;
const ArenaAllocator = std.heap.ArenaAllocator;
const FixedBufferAllocator = std.heap.FixedBufferAllocator;
const ArenaFallbackAllocator = @import("ArenaFallbackAllocator.zig");
