/// A memory allocator into a buffer of a precalculated size.
pub fn AlignedReservationAllocator(
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

pub const ReservationAllocator = AlignedReservationAllocator(.@"16");

pub const ArenaFallbackAllocator = struct {
    /// Where allocations go until it is full.
    ///
    /// Allocated in the `arena`.
    ///
    /// Because the underlying `arena` can already allocate "next" to the `buffer` when it is
    /// full, no logic is needed to attempt to resize the `buffer`.
    buffer: FixedBufferAllocator,
    arena: *ArenaAllocator,

    fn alloc(ctx: *anyopaque, len: usize, alignment: Alignment, ret_addr: usize) ?[*]u8 {
        const self: *ArenaFallbackAllocator = @ptrCast(@alignCast(ctx));
        return FixedBufferAllocator.alloc(
            @ptrCast(&self.buffer),
            len,
            alignment,
            ret_addr,
        ) orelse slow: {
            @branchHint(.unlikely);
            break :slow self.arena.allocator().rawAlloc(len, alignment, ret_addr);
        };
    }

    fn resize(
        ctx: *anyopaque,
        buf: []u8,
        alignment: Alignment,
        new_len: usize,
        ret_addr: usize,
    ) bool {
        const self: *ArenaFallbackAllocator = @ptrCast(@alignCast(ctx));
        return if (self.buffer.ownsSlice(buf))
            // Could attempt resize of `self.buffer` here using `arena`, but it would rarely succeed
            // anyway
            FixedBufferAllocator.resize(@ptrCast(&self.buffer), buf, alignment, new_len, ret_addr)
        else
            self.arena.allocator().rawResize(buf, alignment, new_len, ret_addr);
    }

    fn remap(
        ctx: *anyopaque,
        buf: []u8,
        alignment: Alignment,
        new_len: usize,
        ret_addr: usize,
    ) ?[*]u8 {
        const self: *ArenaFallbackAllocator = @ptrCast(@alignCast(ctx));
        if (self.buffer.ownsSlice(buf)) {
            const resized = FixedBufferAllocator.resize(
                @ptrCast(&self.buffer),
                buf,
                alignment,
                new_len,
                ret_addr,
            );

            if (resized) {
                return buf.ptr;
            } else {
                std.debug.assert(new_len > buf.len);
                const new_ptr = self.arena.allocator().rawAlloc(
                    new_len,
                    alignment,
                    ret_addr,
                ) orelse return null;

                @memcpy(new_ptr[0..new_len], buf);

                FixedBufferAllocator.free(@ptrCast(&self.buffer), buf, alignment, ret_addr);

                return buf.ptr;
            }
        } else {
            return self.arena.allocator().rawRemap(buf, alignment, new_len, ret_addr);
        }
    }

    fn free(ctx: *anyopaque, buf: []u8, alignment: Alignment, ret_addr: usize) void {
        const self: *ArenaFallbackAllocator = @ptrCast(@alignCast(ctx));
        if (self.buffer.ownsSlice(buf)) {
            FixedBufferAllocator.free(@ptrCast(&self.buffer), buf, alignment, ret_addr);
        } else {
            self.arena.allocator().rawFree(buf, alignment, ret_addr);
        }
    }

    const allocator_vtable: Allocator.VTable = .{
        .alloc = ArenaFallbackAllocator.alloc,
        .resize = ArenaFallbackAllocator.resize,
        .remap = ArenaFallbackAllocator.remap,
        .free = ArenaFallbackAllocator.free,
    };

    pub fn allocator(self: *ArenaFallbackAllocator) Allocator {
        return .{ .ptr = @ptrCast(self), .vtable = &allocator_vtable };
    }
};

const std = @import("std");
const Allocator = std.mem.Allocator;
const Alignment = std.mem.Alignment;
const Oom = Allocator.Error;
const ArenaAllocator = std.heap.ArenaAllocator;
const FixedBufferAllocator = std.heap.FixedBufferAllocator;
