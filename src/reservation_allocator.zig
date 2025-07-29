/// A memory allocator into a buffer of a precalculated size.
pub fn AlignedReservationAllocator(
    /// The alignment that all allocations into the buffer are expected to have.
    comptime alignment: Alignment,
) type {
    return struct {
        const Self = @This();

        bytes: usize,

        pub const zero = Self{ .bytes = 0 };

        const align_bytes = alignment.toByteUnits();

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

        pub fn reserve(reservation: *Self, comptime T: type, count: usize) Oom!void {
            comptime {
                if (@alignOf(T) > align_bytes) {
                    @compileError(
                        std.fmt.comptimePrint(
                            @typeName(T) ++ " has an alignment of {}, exceeding the maximum of {}",
                            .{ @alignOf(T), align_bytes },
                        ),
                    );
                }
            }

            reservation.bytes = std.math.add(
                usize,
                reservation.bytes,
                std.math.mul(usize, @sizeOf(T), count) catch return Oom.OutOfMemory,
            ) catch return Oom.OutOfMemory;
            try reservation.alignUpTo(alignment);
        }

        /// Don't forget to call `backing_allocator.free()` on the returned buffer to deallocate
        /// it!
        pub inline fn bufferAllocator(
            reservation: Self,
            backing_allocator: Allocator,
        ) Oom!FixedBufferAllocator {
            return FixedBufferAllocator.init(
                try backing_allocator.alignedAlloc(u8, alignment, reservation.bytes),
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
            comptime header_align: Alignment,
        ) Oom!struct {
            inner: *align(@max(align_bytes, header_align.toByteUnits())) Header,
            alloc: ArenaFallbackAllocator,
        } {
            const new_alignment = comptime Alignment.max(alignment, header_align);

            var new_reservation = reservation;
            try new_reservation.reserve(Header, 1);
            try new_reservation.alignUpTo(new_alignment);
            std.debug.assert(new_reservation.bytes >= @sizeOf(Header));

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

pub const ReservationAllocator = AlignedReservationAllocator(.fromByteUnits(@alignOf(usize)));

pub const ArenaFallbackAllocator = struct {
    /// Where allocations go until it is filled.
    ///
    /// Allocated in the `arena`.
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
