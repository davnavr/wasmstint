//! Used to calculate the size and alignment of a buffer used to back an `Allocator`.

size: usize = 0,
alignment: Alignment = .@"1",

const Reservation = @This();

fn addOrOom(a: usize, b: usize) Oom!usize {
    return std.math.add(usize, a, b) catch Oom.OutOfMemory;
}

pub fn alignUpTo(reservation: *Reservation, new_alignment: Alignment) Oom!void {
    const new_alignment_bytes = new_alignment.toByteUnits();

    reservation.size = std.mem.alignBackward(
        usize,
        try addOrOom(reservation.size, new_alignment_bytes - 1),
        new_alignment_bytes,
    );

    std.debug.assert(reservation.size % new_alignment_bytes == 0);
    reservation.alignment = reservation.alignment.max(new_alignment);
}

pub fn reserveBytes(reservation: *Reservation, size: usize) Oom!void {
    reservation.size = try addOrOom(reservation.size, size);
}

pub inline fn reserveUnaligned(
    reservation: *Reservation,
    comptime T: type,
    count: usize,
) Oom!void {
    const size = std.math.mul(usize, @sizeOf(T), count) catch return Oom.OutOfMemory;
    try reservation.reserveBytes(size);
}

pub fn reserveAligned(
    reservation: *Reservation,
    comptime T: type,
    alignment: std.mem.Alignment,
    count: usize,
) Oom!void {
    try reservation.alignUpTo(alignment);
    try reservation.reserveUnaligned(T, count);
}

pub fn reserve(reservation: *Reservation, comptime T: type, count: usize) Oom!void {
    try reservation.reserveAligned(T, .fromByteUnits(@alignOf(T)), count);
}

pub fn append(current: *Reservation, other: Reservation) Oom!void {
    try current.alignUpTo(other.alignment);
    try current.reserveBytes(other.size);
}

/// Don't forget to call `backing_allocator.free()` on the returned buffer to deallocate
/// it!
pub inline fn bufferAllocator(
    reservation: Reservation,
    backing_allocator: Allocator,
) Oom!FixedBufferAllocator {
    return FixedBufferAllocator.init(
        try allocators.allocBytes(
            backing_allocator,
            reservation.size,
            reservation.alignment,
        ),
    );
}

pub fn arenaFallbackAllocator(
    reservation: Reservation,
    arena: *ArenaAllocator,
) Oom!ArenaFallbackAllocator {
    return .{
        .buffer = try reservation.bufferAllocator(arena.allocator()),
        .arena = arena,
    };
}

pub fn arenaFallbackAllocatorWithHeaderAligned(
    reservation: Reservation,
    arena: *ArenaAllocator,
    comptime Header: type,
    comptime header_alignment: Alignment,
) Oom!struct {
    inner: *align(header_alignment.toByteUnits()) Header,
    alloc: ArenaFallbackAllocator,
} {
    var new_reservation = Reservation{ .size = @sizeOf(Header), .alignment = header_alignment };
    try new_reservation.append(reservation);

    const buffer = try new_reservation.bufferAllocator(arena.allocator());

    errdefer comptime unreachable;

    var allocator = ArenaFallbackAllocator{ .buffer = buffer, .arena = arena };
    const inner = allocator.buffer.allocator().alignedAlloc(Header, header_alignment, 1) catch
        unreachable;

    return .{ .inner = &inner[0], .alloc = allocator };
}

const std = @import("std");
const Allocator = std.mem.Allocator;
const Alignment = std.mem.Alignment;
const Oom = Allocator.Error;
const ArenaAllocator = std.heap.ArenaAllocator;
const FixedBufferAllocator = std.heap.FixedBufferAllocator;
const allocators = @import("../allocators.zig");
const ArenaFallbackAllocator = @import("ArenaFallbackAllocator.zig");
