//! A `MemInst` implementation backed by an `Allocator`.

allocator: Allocator,
memory: MemInst,

const Allocated = @This();

/// Asserts that `size <= initial_capacity <= maximum_size`.
pub fn allocate(
    allocator: Allocator,
    /// The initial size in bytes, rounded down to the nearest multiple of `MemInst.page_size`.
    initial_size: usize,
    /// The initial capacity of the memory allocation, in bytes, rounded down to the nearest
    /// multiple of `MemInst.page_size`.
    initial_capacity: usize,
    /// The maximum size of the memory allocation, in bytes, rounded down to the nearest
    /// multiple of `MemInst.page_size`.
    maximum_size: usize,
) Oom!Allocated {
    std.debug.assert(initial_size <= initial_capacity);
    std.debug.assert(initial_capacity <= maximum_size);

    const max_limit = std.math.maxInt(u32) + 1;
    if (initial_capacity >= max_limit or maximum_size >= max_limit) {
        return error.OutOfMemory; // no memory64 support
    }

    const rounded_capacity = std.mem.alignBackward(usize, initial_capacity, MemInst.page_size);
    const buffer = try allocator.alignedAlloc(
        u8,
        .fromByteUnits(MemInst.buffer_align),
        rounded_capacity,
    );

    return Allocated{
        .allocator = allocator,
        .memory = MemInst{
            .base = buffer.ptr,
            .size = std.mem.alignBackward(usize, initial_size, MemInst.page_size),
            .capacity = rounded_capacity,
            .limit = std.mem.alignBackward(usize, maximum_size, MemInst.page_size),
            .vtable = &vtable,
        },
    };
}

/// Allocates a new `MemInst` corresponding to the given `MemType`.
///
/// The initial size is the minimum specified in the `MemType`.
///
/// Asserts that `initial_capacity` and `maximum_size` are not less than the minimum specified
/// in the `MemType`.
pub fn allocateFromType(
    allocator: Allocator,
    mem_type: *const MemType,
    initial_capacity: usize,
    /// Allows a smaller limit than the one specified in the `mem_type`.
    maximum_size: usize,
) Oom!Allocated {
    const min_bytes = mem_type.limits.min * MemInst.page_size;
    const max_bytes = mem_type.limits.max * MemInst.page_size;

    std.debug.assert(min_bytes <= max_bytes);
    std.debug.assert(min_bytes <= initial_capacity);
    std.debug.assert(maximum_size <= max_bytes);

    return allocate(allocator, min_bytes, initial_capacity, @min(maximum_size, max_bytes));
}

fn grow(mem: *MemInst, new_size: usize) Oom!void {
    std.debug.assert(new_size % MemInst.page_size == 0);
    std.debug.assert(mem.size < new_size);
    std.debug.assert(mem.capacity < new_size);
    std.debug.assert(new_size <= mem.limit);

    const inst: *Allocated = @fieldParentPtr("memory", mem);
    const old_alloc = mem.allocated();
    // In case there is unused capacity, ensures zeroes are copied
    @memset(old_alloc[mem.size..], 0);

    if (inst.allocator.resize(old_alloc, new_size)) {
        // successful resize in place
    } else if (inst.allocator.remap(old_alloc, new_size)) |new_alloc| {
        mem.base = new_alloc.ptr;
        @memset(new_alloc[mem.capacity..], 0);
    } else {
        const new_alloc = try inst.allocator.alignedAlloc(
            u8,
            .fromByteUnits(MemInst.buffer_align),
            new_size,
        );
        @memcpy(new_alloc[0..mem.size], old_alloc[0..mem.size]);
        @memset(new_alloc[mem.size..], 0);
        inst.allocator.free(old_alloc);
        mem.base = new_alloc.ptr;
    }

    mem.size = new_size;
    mem.capacity = new_size;
}

fn free(mem: *MemInst) void {
    const inst: *Allocated = @fieldParentPtr("memory", mem);
    inst.allocator.free(mem.allocated());
}

const vtable = MemInst.VTable{
    .grow = grow,
    .free = free,
};

const std = @import("std");
const Allocator = std.mem.Allocator;
const Oom = Allocator.Error;
const MemType = @import("../../Module.zig").MemType;
const MemInst = @import("../memory.zig").MemInst;
