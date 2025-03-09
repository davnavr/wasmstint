//! Allows the Rust side to use Zig's `SmpAllocator`.
//!
//! The functions exported are expected to be used to implement the
//! [`std::alloc::GlobalAlloc`] trait in calling Rust code.
//!
//! [`std::alloc::GlobalAlloc`]: https://doc.rust-lang.org/std/alloc/trait.GlobalAlloc.html

const std = @import("std");

pub const Alignment = enum(u8) {
    _,

    pub fn convert(self: Alignment) ?std.mem.Alignment {
        return @enumFromInt(
            std.math.cast(
                std.math.Log2Int(usize),
                @intFromEnum(self),
            ) orelse return null,
        );
    }
};

const allocator = std.heap.smp_allocator;

// TODO: Figure out why @export helper causes segmentation fault (addresses on Zig and Rust side differ)

pub export fn wasmstint_fuzz_rust_heap_alloc(size: usize, alignment: Alignment) callconv(.c) ?[*]u8 {
    std.debug.assert(size > 0);
    return allocator.rawAlloc(
        size,
        alignment.convert() orelse return null,
        @returnAddress(),
    );
}

pub export fn wasmstint_fuzz_rust_heap_dealloc(ptr: *anyopaque, size: usize, alignment: Alignment) callconv(.c) void {
    std.debug.assert(size > 0);
    return allocator.rawFree(
        @as([*]u8, @ptrCast(ptr))[0..size],
        alignment.convert() orelse unreachable,
        @returnAddress(),
    );
}

pub export fn wasmstint_fuzz_rust_heap_realloc(ptr: *anyopaque, old_size: usize, alignment: Alignment, new_size: usize) callconv(.c) ?[*]u8 {
    std.debug.assert(old_size > 0);
    std.debug.assert(new_size > 0);
    const old_mem = @as([*]u8, @ptrCast(ptr))[0..old_size];
    const actual_align = alignment.convert() orelse return null;
    const remapped = allocator.rawRemap(
        old_mem,
        actual_align,
        new_size,
        @returnAddress(),
    );

    if (remapped) |new_mem| {
        return new_mem;
    } else {
        const new_mem = allocator.rawAlloc(
            new_size,
            actual_align,
            @returnAddress(),
        ) orelse return null;

        const copy_len = @min(new_size, old_size);
        @memcpy(new_mem[0..copy_len], old_mem[0..copy_len]);
        @memset(new_mem[copy_len..new_size], undefined);

        allocator.rawFree(old_mem, actual_align, @returnAddress());

        return new_mem;
    }
}
