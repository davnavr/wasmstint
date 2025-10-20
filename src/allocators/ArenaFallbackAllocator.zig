/// Where allocations go until it is full.
///
/// Allocated in the `arena`.
///
/// Because the underlying `arena` can already allocate "next" to the `buffer` when it is
/// full, no logic is needed to attempt to resize the `buffer`.
buffer: FixedBufferAllocator,
arena: *std.heap.ArenaAllocator,

const ArenaFallbackAllocator = @This();

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

const std = @import("std");
const Allocator = std.mem.Allocator;
const Alignment = std.mem.Alignment;
const FixedBufferAllocator = std.heap.FixedBufferAllocator;
