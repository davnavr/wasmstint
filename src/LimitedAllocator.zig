const std = @import("std");
const Allocator = std.mem.Allocator;
const Alignment = std.mem.Alignment;

remaining: *usize,
inner: Allocator,

const LimitedAllocator = @This();

pub fn init(remaining: *usize, inner: Allocator) LimitedAllocator {
    return .{
        .remaining = remaining,
        .inner = inner,
    };
}

const vtable = Allocator.VTable{
    .alloc = alloc,
    .resize = resize,
    .remap = remap,
    .free = free,
};

pub fn allocator(self: *LimitedAllocator) Allocator {
    return .{
        .ptr = self,
        .vtable = &vtable,
    };
}

inline fn checkAllocLimit(self: *LimitedAllocator, additional: usize) Allocator.Error!usize {
    return std.math.sub(usize, self.remaining.*, additional) catch error.OutOfMemory;
}

fn alloc(ctx: *anyopaque, len: usize, alignment: Alignment, ret_addr: usize) ?[*]u8 {
    const self: *LimitedAllocator = @ptrCast(@alignCast(ctx));
    const new_limit = self.checkAllocLimit(len) catch return null;

    const result = self.inner.rawAlloc(len, alignment, ret_addr);

    if (result != null) self.remaining.* = new_limit;
    return result;
}

fn resize(ctx: *anyopaque, memory: []u8, alignment: Alignment, new_len: usize, ret_addr: usize) bool {
    const self: *LimitedAllocator = @ptrCast(@alignCast(ctx));
    const new_limit = self.checkAllocLimit(new_len -| memory.len) catch return false;

    const result = self.inner.rawResize(memory, alignment, new_len, ret_addr);

    if (result) self.remaining.* = new_limit;
    return result;
}

fn remap(ctx: *anyopaque, memory: []u8, alignment: Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
    const self: *LimitedAllocator = @ptrCast(@alignCast(ctx));
    const new_limit = self.checkAllocLimit(new_len -| memory.len) catch return null;

    const result = self.inner.rawRemap(memory, alignment, new_len, ret_addr);

    if (result != null) self.remaining.* = new_limit;
    return result;
}

fn free(ctx: *anyopaque, memory: []u8, alignment: Alignment, ret_addr: usize) void {
    const self: *LimitedAllocator = @ptrCast(@alignCast(ctx));
    self.inner.rawFree(memory, alignment, ret_addr);
    self.remaining.* +|= memory.len;
}
