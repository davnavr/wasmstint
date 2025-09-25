const std = @import("std");
const Allocator = std.mem.Allocator;
const Alignment = std.mem.Alignment;

remaining: *usize,
allocated: usize,
inner: Allocator,

const LimitedAllocator = @This();

pub fn init(remaining: *usize, inner: Allocator) LimitedAllocator {
    return .{
        .remaining = remaining,
        .allocated = 0,
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

pub fn resetCount(self: *LimitedAllocator) void {
    self.remaining.* += self.allocated;
    self.allocated = 0;
}

inline fn checkAllocLimit(self: *LimitedAllocator, additional: usize) Allocator.Error!usize {
    return std.math.sub(usize, self.remaining.*, additional) catch error.OutOfMemory;
}

fn alloc(ctx: *anyopaque, len: usize, alignment: Alignment, ret_addr: usize) ?[*]u8 {
    const self: *LimitedAllocator = @ptrCast(@alignCast(ctx));
    const new_limit = self.checkAllocLimit(len) catch return null;

    const result = self.inner.rawAlloc(len, alignment, ret_addr);

    if (result != null) {
        self.remaining.* = new_limit;
        self.allocated += len;
    }

    return result;
}

fn resize(ctx: *anyopaque, memory: []u8, alignment: Alignment, new_len: usize, ret_addr: usize) bool {
    const self: *LimitedAllocator = @ptrCast(@alignCast(ctx));
    const new_limit = if (new_len > memory.len)
        self.checkAllocLimit(new_len - memory.len) catch return false
    else
        self.remaining.* + (memory.len - new_len);

    const result = self.inner.rawResize(memory, alignment, new_len, ret_addr);

    if (result) {
        self.remaining.* = new_limit;
        if (new_len > memory.len) {
            self.allocated += new_len - memory.len;
        } else {
            self.allocated -= (memory.len - new_len);
        }
    }

    return result;
}

fn remap(ctx: *anyopaque, memory: []u8, alignment: Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
    const self: *LimitedAllocator = @ptrCast(@alignCast(ctx));
    const new_limit = if (new_len > memory.len)
        self.checkAllocLimit(new_len - memory.len) catch return null
    else
        self.remaining.* + (memory.len - new_len);

    const result = self.inner.rawRemap(memory, alignment, new_len, ret_addr);

    if (result) |_| {
        self.remaining.* = new_limit;
        if (new_len > memory.len) {
            self.allocated += new_len - memory.len;
        } else {
            self.allocated -= (memory.len - new_len);
        }
    }

    return result;
}

fn free(ctx: *anyopaque, memory: []u8, alignment: Alignment, ret_addr: usize) void {
    const self: *LimitedAllocator = @ptrCast(@alignCast(ctx));
    self.inner.rawFree(memory, alignment, ret_addr);
    self.remaining.* += memory.len;
    self.allocated -= memory.len;
}
