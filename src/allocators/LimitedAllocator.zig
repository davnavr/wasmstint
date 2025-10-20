//! Wraps an existing `Allocator` implementation to limit the amount of memory it can allocate.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Alignment = std.mem.Alignment;

/// Pointer to the remaining amount of memory that can be allocated, in bytes.
remaining: *usize,
/// The current amount of memory that has been allocated, in bytes.
allocated: usize,
inner: Allocator,

const LimitedAllocator = @This();

pub fn init(
    /// The maximum amount of memory that can be allocated.
    ///
    /// Decreasing this value while the allocator is in use has the effect of reducing the amount
    /// of memory that is allowed to be allocated.
    ///
    /// It is not recommended to increment this value.
    remaining: *usize,
    inner: Allocator,
) LimitedAllocator {
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
    self.remaining.* +|= memory.len;
    self.allocated -|= memory.len;
}

test {
    var remaining: usize = 8;
    var limited = LimitedAllocator.init(&remaining, std.testing.allocator);
    const interface = limited.allocator();

    const a = try interface.create(i64);
    defer interface.destroy(a);
    a.* = 42;

    try std.testing.expectError(error.OutOfMemory, interface.create(u8));
}
