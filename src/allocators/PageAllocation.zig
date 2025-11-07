//! `Allocator` implementation for allocating and resizing a single object that uses virtual memory
//! obtained from the OS.

/// `current.len == 0` only when there is not yet an "allocated object".
current: []align(page_size_min) u8,
/// Maximum size that `current` can be, in bytes, without asking the OS for more pages.
allocated: Len,
info: packed struct(usize) {
    maximum: Len,
    has_guard_pages: bool,
},

const PageAllocation = @This();

/// LLVM disallows objects with size overflowing `isize` anyways.
const Len = std.meta.Int(.unsigned, @typeInfo(usize).int.bits - 1);

// const has_mremap = posix.MREMAP != void;

fn checkInvariants(ctx: *const PageAllocation) void {
    const page_size = pageSize();
    std.debug.assert(ctx.info.maximum % page_size == 0);
    std.debug.assert(ctx.allocated % page_size == 0);
    std.debug.assert(ctx.current.len <= ctx.allocated);
    std.debug.assert(ctx.allocated <= ctx.info.maximum);
}

pub const InitOptions = struct {
    /// Specifies an initial amount of memory to reserve for the allocated object, in bytes,
    /// rounded up to a multiple of the page size.
    ///
    /// Must not exceed the `maximum` size.
    ///
    /// - On Windows, this is the initial amount of memory to commit.
    /// - On Unix-like platforms, this is the initial amount to `mprotect` as
    ///   `PROT_READ | PROT_WRITE`.
    preallocate_size: usize = 0,

    /// If `true`, guard pages are placed both before and after the allocation.
    guard_pages: bool = switch (builtin.mode) {
        .Debug, .ReleaseSafe => true,
        .ReleaseFast, .ReleaseSmall => false,
    },

    // /// On platforms that support `mremap()` (currently only Linux), specifies the initial
    // /// amount to `mmap()`.
    // ///
    // /// Must be `>= preallocate_size` and `<= maximum` size.
    // ///
    // /// If equal to the `maximum` size, then the behavior is the same as on other Unix-like
    // /// platforms.
    // initial_size: if (has_remap) usize else void = if (has_remap) 0,
};

fn tryAlignForward(size: usize, align_bytes: Len) Oom!Len {
    return std.mem.alignBackward(
        Len,
        std.math.add(
            Len,
            std.math.cast(Len, size) orelse return Oom.OutOfMemory,
            align_bytes - 1,
        ) catch return Oom.OutOfMemory,
        align_bytes,
    );
}

pub fn init(
    options: InitOptions,
    /// Maximum allowed size of the allocation, in bytes, rounded up to a multiple of the page size.
    ///
    /// - On Windows, this is the amount of memory to reserve.
    /// - On Unix-like platforms, this attempts to replicate behavior on Windows using `PROT_NONE`,
    /// and is the size passed to the `mmap()` call.
    maximum_size: usize,
) Oom!PageAllocation {
    std.debug.assert(options.preallocate_size <= maximum_size);

    if (maximum_size == 0) {
        @branchHint(.cold);
        return PageAllocation{
            .current = &.{},
            .allocated = 0,
            .info = .{ .maximum = 0, .has_guard_pages = false },
        };
    }

    const page_size: Len = @intCast(pageSize());
    const rounded_max = try tryAlignForward(maximum_size, page_size);

    const allocate_size = if (options.guard_pages)
        std.math.add(Len, rounded_max, page_size * 2) catch return Oom.OutOfMemory
    else
        rounded_max;

    // Won't overflow
    const rounded_preallocate = std.mem.alignForward(
        Len,
        @intCast(options.preallocate_size),
        page_size,
    );

    const allocate_all_rw = !options.guard_pages and rounded_preallocate == rounded_max;

    const allocated_pages: []align(page_size_min) u8 = if (builtin.os.tag == .windows) win: {
        var region_size: windows.SIZE_T = allocate_size;
        const allocated_base = virtual_memory.nt.allocate(
            null,
            &region_size,
            .{ .RESERVE = true, .COMMIT = allocate_all_rw },
            if (options.guard_pages) .NOACCESS else .READWRITE,
        ) catch return Oom.OutOfMemory;

        break :win allocated_base[0..allocate_size];
    } else virtual_memory.mman.map_anonymous(
        allocate_size,
        .{ .READ = allocate_all_rw, .WRITE = allocate_all_rw },
        .{},
    ) catch return Oom.OutOfMemory;

    errdefer if (builtin.os.tag == .windows) {
        var region_size: windows.SIZE_T = 0;
        virtual_memory.nt.free(allocated_pages.ptr, &region_size, .RELEASE) catch {};
    } else {
        virtual_memory.mman.unmap(allocated_pages) catch {};
    };

    const preallocate_offset = if (options.guard_pages) page_size else 0;
    const preallocate_pages: []align(page_size_min) u8 = @alignCast(
        allocated_pages[preallocate_offset .. preallocate_offset + rounded_preallocate],
    );
    std.debug.assert(preallocate_pages.len == rounded_preallocate);

    if (rounded_preallocate > 0 and rounded_preallocate < rounded_max) {
        if (builtin.os.tag == .windows) {
            var region_size: windows.SIZE_T = rounded_preallocate;
            _ = virtual_memory.nt.allocate(
                preallocate_pages.ptr,
                &region_size,
                .{ .COMMIT = true },
                .READWRITE,
            ) catch return Oom.OutOfMemory;
        } else {
            _ = virtual_memory.mman.protect(
                preallocate_pages,
                .{ .READ = true, .WRITE = true },
            ) catch return Oom.OutOfMemory;
        }
    }

    if (options.guard_pages) {
        const low_guard: []align(page_size_min) u8 = allocated_pages[0..page_size];
        const high_guard: []align(page_size_min) u8 = @alignCast(
            allocated_pages[allocated_pages.len - page_size ..],
        );
        std.debug.assert(preallocate_pages.len + (page_size * 2) <= allocated_pages.len);

        if (builtin.os.tag == .windows) {
            var region_size: windows.SIZE_T = page_size;
            _ = virtual_memory.nt.allocate(
                low_guard.ptr,
                &region_size,
                .{ .COMMIT = true },
                .NOACCESS,
            ) catch return Oom.OutOfMemory;
            std.debug.assert(region_size == page_size);
            _ = virtual_memory.nt.allocate(
                high_guard.ptr,
                &region_size,
                .{ .COMMIT = true },
                .NOACCESS,
            ) catch return Oom.OutOfMemory;
        } else {
            _ = virtual_memory.mman.protect(low_guard, .{}) catch return Oom.OutOfMemory;
            _ = virtual_memory.mman.protect(high_guard, .{}) catch return Oom.OutOfMemory;
        }
    }

    return PageAllocation{
        .allocated = rounded_preallocate,
        .current = preallocate_pages[0..0],
        .info = .{ .maximum = rounded_max, .has_guard_pages = options.guard_pages },
    };
}

const vtable = Allocator.VTable{
    .alloc = alloc,
    .resize = resize,
    .remap = remap,
    .free = free,
};

pub fn allocator(ctx: *PageAllocation) Allocator {
    return Allocator{ .ptr = @ptrCast(ctx), .vtable = &vtable };
}

pub fn grow(ctx: *PageAllocation, new_capacity: usize) Oom!void {
    ctx.checkInvariants();

    const page_size = pageSize();
    const new_allocated = try tryAlignForward(new_capacity, page_size);
    if (new_allocated <= ctx.allocated) {
        @branchHint(.likely);
        return;
    } else if (new_allocated > ctx.info.maximum) {
        @branchHint(.cold);
        return Oom.OutOfMemory; // reached maximum
    }

    const new_pages_len = new_allocated - ctx.allocated;
    const new_pages: []align(page_size_min) u8 = @alignCast(
        ctx.current.ptr[ctx.allocated..ctx.info.maximum][0..new_pages_len],
    );
    std.debug.assert(new_pages.len % page_size == 0);

    if (builtin.os.tag == .windows) {
        var region_size: windows.SIZE_T = new_pages_len;
        _ = virtual_memory.nt.allocate(
            new_pages.ptr,
            &region_size,
            .{ .COMMIT = true },
            .READWRITE,
        ) catch return Oom.OutOfMemory;
    } else {
        virtual_memory.mman.protect(new_pages, .{ .READ = true, .WRITE = true }) catch
            return Oom.OutOfMemory;
    }

    ctx.allocated = new_allocated;
}

// Could use `MADV_FREE` or `MADV_DONTNEED` (`MEM_RESET` on Windows) when shrinking the allocation

fn alloc(ctx: *anyopaque, len: usize, alignment: Alignment, ret_addr: usize) ?[*]u8 {
    std.debug.assert(len > 0);
    _ = ret_addr;

    const self: *PageAllocation = @ptrCast(@alignCast(ctx));
    self.checkInvariants();
    defer self.checkInvariants();

    const page_size: Len = @intCast(pageSize());
    if (alignment.toByteUnits() > page_size or self.current.len != 0) {
        @branchHint(.cold);
        return null;
    }

    self.grow(len) catch return null;
    self.current.len = len;
    return self.current.ptr;
}

fn resize(
    ctx: *anyopaque,
    memory: []u8,
    alignment: Alignment,
    new_len: usize,
    ret_addr: usize,
) bool {
    std.debug.assert(memory.len > 0);

    const self: *PageAllocation = @ptrCast(@alignCast(ctx));
    self.checkInvariants();
    defer self.checkInvariants();

    if (alignment.toByteUnits() > pageSize()) {
        @branchHint(.cold);
        return false;
    }

    if (new_len == 0) {
        free(ctx, memory, alignment, ret_addr);
        return true;
    }

    std.debug.assert(@intFromPtr(memory.ptr) == @intFromPtr(self.current.ptr));
    if (builtin.mode == .Debug and memory.len != self.current.len) {
        std.debug.panic(
            "expected {*} to have length {d}, is {d}",
            .{ memory.ptr, self.current.len, memory.len },
        );
    }

    if (memory.len < new_len) {
        self.grow(new_len) catch return false;
    }

    self.current.len = new_len;
    return true;
}

fn remap(
    ctx: *anyopaque,
    memory: []u8,
    alignment: Alignment,
    new_len: usize,
    ret_addr: usize,
) ?[*]u8 {
    return if (resize(ctx, memory, alignment, new_len, ret_addr))
        memory.ptr
    else
        return null;
}

fn free(
    ctx: *anyopaque,
    memory: []u8,
    alignment: Alignment,
    ret_addr: usize,
) void {
    std.debug.assert(memory.len > 0);
    _ = ret_addr;

    const self: *PageAllocation = @ptrCast(@alignCast(ctx));
    self.checkInvariants();
    defer self.checkInvariants();

    const page_size = pageSize();
    std.debug.assert(alignment.toByteUnits() <= page_size);

    std.debug.assert(@intFromPtr(memory.ptr) == @intFromPtr(self.current.ptr));
    std.debug.assert(memory.len == self.current.len);

    self.current.len = 0;
}

pub fn deinit(ctx: *PageAllocation) void {
    ctx.checkInvariants();

    defer ctx.* = undefined;

    if (ctx.info.maximum == 0) {
        @branchHint(.unlikely);
        return;
    }

    const page_size = pageSize();
    const pages: []align(page_size_min) u8 = if (ctx.info.has_guard_pages)
        (ctx.current.ptr - page_size)[0 .. ctx.info.maximum + (page_size * 2)]
    else
        ctx.current.ptr[0..ctx.info.maximum];

    if (builtin.os.tag == .windows) {
        var region_size: windows.SIZE_T = 0;
        virtual_memory.nt.free(pages.ptr, &region_size, .RELEASE) catch {};
    } else {
        virtual_memory.mman.unmap(pages) catch {};
    }
}

const std = @import("std");
const windows = std.os.windows;
const posix = std.posix;
const Allocator = std.mem.Allocator;
const Alignment = std.mem.Alignment;
const Oom = Allocator.Error;
const builtin = @import("builtin");
const pageSize = std.heap.pageSize;
const page_size_min = std.heap.page_size_min;
const virtual_memory = @import("virtual_memory.zig");

fn testArrayList(init_options: InitOptions, maximum: usize) !void {
    var ctx = try PageAllocation.init(init_options, maximum);
    defer ctx.deinit();

    const gpa = ctx.allocator();
    var list = try std.ArrayList(u64)
        .initCapacity(ctx.allocator(), @divExact(maximum, @sizeOf(u64)));
    try list.append(gpa, 42);
    defer list.deinit(gpa);

    // Already existing allocation
    try std.testing.expectError(error.OutOfMemory, gpa.create(u64));

    for (0..@divExact(ctx.info.maximum, @sizeOf(u64)) - 1) |i| {
        try list.append(gpa, i);
    }

    try std.testing.expectEqual(42, list.items[0]);

    // Full
    try std.testing.expectError(error.OutOfMemory, list.append(gpa, 12345678));

    list.clearAndFree(gpa);

    const a = try gpa.create(u64);
    a.* = 43;

    // Full again
    try std.testing.expectError(error.OutOfMemory, list.append(gpa, 0xABCDEF01));

    try std.testing.expectEqual(43, a.*);
}

test "ArrayList" {
    const page_size = pageSize();
    try testArrayList(.{ .guard_pages = false }, page_size);
    try testArrayList(.{ .preallocate_size = 100, .guard_pages = false }, page_size * 2);
    try testArrayList(.{ .preallocate_size = page_size, .guard_pages = true }, page_size * 3);
}
