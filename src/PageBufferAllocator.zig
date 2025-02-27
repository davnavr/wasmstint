//! Reserves a contiguous region of pages, and serves allocation requests by
//! providing pages from that region.
//!
//! A `PageBufferAllocator` is intended to back another allocator, such as an `ArenaAllocator`.

const std = @import("std");
const windows = std.os.windows;
const posix = std.posix;
const mem = std.mem;
const Allocator = mem.Allocator;
const builtin = @import("builtin");

const use_win32 = builtin.os.tag == .windows;

const has_guard_pages = switch (builtin.mode) {
    .Debug, .ReleaseSafe => true,
    .ReleaseSmall, .ReleaseFast => false,
};

base: [*]align(std.heap.page_size_min) u8,
next: []align(std.heap.page_size_min) u8,

const PageBufferAllocator = @This();

pub const pageSize = std.heap.pageSize;

pub fn init(size: usize) Allocator.Error!PageBufferAllocator {
    if (size == 0) return error.OutOfMemory;

    const page_size = pageSize();
    _ = std.math.add(usize, size, page_size - 1) catch return error.OutOfMemory;
    const rounded_size = std.mem.alignForward(usize, size, page_size);

    const actual_size = if (has_guard_pages)
        std.math.add(usize, rounded_size, page_size * 2) catch
            return error.OutOfMemory
    else
        rounded_size;

    const offsets = if (has_guard_pages)
        .{ .start = page_size, .end = rounded_size + page_size }
    else
        .{ .start = 0, .end = rounded_size };

    std.debug.assert(offsets.end - offsets.start == rounded_size);

    if (use_win32) {
        const base = windows.VirtualAlloc(
            0,
            actual_size,
            windows.MEM_RESERVE,
            windows.PAGE_NOACCESS,
        ) catch return error.OutOfMemory;

        return PageBufferAllocator{
            .base = base,
            .next = @alignCast(base[offsets.start..offsets.end]),
        };
    } else {
        const base = posix.mmap(
            null,
            actual_size,
            posix.PROT.NONE,
            .{
                .TYPE = .PRIVATE,
                .ANONYMOUS = true,
            },
            -1,
            0,
        ) catch return error.OutOfMemory;

        return PageBufferAllocator{
            .base = base.ptr,
            .next = base[offsets.start..offsets.end],
        };
    }
}

fn startPtr(pages: *const PageBufferAllocator) [*]align(std.heap.page_size_min) u8 {
    return @ptrCast(@alignCast(&pages.base[if (has_guard_pages) pageSize() else 0]));
}

fn endPtr(pages: *const PageBufferAllocator) [*]align(std.heap.page_size_min) u8 {
    return @ptrCast(@alignCast(&pages.next.ptr[pages.next.len]));
}

fn alloc(ctx: *anyopaque, requested_size: usize, alignment: mem.Alignment, _: usize) ?[*]u8 {
    std.debug.assert(requested_size > 0);

    const page_size = pageSize();
    if (page_size < alignment.toByteUnits()) return null;

    const pages: *PageBufferAllocator = @ptrCast(@alignCast(ctx));
    if (pages.next.len < requested_size) {
        return null; // Could use linux mremap here?
    }

    const rounded_size = mem.alignForward(usize, requested_size, page_size);
    const buf: []align(std.heap.page_size_min) u8 = @alignCast(pages.next[0..rounded_size]);
    std.debug.assert(@intFromPtr(buf.ptr) % page_size == 0);

    if (use_win32) {
        var old_protect: windows.DWORD = undefined;
        windows.VirtualProtect(
            buf.ptr,
            buf.len,
            windows.PAGE_READWRITE,
            &old_protect,
        ) catch return null;
    } else {
        posix.mprotect(buf, posix.PROT.READ | posix.PROT.WRITE) catch return null;
    }

    std.debug.assertReadable(buf[0..1]);
    std.debug.assertReadable(buf[buf.len - 1 .. buf.len]);

    pages.next = @alignCast(pages.next[buf.len..]);
    std.debug.assert(@intFromPtr(pages.next.ptr) % page_size == 0);

    return buf.ptr;
}

fn resize(ctx: *anyopaque, buf: []u8, alignment: mem.Alignment, new_size: usize, ra: usize) bool {
    std.debug.assert(buf.len > 0);
    if (new_size == 0) {
        free(ctx, buf, alignment, ra);
        return true;
    }

    const page_size = pageSize();
    std.debug.assert(@intFromPtr(buf.ptr) % page_size == 0);
    std.debug.assert(alignment.toByteUnits() <= page_size);

    const rounded_old_size = mem.alignForward(usize, buf.len, page_size);

    // Detect if an attempt was made to resize a guard page or an already freed allocation.
    std.debug.assertReadable(buf[0..1]);
    std.debug.assertReadable(buf.ptr[rounded_old_size - 1 .. rounded_old_size]);

    if (new_size <= rounded_old_size) {
        // Unused space is available in the allocated pages.
        return true;
    }

    // Detect if the buffer actually belongs to this allocator.
    const pages: *PageBufferAllocator = @ptrCast(@alignCast(ctx));
    std.debug.assert(@intFromPtr(pages.startPtr()) <= @intFromPtr(buf.ptr));
    std.debug.assert(@intFromPtr(buf.ptr) <= @intFromPtr(pages.endPtr()));

    // Only allow resizing if `buf` is the last allocation.
    if (@intFromPtr(&buf.ptr[rounded_old_size]) != @intFromPtr(pages.next.ptr))
        return false;

    _ = std.math.add(usize, new_size, page_size - 1) catch return false;
    const rounded_new_size = mem.alignForward(usize, new_size, page_size);

    const additional = rounded_new_size - rounded_old_size;
    std.debug.assert(additional % page_size == 0);

    _ = alloc(ctx, additional, alignment, ra) orelse return false;

    std.debug.assert(@intFromPtr(&buf.ptr[rounded_new_size]) == @intFromPtr(pages.next.ptr));
    std.debug.assertReadable(buf.ptr[rounded_new_size - 1 .. rounded_new_size]);

    return true;
}

fn remap(ctx: *anyopaque, buf: []u8, alignment: mem.Alignment, new_size: usize, ra: usize) ?[*]u8 {
    return if (resize(ctx, buf, alignment, new_size, ra))
        buf.ptr
    else
        null;
}

fn free(ctx: *anyopaque, buf: []u8, alignment: mem.Alignment, _: usize) void {
    std.debug.assert(buf.len > 0);

    const page_size = pageSize();
    std.debug.assert(@intFromPtr(buf.ptr) % page_size == 0);
    std.debug.assert(alignment.toByteUnits() <= page_size);

    const rounded_size = mem.alignForward(usize, buf.len, page_size);

    // Detect if the buffer actually belongs to this allocator.
    const pages: *PageBufferAllocator = @ptrCast(@alignCast(ctx));
    std.debug.assert(@intFromPtr(pages.startPtr()) <= @intFromPtr(buf.ptr));
    std.debug.assert(@intFromPtr(buf.ptr) <= @intFromPtr(pages.endPtr()));

    const page_buf: []align(std.heap.page_size_min) u8 = @alignCast(buf.ptr[0..rounded_size]);

    // Detect if an attempt was made to free a guard page or an already freed allocation.
    std.debug.assertReadable(buf[0..1]);
    std.debug.assertReadable(page_buf[rounded_size - 1 ..]);

    if (use_win32) {
        var old_protect: windows.DWORD = undefined;
        windows.VirtualProtect(
            buf.ptr,
            rounded_size,
            windows.PAGE_NOACCESS,
            &old_protect,
        ) catch unreachable;
    } else {
        posix.mprotect(page_buf, posix.PROT.NONE) catch unreachable;
    }

    if (@intFromPtr(&buf.ptr[rounded_size]) == @intFromPtr(pages.next.ptr)) {
        const old_end_ptr = pages.endPtr();
        pages.next = @alignCast(buf.ptr[0 .. pages.next.len + rounded_size]);
        std.debug.assert(@intFromPtr(pages.endPtr()) == @intFromPtr(old_end_ptr));
    }
}

const vtable = mem.Allocator.VTable{
    .alloc = alloc,
    .resize = resize,
    .remap = remap,
    .free = free,
};

pub fn allocator(pages: *PageBufferAllocator) mem.Allocator {
    return .{
        .ptr = pages,
        .vtable = &vtable,
    };
}

pub fn reset(pages: *PageBufferAllocator) void {
    const arena_size = @intFromPtr(pages.endPtr()) - @intFromPtr(pages.startPtr());
    std.debug.assert(arena_size % pageSize() == 0);
    const arena: []align(std.heap.page_size_min) u8 = @alignCast(pages.startPtr()[0..arena_size]);

    if (use_win32) {
        var old_protect: windows.DWORD = undefined;
        windows.VirtualProtect(
            arena.ptr,
            arena_size,
            windows.PAGE_NOACCESS,
            &old_protect,
        ) catch unreachable;
    } else {
        posix.mprotect(arena, posix.PROT.NONE) catch unreachable;
    }

    pages.next = arena;
}

pub fn deinit(pages: PageBufferAllocator) void {
    std.debug.assert(@intFromPtr(pages.base) % std.heap.pageSize() == 0);
    if (use_win32) {
        windows.VirtualFree(pages.base, 0, windows.MEM_RELEASE);
    } else {
        const page_size = pageSize();
        const size = (@intFromPtr(pages.endPtr()) - @intFromPtr(pages.base)) +
            (if (has_guard_pages) page_size else 0);

        posix.munmap(pages.base[0..size]);
    }
}

test "OOM" {
    const page_size = pageSize();
    var pages = try PageBufferAllocator.init(pageSize() * 2);
    defer pages.deinit();

    const word: *volatile u32 = try pages.allocator().create(u32);
    defer pages.allocator().destroy(@volatileCast(word));
    word.* = 42;

    try std.testing.expectError(
        error.OutOfMemory,
        pages.allocator().alloc(u8, page_size + 1),
    );

    try std.testing.expectEqual(word.*, 42);
}

test "SegmentedList" {
    var pages = try PageBufferAllocator.init(14 * pageSize());
    defer pages.deinit();

    var list = std.SegmentedList(u32, 0){};
    defer list.deinit(pages.allocator());

    // Has bug, if OOM occurs while allocating data segments!
    // try list.growCapacity(pages.allocator(), 100);
    for (0..100) |i| {
        try list.append(pages.allocator(), @intCast(i));
    }

    for (0..100) |i| {
        try std.testing.expectEqual(list.at(i).*, i);
    }
}

test "ArrayList" {
    var pages = try PageBufferAllocator.init(pageSize() * 3);
    defer pages.deinit();

    var list = std.ArrayList(u8).init(pages.allocator());
    defer list.deinit();

    try list.appendSlice("Hello");

    const other = try pages.allocator().alloc(u8, 100);
    defer pages.allocator().free(other);

    try list.appendSlice(" World!");
    try std.testing.expectEqualStrings("Hello World!", list.items);
}
