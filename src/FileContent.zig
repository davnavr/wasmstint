//! Provides a read-only view of a `File`'s contents.

const FileContent = @This();

contents: []align(page_size_min) const u8,
/// On windows, all pages belonging to the same "allocation" must be freed
/// at once, and cannot be partially freed.
allocated_size: if (builtin.os.tag == .windows) usize else void,

const ReadError = Oom || fs.File.OpenError || fs.File.ReadError || fs.File.StatError;

pub fn readFileZ(dir: Dir, path: [:0]const u8) ReadError!FileContent {
    const file = try dir.openFileZ(path, .{ .mode = .read_only });
    defer file.close();

    const page_size = pageSize();
    const indicated_size = std.math.cast(usize, (try file.stat()).size) orelse
        return Oom.OutOfMemory;
    const allocated_size = @max(
        page_size,
        std.mem.alignBackward(
            usize,
            std.math.add(usize, indicated_size, page_size - 1) catch return Oom.OutOfMemory,
            page_size,
        ),
    );

    std.debug.assert(allocated_size >= indicated_size);
    std.debug.assert(allocated_size % page_size == 0);

    if (builtin.os.tag == .windows) {
        @panic("TODO: Windows VirtualAlloc(reserve and allocate) and then decommit");
    } else {
        const allocated: []align(page_size_min) u8 = posix.mmap(
            std.heap.next_mmap_addr_hint, // TODO: Fix need atomic operations
            allocated_size,
            posix.system.PROT.WRITE,
            .{ .TYPE = .PRIVATE, .ANONYMOUS = true },
            -1,
            0,
        ) catch return Oom.OutOfMemory;
        errdefer posix.munmap(allocated);

        const actual_size = try file.readAll(allocated);
        const unused_pages_size = std.mem.alignBackward(
            usize,
            allocated_size - actual_size,
            page_size,
        );

        std.debug.assert(actual_size + unused_pages_size <= allocated_size);
        std.debug.assert(unused_pages_size % page_size == 0);

        const unused_pages_start_offset = allocated_size - unused_pages_size;
        const unused_pages: []align(page_size_min) const u8 = @alignCast(
            allocated[unused_pages_start_offset .. unused_pages_start_offset + unused_pages_size],
        );
        const used_pages = allocated[0..std.mem.alignForward(usize, actual_size, page_size)];
        std.debug.assert(
            @intFromPtr(used_pages.ptr + used_pages.len) <= @intFromPtr(unused_pages.ptr),
        );
        if (unused_pages_size > 0) {
            posix.munmap(unused_pages); // Does Zig allow unmapping some pages at the end?
        }

        // OOM shouldn't occur when "shortening" an allocation
        posix.mprotect(used_pages, posix.system.PROT.READ) catch unreachable;

        return .{ .contents = allocated[0..actual_size], .allocated_size = {} };
    }
}

// pub fn deinit(contents: *FileContent) void {
//     std.heap.PageAllocator.unmap(
//         @alignCast(@constCast(contents.contents.ptr[0..contents.allocated_size])),
//     );
// }

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const Oom = std.mem.Allocator.Error;
const pageSize = std.heap.pageSize;
const page_size_min = std.heap.page_size_min;
const fs = std.fs;
const Dir = fs.Dir;
