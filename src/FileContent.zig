//! Provides a read-only view of a `File`'s contents.

const FileContent = @This();

contents: []align(page_size_min) const u8,

const ReadError = Oom || fs.File.OpenError || fs.File.ReadError || fs.File.StatError;

fn calculateAllocationSizes(
    page_size: usize,
    allocated: []align(page_size_min) u8,
    actual_size: usize,
) struct { unused: []align(page_size_min) u8, used: []align(page_size_min) u8 } {
    const unused_pages_size = std.mem.alignBackward(
        usize,
        allocated.len - actual_size,
        page_size,
    );

    std.debug.assert(actual_size + unused_pages_size <= allocated.len);
    std.debug.assert(unused_pages_size % page_size == 0);

    const unused_pages_start_offset = allocated.len - unused_pages_size;
    const unused_pages: []align(page_size_min) u8 = @alignCast(
        allocated[unused_pages_start_offset .. unused_pages_start_offset + unused_pages_size],
    );

    const used_pages = allocated[0..std.mem.alignForward(usize, actual_size, page_size)];
    std.debug.assert(
        @intFromPtr(used_pages.ptr + used_pages.len) <= @intFromPtr(unused_pages.ptr),
    );

    return .{ .unused = unused_pages, .used = used_pages };
}

pub fn readFileZ(dir: fs.Dir, path: [:0]const u8) ReadError!FileContent {
    const open_options = fs.File.OpenFlags{ .mode = .read_only };
    const file = switch (builtin.os.tag) {
        .windows, .wasi => try dir.openFile(path, open_options),
        else => try dir.openFileZ(path, open_options),
    };
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
        const reserved = windows.VirtualAlloc(
            null,
            allocated_size,
            windows.MEM_COMMIT | windows.MEM_RESERVE,
            windows.PAGE_READWRITE,
        ) catch return Oom.OutOfMemory;
        errdefer windows.VirtualFree(reserved, 0, windows.MEM_RELEASE);

        const allocated: []align(page_size_min) u8 =
            @as([*]align(page_size_min) u8, @ptrCast(@alignCast(reserved)))[0..allocated_size];

        const actual_size = try file.readAll(allocated);
        const pages = calculateAllocationSizes(page_size, allocated, actual_size);

        if (pages.unused.len > 0) {
            windows.VirtualFree(
                @ptrCast(pages.unused.ptr),
                pages.unused.len,
                windows.MEM_DECOMMIT,
            );
        }

        if (pages.used.len > 0) {
            var dummy_old_protect: windows.DWORD = undefined;
            windows.VirtualProtect(
                @ptrCast(pages.used.ptr),
                pages.used.len,
                windows.PAGE_READONLY,
                &dummy_old_protect,
            ) catch unreachable;
        }

        return .{ .contents = allocated[0..actual_size] };
    } else {
        // see `PageAllocator.map`
        const hint = @atomicLoad(
            @TypeOf(std.heap.next_mmap_addr_hint),
            &std.heap.next_mmap_addr_hint,
            .unordered,
        );

        const allocated: []align(page_size_min) u8 = posix.mmap(
            hint,
            allocated_size,
            posix.system.PROT.WRITE,
            .{ .TYPE = .PRIVATE, .ANONYMOUS = true },
            -1,
            0,
        ) catch return Oom.OutOfMemory;
        errdefer posix.munmap(allocated);

        const actual_size = try file.readAll(allocated);
        const pages = calculateAllocationSizes(page_size, allocated, actual_size);

        if (pages.unused.len > 0) {
            posix.munmap(pages.unused); // Does Zig allow unmapping some pages at the end?
        }

        // see `PageAllocator.map`
        _ = @cmpxchgWeak(
            @TypeOf(std.heap.next_mmap_addr_hint),
            &std.heap.next_mmap_addr_hint,
            hint,
            @constCast(pages.unused.ptr),
            .monotonic,
            .monotonic,
        );

        posix.mprotect(pages.used, posix.system.PROT.READ) catch |e| switch (e) {
            // OOM probably shouldn't occur, since "whole" allocation is marked read-only
            error.OutOfMemory => |oom| return oom,
            else => unreachable,
        };

        return .{ .contents = allocated[0..actual_size] };
    }
}

// pub fn deinit(contents: *FileContent) void {
//     // Should instead use posix.unmap and windows.VirtualFree
//     std.heap.PageAllocator.unmap(
//         @alignCast(@constCast(contents.contents.ptr[0..contents.allocated_size])),
//     );
// }

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const windows = std.os.windows;
const Oom = std.mem.Allocator.Error;
const pageSize = std.heap.pageSize;
const page_size_min = std.heap.page_size_min;
const fs = std.fs;
