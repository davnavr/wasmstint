//! Provides a read-only view of a `File`'s contents.

const FileContent = @This();

const has_kind = builtin.os.tag == .windows and builtin.mode == .Debug;

const Ptr = [*]align(page_size_min) const u8;

const Kind = enum(u1) {
    /// The file's contents were read to a virtual memory allocation.
    allocated,
    /// The file's contents were mapped into memory.
    ///
    /// Note that only Windows supports mapping files into memory while also preventing
    /// modifications of the file contents from other processes.
    memory_mapped,
};

const Len = packed struct(usize) {
    /// This only allows mapping with a length `<= std.math.maxInt(isize)`.
    ///
    /// This is fine, as LLVM doesn't even allow allocations that large anyway.
    const Bits = std.meta.Int(.unsigned, @bitSizeOf(usize) - 1);

    bits: Bits,
    kind: Kind,
};

ptr: [*]align(page_size_min) const u8,
len: Len,

pub fn contents(view: FileContent) []align(page_size_min) const u8 {
    return view.ptr[0..view.len.bits];
}

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

const MapError = Oom || fs.File.OpenError;

const empty = FileContent{
    .ptr = @as([]align(page_size_min) const u8, &.{}).ptr,
    .len = Len{ .bits = 0, .kind = .allocated },
};

// pub const MapFileOptions = struct {
//     maximum_size: usize = 0,
// };

// /// Windows-only. Creates a shared read-only view of the given file contents, and prevents
// /// the modification of the file, even by other processes.
// pub fn mapFileW(dir: fs.Dir, path: []const u16) MapError!FileContent {
//     const file = fs.File{
//         .handle = try windows.OpenFile(
//             path,
//             windows.OpenFileOptions{
//                 .dir = dir.fd,
//                 .access_mask = windows.GENERIC_READ,
//                 .creation = windows.FILE_OPEN,
//             },
//         ),
//     };
//     defer file.close();
//     // Acquire a shared lock
//     {
//         var io: windows.IO_STATUS_BLOCK = undefined;
//         const byte_offset: windows.LARGE_INTEGER = 0;
//         try windows.LockFile(
//             file.handle,
//             null,
//             null,
//             null,
//             &io,
//             &byte_offset,
//             // & // Unknown length!
//         );
//     }
//     // https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createfilemappinga#remarks
//     // It is allowed to close the mapping handle *before* calling `UnmapViewOfFile`
// }

// /// See `mapFileW()`.
// pub fn mapFile(
//     dir: fs.Dir,
//     name_allocator: std.mem.Allocator,
//     path: []const u8,
// ) MapError!FileContent {
//     const path_w = try std.unicode.wtf8ToWtf16LeAlloc(name_allocator, path);
//     defer name_allocator.free(path);
//     return mapFileW(dir, path_w);
// }

const ReadError = Oom || fs.File.OpenError || fs.File.ReadError || fs.File.StatError;

/// Cross-platform reading of file contents.
///
/// Reads a file to its end, filling a region of virtual memory that will be marked read-only when
/// this function returns.
pub fn readFileZ(dir: fs.Dir, path: [:0]const u8) ReadError!FileContent {
    const open_options = fs.File.OpenFlags{ .mode = .read_only };
    const file = switch (builtin.os.tag) {
        .windows, .wasi => try dir.openFile(path, open_options),
        else => try dir.openFileZ(path, open_options),
    };
    defer file.close();

    const page_size: Len.Bits = @intCast(pageSize());
    const indicated_size = std.math.cast(Len.Bits, (try file.stat()).size) orelse
        return Oom.OutOfMemory;

    if (indicated_size == 0) {
        return FileContent.empty;
    }

    const allocated_size: Len.Bits = std.mem.alignBackward(
        Len.Bits,
        std.math.add(Len.Bits, indicated_size, page_size - 1) catch return Oom.OutOfMemory,
        page_size,
    );

    std.debug.assert(allocated_size >= indicated_size);
    std.debug.assert(allocated_size % page_size == 0);

    if (builtin.os.tag == .windows) {
        const current_process = windows.GetCurrentProcess();
        var base_address: ?*anyopaque = null;
        var reserve_size: windows.SIZE_T = allocated_size;
        const reserve_status = windows.ntdll.NtAllocateVirtualMemory(
            current_process,
            @ptrCast(&base_address),
            0,
            &reserve_size,
            windows.MEM_COMMIT | windows.MEM_RESERVE,
            windows.PAGE_READWRITE,
        );

        switch (reserve_status) {
            .SUCCESS => {},
            .ALREADY_COMMITTED => unreachable,
            .COMMITMENT_LIMIT, .NO_MEMORY => return Oom.OutOfMemory,
            .INSUFFICIENT_RESOURCES => return fs.File.OpenError.SystemResources,
            .CONFLICTING_ADDRESSES => unreachable,
            .INVALID_HANDLE => unreachable,
            .INVALID_PAGE_PROTECTION => unreachable,
            .OBJECT_TYPE_MISMATCH => unreachable,
            .PROCESS_IS_TERMINATING => unreachable, // Going to die anyways.
            else => return windows.unexpectedStatus(reserve_status),
        }

        const allocated: []align(page_size_min) u8 = @as(
            [*]align(page_size_min) u8,
            @ptrCast(@alignCast(base_address.?)),
        )[0..allocated_size];

        errdefer {
            var allocated_base: *anyopaque = allocated.ptr;
            var region_size: windows.SIZE_T = 0;
            const free_status = windows.ntdll.NtFreeVirtualMemory(
                current_process,
                &allocated_base,
                &region_size,
                windows.MEM_RELEASE,
            );

            std.debug.assert(free_status == .SUCCESS);
        }

        const actual_size: Len.Bits = @intCast(try file.readAll(allocated));
        const pages = calculateAllocationSizes(page_size, allocated, actual_size);
        std.debug.assert(@intFromPtr(pages.used.ptr) == @intFromPtr(base_address));

        if (pages.unused.len > 0) {
            var unused_address: *anyopaque = pages.unused.ptr;
            var region_size: windows.SIZE_T = pages.unused.len;
            const decommit_status = windows.ntdll.NtFreeVirtualMemory(
                current_process,
                &unused_address,
                &region_size,
                windows.MEM_DECOMMIT,
            );

            std.debug.assert(decommit_status == .SUCCESS);
        }

        if (pages.used.len > 0) {
            var used_size: windows.SIZE_T = pages.used.len;
            var dummy_old_protect: windows.DWORD = undefined;
            const protect_status = windows.ntdll.NtProtectVirtualMemory(
                current_process,
                @ptrCast(&base_address),
                &used_size,
                windows.PAGE_READONLY,
                &dummy_old_protect,
            );

            std.debug.assert(protect_status == .SUCCESS);
        }

        return FileContent{
            .ptr = allocated.ptr,
            .len = Len{ .bits = actual_size, .kind = .allocated },
        };
    } else {
        if (builtin.cpu.arch.isWasm() and !builtin.link_libc) {
            // Need a `allocReadFile` function.
            @compileError(
                "WebAssembly does not support mmap without libc, provide an allocator instead",
            );
        }

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

        const actual_size: Len.Bits = @intCast(try file.readAll(allocated));
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

        return FileContent{
            .ptr = allocated.ptr,
            .len = Len{ .bits = actual_size, .kind = .allocated },
        };
    }
}

pub fn deinit(view: FileContent) void {
    if (view.len.bits == 0) {
        std.debug.assert(@intFromPtr(view.ptr) == @intFromPtr(empty.ptr));
        std.debug.assert(view.len.kind == empty.len.kind);
    } else if (builtin.os.tag == .windows) {
        switch (view.len.kind) {
            .allocated => {
                var base_address: *anyopaque = @ptrCast(@constCast(view.ptr));
                var region_size: windows.SIZE_T = 0;
                const status = windows.ntdll.NtFreeVirtualMemory(
                    windows.GetCurrentProcess(),
                    &base_address,
                    &region_size,
                    windows.MEM_RELEASE,
                );

                std.debug.assert(status == .SUCCESS);
            },
            .memory_mapped => @panic("TODO: Unmap file"),
        }
    } else {
        switch (view.len.kind) {
            .allocated => posix.munmap(@constCast(view.contents())),
            .memory_mapped => undefined,
        }
    }
}

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const windows = std.os.windows;
const Oom = std.mem.Allocator.Error;
const pageSize = std.heap.pageSize;
const page_size_min = std.heap.page_size_min;
const fs = std.fs;
