//! Allocates `MemInst`s with OS virtual memory pages.

const MapError = ModuleAllocating.LimitsError || Oom;

/// Allocates OS memory pages for use as a `MemInst`.
///
///
/// Asserts that `initial_size <= initial_capacity`.
pub fn map(
    mem_type: *const MemType,
    /// The initial capacity of the memory allocation, in bytes, rounded down to the nearest
    /// multiple of `MemInst.page_size`.
    ///
    /// On Windows, this is the initial amount of memory committed.
    ///
    /// If below `mem_type.limits.min`, then `error.LimitsMismatch` is returned.
    initial_capacity: usize,
    /// The initial total size of the memory allocation, in bytes, rounded down to the nearest
    /// multiple of `MemInst.page_size`.
    ///
    /// On Windows, this is the amount of memory reserved.
    initial_reserve: usize,
) MapError!MemInst {
    comptime {
        std.debug.assert(page_size_min <= MemInst.page_size);
    }

    std.debug.assert(mem_type.limits.min <= mem_type.limits.max);
    std.debug.assert(initial_capacity <= initial_reserve);
    const min_bytes = @as(u32, @intCast(mem_type.limits.min)) * MemInst.page_size;
    const max_bytes = @as(u32, @intCast(mem_type.limits.max)) * MemInst.page_size;

    const reserve: u32 = @intCast(
        @min(
            max_bytes,
            std.mem.alignBackward(usize, initial_reserve, MemInst.page_size),
        ),
    );

    if (min_bytes > reserve) {
        return error.LimitsMismatch;
    }

    const capacity = std.mem.alignBackward(u32, @intCast(initial_capacity), MemInst.page_size);
    std.debug.assert(min_bytes <= capacity);
    std.debug.assert(capacity <= reserve);
    if (builtin.mode == .Debug) {
        const page_size = pageSize();
        std.debug.assert(capacity % page_size == 0);
        std.debug.assert(reserve % page_size == 0);
    }

    const single_syscall = capacity == reserve;
    const allocation: []align(page_size_min) u8 = if (builtin.os.tag == .windows) win: {
        const base_addr = windows.VirtualAlloc(
            null,
            reserve,
            windows.MEM_RESERVE | (if (single_syscall) windows.MEM_COMMIT else 0),
            windows.PAGE_READWRITE,
        ) catch return Oom.OutOfMemory;
        errdefer windows.VirtualFree(base_addr, 0, windows.MEM_RELEASE);

        if (!single_syscall) {
            windows.VirtualAlloc(
                base_addr,
                capacity,
                windows.MEM_COMMIT,
                windows.PAGE_READWRITE,
            ) catch return Oom.OutOfMemory;
        }

        break :win @as([*]align(page_size_min) u8, @alignCast(@ptrCast(base_addr)))[0..reserve];
    } else posix: {
        // see `PageAllocator.map`
        const hint = @atomicLoad(
            @TypeOf(std.heap.next_mmap_addr_hint),
            &std.heap.next_mmap_addr_hint,
            .unordered,
        );

        const pages = posix.mmap(
            hint,
            reserve,
            if (single_syscall) posix.system.PROT.WRITE else posix.system.PROT.NONE,
            .{ .TYPE = .PRIVATE, .ANONYMOUS = true },
            -1,
            0,
        );
        errdefer posix.munmap(pages);

        if (!single_syscall) {
            posix.mprotect(pages[0..capacity], posix.system.PROT.WRITE) catch |e| switch (e) {
                error.OutOfMemory => |oom| return oom,
                error.AccessDenied, error.Unexpected => unreachable,
            };
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

        break :posix pages;
    };

    errdefer comptime unreachable;

    // OS returns pages already filled with all zeroes
    return MemInst{
        .base = allocation.ptr,
        .size = min_bytes,
        .capacity = capacity,
        .limit = allocation.len,
    };
}

/// See `map()`.
///
/// Asserts that another memory still needs allocation.
pub fn allocate(
    request: *ModuleAllocating,
    initial_capacity: usize,
    initial_reserve: usize,
) MapError!void {
    const mem_inst = try map(request.nextMemoryType().?, initial_capacity, initial_reserve);
    request.nextMemory().* = mem_inst;
}

pub fn free(mem: *MemInst) void {
    if (builtin.mode == .Debug) {
        const page_size = pageSize();
        std.debug.assert(mem.size % page_size == 0);
        std.debug.assert(mem.capacity % page_size == 0);
        std.debug.assert(mem.limit % page_size == 0);
    }

    if (builtin.os.tag == .windows) {
        if (builtin.mode == .Debug) {
            var info: windows.SYSTEM_INFO = undefined;
            windows.kernel32.GetSystemInfo(&info);
            std.debug.assert(@intFromPtr(mem.base) % info.dwAllocationGranularity == 0);
        }

        windows.VirtualFree(@ptrCast(mem.base), 0, windows.MEM_RELEASE);
    } else {
        posix.munmap(@alignCast(mem.bytes()));
    }

    mem.* = undefined;
}

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const windows = std.os.windows;
const pageSize = std.heap.pageSize();
const page_size_min = std.heap.page_size_min;
const Oom = std.mem.Allocator.Error;
const MemType = @import("../Module.zig").MemType;
const ModuleAllocating = @import("ModuleAllocating.zig");
const MemInst = @import("memory.zig").MemInst;
