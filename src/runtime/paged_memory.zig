//! Allocates `MemInst`s with OS virtual memory pages.

const MapError = ModuleAllocating.LimitsError || Oom;

/// Allocates OS memory pages for use as a `MemInst`.
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
    /// The maximum size of the memory allocation, in bytes, rounded down to the nearest
    /// multiple of `MemInst.page_size`.
    ///
    /// On Windows, this is the amount of memory reserved.
    /// On Unix-like platforms, pages with the `PROT_NONE` flag are mapped instead.
    maximum_size: usize,
) MapError!MemInst {
    comptime {
        std.debug.assert(page_size_min <= MemInst.page_size);
    }

    std.debug.assert(mem_type.limits.min <= mem_type.limits.max);
    std.debug.assert(initial_capacity <= maximum_size);
    const min_bytes = @as(u33, @intCast(mem_type.limits.min)) * MemInst.page_size;
    const max_bytes = @as(u33, @intCast(mem_type.limits.max)) * MemInst.page_size;

    const reserve: u33 = @intCast(
        @min(
            max_bytes,
            std.mem.alignBackward(usize, maximum_size, MemInst.page_size),
        ),
    );

    if (reserve < min_bytes) {
        return error.LimitsMismatch;
    }

    if (reserve == 0) {
        return MemInst{
            .base = @ptrFromInt(std.heap.page_size_max),
            .size = 0,
            .capacity = 0,
            .limit = 0,
        };
    }

    const capacity = std.mem.alignBackward(u33, @intCast(initial_capacity), MemInst.page_size);
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
            if (single_syscall)
                (posix.system.PROT.WRITE | posix.system.PROT.READ)
            else
                posix.system.PROT.NONE,
            .{ .TYPE = .PRIVATE, .ANONYMOUS = true },
            -1,
            0,
        ) catch |e| switch (e) {
            error.OutOfMemory => |oom| return oom,
            else => unreachable,
        };
        errdefer posix.munmap(pages);

        // This recreates windows commit behavior
        // TODO: Linux has mremap so only other Unix targets are required to do this
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
            @constCast(@alignCast(pages.ptr[pages.len..pages.len].ptr)),
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
    maximum: usize,
) MapError!void {
    const mem_inst = try map(request.nextMemoryType().?, initial_capacity, maximum);
    request.nextMemory().* = mem_inst;
}

fn checkMemInst(mem: *const MemInst) void {
    if (builtin.mode == .Debug) {
        const page_size = pageSize();
        std.debug.assert(mem.size % page_size == 0);
        std.debug.assert(mem.capacity % page_size == 0);
        std.debug.assert(mem.limit % page_size == 0);
        // Checking dwAllocationGranularity on Windows is overkill
        std.debug.assert(@intFromPtr(mem.base) % page_size == 0);
    }
}

pub fn free(mem: *MemInst) void {
    checkMemInst(mem);
    if (builtin.os.tag == .windows) {
        windows.VirtualFree(@ptrCast(mem.base), 0, windows.MEM_RELEASE);
    } else {
        posix.munmap(@alignCast(mem.bytes()));
    }

    mem.* = undefined;
}

/// Fulfills a growth request for the given memory instance allocated in OS virtual memory pages.
///
/// On Windows, new pages are committed from the existing allocation.
/// On Unix-like platforms, `mprotect()` is called to allow access to the new pages.
///
/// Because `MemInst.limit` tracks both the memory's maximum and the current size of
/// the allocation, `mremap` is unable to be used on Linux without introducing a
/// new `usize` value to track a "reserved capacity".
pub fn grow(
    request: *const Interpreter.InterruptionCause.MemoryGrow,
) void {
    checkMemInst(request.memory);
    // No overflow, already handled by Interpreter's memory.grow handler
    std.debug.assert(request.old_size <= request.new_size);
    std.debug.assert(request.new_size <= request.memory.limit);
    std.debug.assert(request.new_size % MemInst.buffer_align == 0);

    if (request.new_size <= request.memory.size) {
        std.debug.assert(request.new_size <= request.memory.capacity);
        return; // resize already occurred
    }

    const new_pages: []align(page_size_min) u8 = @alignCast(
        request.memory.base[0..request.memory.limit][request.memory.size..request.new_size],
    );

    if (builtin.os.tag == .windows) {
        windows.VirtualAlloc(
            @ptrCast(new_pages),
            new_pages.len,
            windows.MEM_COMMIT,
            windows.PAGE_READWRITE,
        ) catch return;
    } else {
        posix.mprotect(new_pages, posix.PROT.READ | posix.PROT.WRITE) catch |e| switch (e) {
            error.OutOfMemory => return,
            error.AccessDenied, error.Unexpected => unreachable,
        };
    }

    request.memory.capacity = request.new_size;
    request.result.i32 = @intCast(request.old_size);
}

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const windows = std.os.windows;
const pageSize = std.heap.pageSize;
const page_size_min = std.heap.page_size_min;
const Oom = std.mem.Allocator.Error;
const MemType = @import("../Module.zig").MemType;
const ModuleAllocating = @import("ModuleAllocating.zig");
const MemInst = @import("memory.zig").MemInst;
const Interpreter = @import("../Interpreter.zig");
