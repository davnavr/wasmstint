//! Allocates `MemInst`s with OS virtual memory pages.
pub const Mapped = extern struct {
    memory: MemInst,

    const empty = Mapped{
        .memory = memory: {
            var memory = MemInst.empty;
            memory.base = @ptrFromInt(page_size_min);
            break :memory memory;
        },
    };

    /// Allocates OS memory pages for use as a `MemInst`.
    ///
    /// Asserts that `size <= initial_capacity <= maximum_size`.
    pub fn allocate(
        /// The initial size in bytes, rounded down to the nearest multiple of `MemInst.page_size`.
        size: usize,
        /// The initial capacity of the memory allocation, in bytes, rounded down to the nearest
        /// multiple of `MemInst.page_size`.
        ///
        /// On Windows, this is the initial amount of memory committed.
        initial_capacity: usize,
        /// The maximum size of the memory allocation, in bytes, rounded down to the nearest
        /// multiple of `MemInst.page_size`.
        ///
        /// On Windows, this is the amount of memory reserved.
        /// On Unix-like platforms, pages with the `PROT_NONE` flag are mapped instead.
        maximum_size: usize,
    ) Oom!Mapped {
        comptime {
            std.debug.assert(page_size_min <= MemInst.page_size);
        }

        std.debug.assert(size <= initial_capacity);
        std.debug.assert(initial_capacity <= maximum_size);

        const reserve: u33 = @min(
            // Maximum limit for 32-bit memories is 4 GiB
            comptime std.math.maxInt(u32) + 1,
            @as(u33, @intCast(std.mem.alignBackward(usize, maximum_size, MemInst.page_size))),
        );

        if (reserve == 0) {
            return empty;
        }

        const capacity = std.mem.alignBackward(u33, @intCast(initial_capacity), MemInst.page_size);
        std.debug.assert(capacity <= reserve);
        if (builtin.mode == .Debug) {
            const page_size = pageSize();
            std.debug.assert(capacity % page_size == 0);
            std.debug.assert(reserve % page_size == 0);
        }

        const single_syscall = capacity == reserve;
        const allocation: []align(page_size_min) u8 = if (builtin.os.tag == .windows) win: {
            var alloc_size: windows.SIZE_T = reserve;
            const base_addr: [*]align(page_size_min) u8 = virtual_memory.nt.allocate(
                null,
                &alloc_size,
                .{ .RESERVE = true, .COMMIT = single_syscall },
                .READWRITE,
            ) catch return Oom.OutOfMemory;
            std.debug.assert(alloc_size == reserve);

            errdefer {
                var freed_size: windows.SIZE_T = reserve;
                virtual_memory.nt.free(base_addr, &freed_size, .RELEASE) catch {};
                std.debug.assert(reserve == freed_size);
            }

            if (!single_syscall and capacity > 0) {
                var commit_size: windows.SIZE_T = capacity;
                const commit_ret = virtual_memory.nt.allocate(
                    base_addr,
                    &commit_size,
                    .{ .COMMIT = true },
                    .READWRITE,
                ) catch return Oom.OutOfMemory;
                std.debug.assert(commit_size == capacity);
                std.debug.assert(@intFromPtr(base_addr) == @intFromPtr(commit_ret));
            }

            break :win base_addr[0..reserve];
        } else posix: {
            const pages = virtual_memory.mman.map_anonymous(
                reserve,
                .{ .WRITE = single_syscall, .READ = single_syscall },
                .{},
            ) catch return Oom.OutOfMemory;
            errdefer virtual_memory.mman.unmap(pages) catch {};

            // This is similar to windows commit behavior
            if (!single_syscall and capacity > 0) {
                virtual_memory.mman.protect(pages[0..capacity], .{ .WRITE = true }) catch
                    return Oom.OutOfMemory;
            }

            break :posix pages;
        };

        errdefer comptime unreachable;

        std.debug.assert(allocation.len == reserve);

        // OS returns pages already filled with all zeroes
        const inst = MemInst{
            .base = allocation.ptr,
            .size = std.mem.alignBackward(usize, size, MemInst.page_size),
            .capacity = capacity,
            .limit = allocation.len,
            .vtable = &vtable,
        };

        inst.checkInvariants();
        return Mapped{ .memory = inst };
    }

    /// Allocates a new `MemInst` corresponding to the given `MemType`.
    ///
    /// The initial size is the minimum specified in the `MemType`.
    ///
    /// Asserts that `initial_capacity` and `maximum_size` are not less than the minimum specified
    /// in the `MemType`.
    pub fn allocateFromType(
        mem_type: *const MemType,
        initial_capacity: usize,
        /// Allows a smaller limit than the one specified in the `mem_type`.
        maximum_size: usize,
    ) Oom!Mapped {
        const min_bytes = @as(u33, @intCast(mem_type.limits.min)) * MemInst.page_size;
        const max_bytes = @as(u33, @intCast(mem_type.limits.max)) * MemInst.page_size;

        std.debug.assert(min_bytes <= max_bytes);
        std.debug.assert(min_bytes <= initial_capacity);

        return allocate(min_bytes, initial_capacity, @min(maximum_size, max_bytes));
    }

    fn checkInvariants(inst: *const Mapped) void {
        if (builtin.mode == .Debug) {
            const mem = inst.memory;
            const page_size = pageSize();
            std.debug.assert(mem.size % page_size == 0);
            std.debug.assert(mem.capacity % page_size == 0);
            // Checking dwAllocationGranularity on Windows is overkill
            std.debug.assert(@intFromPtr(mem.base) % page_size == 0);
        }
    }

    const vtable = MemInst.VTable{
        .grow = grow,
        .free = free,
    };
};

fn free(mem: *MemInst) void {
    const inst: *Mapped = @ptrCast(mem);
    inst.checkInvariants();
    if (builtin.os.tag == .windows) {
        const freed_size: windows.SIZE_T = 0;
        virtual_memory.nt.free(mem.base, &freed_size, .RELEASE) catch |e| unexpectedError(e);
        std.debug.assert(freed_size == mem.limit);
    } else {
        const pages: []align(page_size_min) u8 = @alignCast(mem.base[0..mem.limit]);
        if (pages.len > 0) {
            virtual_memory.mman.unmap(pages) catch |e| unexpectedError(e);
        }
    }
}

inline fn unexpectedError(e: anyerror) void {
    @branchHint(.cold);
    if (std.posix.unexpected_error_tracing) {
        var stderr_buf: [512]u8 align(16) = undefined;
        const stderr, const color = std.debug.lockStderrWriter(&stderr_buf);
        defer std.debug.unlockStderrWriter();
        stderr.print("unexpected error: {t}\n", .{e}) catch {};
        if (@errorReturnTrace()) |trace| {
            std.debug.writeStackTrace(trace, stderr, color) catch {};
        }
    }
}

/// On Windows, new pages are committed from the existing allocation.
/// On Unix-like platforms, `mprotect()` is called to allow access to the new pages.
///
/// Because `MemInst.limit` tracks both the memory's maximum and the current size of
/// the allocation, `mremap()` is unable to be used on Linux without introducing a
/// new `usize` field to track a "reserved capacity".
fn grow(mem: *MemInst, new_size: usize) Oom!void {
    std.debug.assert(new_size % MemInst.page_size == 0);
    std.debug.assert(mem.size < new_size);
    std.debug.assert(mem.capacity < new_size);
    std.debug.assert(new_size <= mem.limit);

    const inst: *Mapped = @ptrCast(mem);
    inst.checkInvariants();

    const new_pages: []align(page_size_min) u8 =
        @alignCast(mem.base[0..mem.limit][mem.capacity..new_size]);
    std.debug.assert(new_pages.len % MemInst.page_size == 0);

    if (builtin.os.tag == .windows) {
        var region_size: windows.SIZE_T = new_pages.len;
        // Newly commited pages are always zeroed.
        const base = virtual_memory.nt.allocate(
            new_pages.ptr,
            &region_size,
            .{ .COMMIT = true },
            .READWRITE,
        ) catch return Oom.OutOfMemory;
        std.debug.assert(@intFromPtr(base) == @intFromPtr(new_pages.ptr));
    } else {
        // These pages were never written to before this `mprotect()` call, so the pages still
        // contain zeroes.
        virtual_memory.mman.protect(new_pages, .{ .READ = true, .WRITE = true }) catch
            return Oom.OutOfMemory;
    }

    mem.size = new_size;
    mem.capacity = new_size;
}

const std = @import("std");
const builtin = @import("builtin");
const windows = std.os.windows;
const pageSize = std.heap.pageSize;
const page_size_min = std.heap.page_size_min;
const Oom = std.mem.Allocator.Error;
const virtual_memory = @import("allocators").virtual_memory;
const MemType = @import("../../Module.zig").MemType;
const MemInst = @import("../memory.zig").MemInst;
