//! A wrapper over some allocator implementation.

const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;

const Impl = if (builtin.mode == .Debug)
    StdGpaImpl
else if (builtin.link_libc)
    LibcMallocImpl
else if (builtin.os.tag == .windows)
    WindowsHeapImpl
else
    StdGpaImpl;

const LibcMallocImpl = struct {
    pub inline fn init() LibcMallocImpl {
        return .{};
    }

    pub inline fn allocator(_: *LibcMallocImpl) Allocator {
        return std.heap.c_allocator;
    }

    pub inline fn deinit(_: *LibcMallocImpl) void {}
};

const WindowsHeapImpl = struct {
    inner: std.heap.HeapAllocator,

    pub fn init() WindowsHeapImpl {
        return .{
            .inner = std.heap.HeapAllocator{
                .heap_handle = std.os.windows.kernel32.GetProcessHeap(),
            },
        };
    }

    pub fn deinit(heap: *WindowsHeapImpl) void {
        defer heap.* = undefined;

        if (heap.inner.heap_handle != std.os.windows.kernel32.GetProcessHeap())
            heap.inner.deinit();
    }
};

const StdGpaImpl = struct {
    inner: std.heap.GeneralPurposeAllocator(.{}),

    pub fn init() StdGpaImpl {
        return .{ .inner = .init };
    }

    pub fn allocator(gpa: *StdGpaImpl) Allocator {
        return gpa.inner.allocator();
    }

    pub fn deinit(gpa: *StdGpaImpl) void {
        _ = gpa.inner.deinit();
    }
};

impl: Impl,

const GlobalAllocator = @This();

pub inline fn init() GlobalAllocator {
    return .{ .impl = Impl.init() };
}

pub inline fn deinit(alloc: *GlobalAllocator) void {
    alloc.impl.deinit();
}

pub inline fn allocator(alloc: *GlobalAllocator) Allocator {
    return alloc.impl.allocator();
}
