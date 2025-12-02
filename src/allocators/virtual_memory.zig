//! Thin wrappers over OS virtual memory allocation APIs.

/// Windows `ntdll` virtual memory APIs (e.g. `NtAllocateVirtualMemory` instead of `VirtualAlloc`).
pub const nt = struct {
    pub const AllocateVirtualMemoryError = Oom || std.posix.UnexpectedError || error{
        AlreadyCommitted,
        SystemResources,
        /// An existing virtual memory allocation already existed within
        /// `base_address..base_address + region_size`.
        ConflictingAddresses,
    };

    pub const AllocationType = packed struct(windows.ULONG) {
        _0: u12 = 0,
        COMMIT: bool = false,
        RESERVE: bool = false,
        _14: u5 = 0,
        RESET: bool = false,
        TOP_DOWN: bool = false,
        WRITE_WATCH: bool = false,
        PHYSICAL: bool = false,
        _23: u1 = 0,
        RESET_UNDO: bool = false,
        _25: u4 = 0,
        LARGE_PAGES: bool = false,
        _30: u2 = 0,

        comptime {
            for (@typeInfo(AllocationType).@"struct".fields) |field| {
                if (field.type != bool) {
                    continue;
                }

                const expected: windows.ULONG = @field(windows, "MEM_" ++ field.name);
                var actual = AllocationType{};
                @field(actual, field.name) = true;

                const actual_bits: windows.ULONG = @bitCast(actual);
                if (expected != actual_bits) {
                    @compileError(
                        std.fmt.comptimePrint(
                            "expected 0x{X:0>8} (MEM_" ++ field.name ++ "), got 0x{X:0>8}",
                            .{ expected, actual_bits },
                        ),
                    );
                }
            }

            std.debug.assert(@as(u32, @bitCast(AllocationType{})) == 0);
        }
    };

    /// Subset of the Windows [memory protection constants] (`PAGE_*`).
    ///
    /// [memory protection constants]: https://learn.microsoft.com/en-us/windows/win32/Memory/memory-protection-constants
    pub const Protection = enum(windows.ULONG) {
        NOACCESS = windows.PAGE_NOACCESS,
        READONLY = windows.PAGE_READONLY,
        READWRITE = windows.PAGE_READWRITE,
        _,
    };

    /// Returns the base of the base address of the allocated region of pages.
    ///
    /// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntallocatevirtualmemory
    pub fn allocate(
        base_address: ?[*]align(page_size_min) u8,
        region_size: *windows.SIZE_T,
        allocation_type: AllocationType,
        protection: Protection,
    ) AllocateVirtualMemoryError![*]align(page_size_min) u8 {
        var ret_base_address: ?*anyopaque = @ptrCast(base_address);
        const status = windows.ntdll.NtAllocateVirtualMemory(
            windows.GetCurrentProcess(),
            @ptrCast(&ret_base_address),
            0,
            region_size,
            @as(windows.ULONG, @bitCast(allocation_type)),
            @intFromEnum(protection),
        );

        return switch (status) {
            .SUCCESS => @ptrCast(@alignCast(ret_base_address.?)),
            .ALREADY_COMMITTED => error.AlreadyCommitted,
            .COMMITMENT_LIMIT, .NO_MEMORY => Oom.OutOfMemory,
            .INSUFFICIENT_RESOURCES => error.SystemResources,
            .CONFLICTING_ADDRESSES => error.ConflictingAddresses,
            .INVALID_HANDLE => unreachable,
            .INVALID_PAGE_PROTECTION => unreachable,
            .INVALID_PARAMETER_2 => unreachable, // base address ptr
            .INVALID_PARAMETER_3 => unreachable, // zero bits
            .INVALID_PARAMETER_4 => unreachable, // region size ptr
            .INVALID_PARAMETER_5 => unreachable, // allocation type
            .INVALID_PARAMETER_6 => unreachable, // protection flags
            .PROCESS_IS_TERMINATING => Oom.OutOfMemory, // Going to die anyways.
            // .ACCESS_DENIED, .OBJECT_TYPE_MISMATCH,
            else => windows.unexpectedStatus(status),
        };
    }

    pub const FreeType = enum(windows.ULONG) {
        DECOMMIT = windows.MEM_DECOMMIT,
        RELEASE = windows.MEM_RELEASE,
        _,
    };

    pub fn free(
        base_address: [*]align(page_size_min) u8,
        region_size: *windows.SIZE_T,
        free_type: FreeType,
    ) posix.UnexpectedError!void {
        var freed_address: ?*anyopaque = @ptrCast(base_address);
        const status = windows.ntdll.NtFreeVirtualMemory(
            windows.GetCurrentProcess(),
            @ptrCast(&freed_address),
            region_size,
            @intFromEnum(free_type),
        );

        switch (status) {
            .SUCCESS => {},
            .INVALID_HANDLE => unreachable,
            .INVALID_PARAMETER_2 => unreachable, // base ptr
            .INVALID_PARAMETER_3 => unreachable, // region size ptr
            .INVALID_PARAMETER_4 => unreachable, // free type
            else => return windows.unexpectedStatus(status),
        }
    }

    pub const ProtectError = posix.UnexpectedError || Oom || error{
        ConflictingAddresses,
        SystemResources,
    };

    pub fn protect(
        pages: []align(page_size_min) u8,
        new_protection: Protection,
    ) ProtectError!Protection {
        var base_address: ?*anyopaque = @ptrCast(pages.ptr);
        var region_size: windows.SIZE_T = pages.len;
        var old_protect: windows.DWORD = undefined;
        const status = windows.ntdll.NtProtectVirtualMemory(
            windows.GetCurrentProcess(),
            @ptrCast(&base_address),
            &region_size,
            @intFromEnum(new_protection),
            &old_protect,
        );

        return switch (status) {
            .SUCCESS => @enumFromInt(old_protect),
            .NO_MEMORY => return Oom.OutOfMemory,
            .INSUFFICIENT_RESOURCES => return error.SystemResources,
            .INVALID_HANDLE => unreachable,
            .INVALID_PAGE_PROTECTION => unreachable,
            .INVALID_PARAMETER_2 => unreachable, // base address ptr
            .INVALID_PARAMETER_3 => unreachable, // region size ptr
            .INVALID_PARAMETER_4 => unreachable, // new protection
            .INVALID_PARAMETER_5 => unreachable, // old protection ptr
            .PROCESS_IS_TERMINATING => return Oom.OutOfMemory, // Going to die anyways.
            .CONFLICTING_ADDRESSES => return error.ConflictingAddresses,
            .NOT_COMMITTED => unreachable,
            else => return windows.unexpectedStatus(status),
        };
    }
};

/// POSIX and Unix-like memory management apis (`mman.h`).
pub const mman = struct {
    pub const has_mmap_anonymous = posix.MAP != void and @hasField(posix.MAP, "ANONYMOUS");

    pub const Prot = @Type(.{
        .@"struct" = std.builtin.Type.Struct{
            .layout = .@"packed",
            .backing_integer = u32,
            .decls = &.{},
            .is_tuple = false,
            .fields = fields: {
                @setEvalBranchQuota(5000);
                var fields: [32]std.builtin.Type.StructField = undefined;
                for (0.., &fields) |i, *f| {
                    f.* = .{
                        .name = std.fmt.comptimePrint("_{d}", .{i}),
                        .type = bool,
                        .default_value_ptr = @ptrCast(&false),
                        .is_comptime = false,
                        .alignment = 0,
                    };
                }

                const src_decls = @typeInfo(posix.PROT).@"struct".decls;
                for (src_decls) |d| {
                    const value: u32 = @field(posix.PROT, d.name);
                    if (@popCount(value) != 1) {
                        continue;
                    }

                    fields[@ctz(value)].name = d.name;
                }

                break :fields &fields;
            },
        },
    });

    comptime {
        if (posix.PROT != void) {
            std.debug.assert(
                @as(u32, @bitCast(Prot{ .READ = true, .WRITE = true })) ==
                    posix.PROT.READ | posix.PROT.WRITE,
            );
        }
    }

    pub const Flags = struct {
        // left blank for now...
    };

    pub const MapError = Oom || posix.UnexpectedError;

    /// - [POSIX](https://pubs.opengroup.org/onlinepubs/009604499/functions/mmap.html)
    /// - [Linux (man7)](https://man7.org/linux/man-pages/man2/mmap.2.html)
    /// - [FreeBSD](https://man.freebsd.org/cgi/man.cgi?mmap(2))
    pub fn map_anonymous(
        length: usize,
        prot: Prot,
        flags: Flags,
    ) MapError![]align(page_size_min) u8 {
        if (comptime !has_mmap_anonymous) {
            @compileError("target platform " ++ @tagName(builtin.cpu.arch) ++ "-" ++
                @tagName(builtin.os.tag) ++ " does not support mmap with MAP_ANONYMOUS");
        }

        std.debug.assert(length > 0);

        _ = flags;

        // see `PageAllocator.map`
        const hint = @atomicLoad(
            @TypeOf(std.heap.next_mmap_addr_hint),
            &std.heap.next_mmap_addr_hint,
            .unordered,
        );

        const pages = posix.mmap(
            hint,
            length,
            @as(u32, @bitCast(prot)),
            posix.MAP{ .TYPE = .PRIVATE, .ANONYMOUS = true },
            -1,
            0,
        ) catch |e| switch (e) {
            error.AccessDenied => unreachable,
            error.MemoryMappingNotSupported => unreachable,
            error.PermissionDenied => unreachable,
            error.ProcessFdQuotaExceeded => unreachable,
            error.SystemFdQuotaExceeded => unreachable,
            else => return Oom.OutOfMemory,
        };

        // see `PageAllocator.map`
        _ = @cmpxchgWeak(
            @TypeOf(std.heap.next_mmap_addr_hint),
            &std.heap.next_mmap_addr_hint,
            hint,
            @alignCast(@constCast(pages.ptr[pages.len..pages.len].ptr)),
            .monotonic,
            .monotonic,
        );

        return pages;
    }

    pub const ProtectError = posix.UnexpectedError || Oom;

    pub fn protect(
        /// Must refer to anonymously mapped memory.
        pages: []align(page_size_min) u8,
        prot: Prot,
    ) ProtectError!void {
        std.debug.assert(pages.len > 0);
        return posix.mprotect(pages, @as(u32, @bitCast(prot))) catch |e| switch (e) {
            error.OutOfMemory, error.Unexpected => |err| err,
            error.AccessDenied => unreachable, // `mprotect` on mapped file
        };
    }

    pub const UnmapError = posix.UnexpectedError || Oom;

    pub fn unmap(pages: []align(page_size_min) u8) UnmapError!void {
        std.debug.assert(pages.len > 0);

        // Zig wrapper `std.posix.munmap` doesn't allow freeing in the middle of existing mapping.
        switch (posix.errno(posix.system.munmap(pages.ptr, pages.len))) {
            .SUCCESS => {},
            .INVAL => unreachable,
            .NOMEM => return error.OutOfMemory,
            else => |bad| return posix.unexpectedErrno(bad),
        }
    }
};

const std = @import("std");
const builtin = @import("builtin");
const page_size_min = std.heap.page_size_min;
const posix = std.posix;
const windows = std.os.windows;
const Oom = std.mem.Allocator.Error;
