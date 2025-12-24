//! Cross-platform reading of file contents into memory buffers.

pub const FileContent = if (builtin.os.tag == .windows)
    WindowsMappedView
else if (virtual_memory.mman.has_mmap_anonymous)
    VirtualMemory
else
    Allocated;

pub const BytePath = if (builtin.os.tag == .windows or !virtual_memory.mman.has_mmap_anonymous)
    []const u8
else
    [:0]const u8;

/// Reads the contents of a file into an allocated buffer, using the best platform-specific API
/// where possible.
///
/// Don't forget to call `deinit()`!.
pub fn readFilePortable(
    io: Io,
    dir: Io.Dir,
    sub_path: BytePath,
    /// - On Windows, this is used to allocate a temporary buffer containing a `WTF-16` version of
    /// `sub_path`.
    /// - On Unix-like platforms, this is *ignored*.
    /// - On platforms without `mmap` and `MAP_ANONYMOUS` (such as WebAssembly) this is used to
    /// allocate a buffer to store the file's contents.
    allocator: Allocator,
) !FileContent {
    if (builtin.os.tag == .windows) {
        const sub_path_wide = std.unicode.wtf8ToWtf16LeAllocZ(
            allocator,
            sub_path,
        ) catch |e| return switch (e) {
            error.OutOfMemory => |oom| oom,
            error.InvalidWtf8 => error.BadPathName,
        };
        defer allocator.free(sub_path_wide);

        var allocated_name = std.mem.zeroes(std.os.windows.UNICODE_STRING);
        const nt_path = if (try sys.windows.relativeDosPathToNt(
            dir.handle,
            sub_path_wide,
            &allocated_name,
        )) |relative|
            relative
        else
            allocated_name.Buffer.?[0..@divExact(allocated_name.Length, 2)];

        defer std.os.windows.ntdll.RtlFreeUnicodeString(&allocated_name);

        return mapFileWindows(io, dir, nt_path);
    } else if (virtual_memory.mman.has_mmap_anonymous) {
        return readFile(io, dir, sub_path);
    } else {
        return readFileAlloc(io, dir, sub_path, allocator);
    }
}

pub const ReadFileError = Oom || Io.File.OpenError || Io.File.Reader.Error || Io.File.StatError;

pub const VirtualMemory = struct {
    allocation: []align(page_size_min) const u8,

    const AllocationSizes = struct {
        unused: []align(page_size_min) u8,
        used: []align(page_size_min) u8,
    };

    fn calculateAllocationSizes(
        page_size: usize,
        allocated: []align(page_size_min) u8,
        actual_size: usize,
    ) AllocationSizes {
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

    pub fn contents(file: VirtualMemory) []const u8 {
        return file.allocation;
    }

    pub fn deinit(file: *VirtualMemory) void {
        defer file.* = undefined;
        if (file.allocation.len == 0) {
            return;
        }

        const page_size = std.heap.pageSize();
        std.debug.assert(@intFromPtr(file.allocation.ptr) % page_size == 0);
        const pages_len = std.mem.alignForward(usize, file.allocation.len, page_size);
        const pages: []align(page_size_min) u8 = @constCast(file.allocation.ptr[0..pages_len]);

        if (builtin.os.tag == .windows) {
            var region_size: windows.SIZE_T = pages.len;
            virtual_memory.nt.free(pages.ptr, &region_size, .RELEASE) catch unreachable;
        } else {
            virtual_memory.mman.unmap(pages) catch unreachable;
        }
    }
};

fn openFileAt(io: Io, dir: Io.Dir, sub_path: BytePath) Io.File.OpenError!Io.File {
    const open_options = Io.File.OpenFlags{ .mode = .read_only };
    // return switch (BytePath) {
    //     [:0]const u8 => try dir.openFileZ(sub_path, open_options),
    //     []const u8 => try dir.openFile(sub_path, open_options),
    //     else => comptime unreachable,
    // };
    return dir.openFile(io, sub_path, open_options);
}

/// Reads the contents of a file into a read-only (`PROT_READ`) virtual memory allocation created
/// with `mmap()` and `MAP_ANONYMOUS`.
///
/// On Windows, this instead calls `VirtualAlloc()` with `PAGE_READONLY`. To create a file mapping
/// instead, call `mapFileWindows`.
pub fn readFile(io: Io, dir: Io.Dir, sub_path: BytePath) ReadFileError!VirtualMemory {
    const file = try openFileAt(io, dir, sub_path);
    defer file.close(io);

    const page_size = std.heap.pageSize();
    const indicated_size = (try file.stat(io)).size;

    if (indicated_size == 0) {
        return VirtualMemory{ .allocation = &.{} };
    }

    const allocated_size = std.mem.alignBackward(
        usize,
        std.math.add(usize, indicated_size, page_size - 1) catch return Oom.OutOfMemory,
        page_size,
    );

    std.debug.assert(allocated_size >= indicated_size);
    std.debug.assert(allocated_size % page_size == 0);

    const allocated: []align(page_size_min) u8 = if (builtin.os.tag == .windows) win: {
        var region_size: windows.SIZE_T = allocated_size;
        const base = virtual_memory.nt.allocate(
            null,
            &region_size,
            .{ .COMMIT = true, .RESERVE = true },
            .READWRITE,
        ) catch |e| return switch (e) {
            error.AlreadyCommitted, error.ConflictingAddresses => error.OutOfMemory,
            else => |err| err,
        };

        break :win base[0..allocated_size];
    } else try virtual_memory.mman.map_anonymous(allocated_size, .{ .WRITE = true }, .{});

    errdefer if (builtin.os.tag == .windows) {
        var region_size: windows.SIZE_T = allocated.len;
        virtual_memory.nt.free(allocated.ptr, &region_size, .DECOMMIT) catch {};
    } else posix.munmap(allocated);

    const actual_size = read: {
        var reader = file.readerStreaming(io, allocated);
        reader.interface.fill(allocated.len) catch |e| switch (e) {
            error.EndOfStream => {},
            error.ReadFailed => return reader.err.?,
        };

        break :read reader.interface.bufferedLen();
    };
    const pages = VirtualMemory.calculateAllocationSizes(page_size, allocated, actual_size);

    if (pages.unused.len > 0) {
        if (builtin.os.tag == .windows) {
            var region_size: windows.SIZE_T = pages.unused.len;
            try virtual_memory.nt.free(pages.unused.ptr, &region_size, .DECOMMIT);
        } else {
            try virtual_memory.mman.unmap(pages.unused);
        }
    }

    if (pages.used.len > 0) {
        if (builtin.os.tag == .windows) {
            _ = virtual_memory.nt.protect(pages.used, .READONLY) catch |e| return switch (e) {
                error.ConflictingAddresses => Oom.OutOfMemory,
                else => |err| err,
            };
        } else {
            try virtual_memory.mman.protect(pages.used, .{ .READ = true });
        }
    }

    return VirtualMemory{ .allocation = pages.used[0..actual_size] };
}

pub const WindowsMappedView = struct {
    allocation: []align(page_size_min) const u8,
    mapping: windows.HANDLE,

    pub fn contents(view: WindowsMappedView) []const u8 {
        return view.allocation;
    }

    pub fn deinit(view: *WindowsMappedView) void {
        const unmap_status = windows.ntdll.NtUnmapViewOfSection(
            windows.GetCurrentProcess(),
            @ptrCast(@constCast(view.allocation.ptr)),
        );

        std.debug.assert(unmap_status == .SUCCESS);

        windows.CloseHandle(view.mapping);
        view.* = undefined;
    }
};

pub const MapFileError = Oom || windows.OpenError || Io.Cancelable || error{
    /// File was already locked
    FileLockConflict,
    FileMappingNotSupported,
};

/// Unlike the Unix-lock operating systems, Windows allows mapping files while preventing other
/// processes from modifying it.
///
/// Note that this function has not been tested on files on network drives.
///
/// To instead allocate a buffer via `VirtualAlloc()` and read the file into it, call `readFile`.
pub fn mapFileWindows(
    io: Io,
    dir: Io.Dir,
    /// WTF-16 encoded NT path to the file to open.
    sub_path_w: []const u16,
) MapFileError!WindowsMappedView {
    const file = try windows.OpenFile(
        sub_path_w,
        windows.OpenFileOptions{
            .dir = dir.handle,
            .access_mask = windows.FILE_READ_DATA | windows.SYNCHRONIZE,
            .creation = windows.FILE_OPEN,
            // Prevent other processes from modifying the file
            .share_access = windows.FILE_SHARE_READ,
        },
    );
    // Safe to close file handle after mapping is created
    defer windows.CloseHandle(file);

    if (io.cancelRequested()) {
        return error.Canceled;
    }

    // Unfortunately have to get actual size of file, since neither `NtCreateSection` nor
    // `NtMapViewOfSection` provide a way to get a size that isn't rounded to page size.
    const size = size: {
        var io_status_block: windows.IO_STATUS_BLOCK = undefined;
        var info: windows.FILE_STANDARD_INFORMATION = undefined;
        const status = sys.windows.ntQueryInformationFile(
            file,
            &io_status_block,
            .FileStandardInformation,
            &info,
        );

        switch (status) {
            .SUCCESS, .BUFFER_OVERFLOW => break :size @as(
                usize,
                @truncate(@as(u64, @bitCast(info.EndOfFile))),
            ),
            .INVALID_PARAMETER => unreachable,
            .ACCESS_DENIED => unreachable,
            else => return windows.unexpectedStatus(status),
        }
    };

    if (io.cancelRequested()) {
        return error.Canceled;
    }

    const mapping: windows.HANDLE = mapping: {
        // ntdll equivalent of `CreateFileMappingW`
        var section: windows.HANDLE = undefined;
        var maximum_size: windows.LARGE_INTEGER = @bitCast(@as(u64, size));
        const status = windows.ntdll.NtCreateSection(
            &section,
            windows.SECTION_QUERY | windows.SECTION_MAP_READ,
            null,
            &maximum_size, // `null` means no restiction
            windows.PAGE_READONLY,
            windows.SEC_COMMIT,
            file,
        );

        switch (status) {
            .SUCCESS => break :mapping section,
            .FILE_LOCK_CONFLICT => return error.FileLockConflict,
            .INVALID_FILE_FOR_SECTION => return error.FileMappingNotSupported,
            .INVALID_PAGE_PROTECTION => unreachable,
            .MAPPED_FILE_SIZE_ZERO => return WindowsMappedView{
                .allocation = &.{},
                .mapping = windows.INVALID_HANDLE_VALUE,
            },
            .SECTION_TOO_BIG => unreachable,
            .VIRUS_INFECTED, .VIRUS_DELETED => return error.AntivirusInterference,
            .INVALID_PARAMETER_6 => unreachable,
            else => return windows.unexpectedStatus(status),
        }
    };
    errdefer windows.CloseHandle(mapping);

    if (io.cancelRequested()) {
        return error.Canceled;
    }

    const win = struct {
        /// Zig got values in `windows.SECTION_INHERIT` wrong.
        pub const InheritDisposition = enum(c_int) {
            ViewShare = 1,
            ViewUnmap = 2,
            _,
        };

        /// `ntdll` equivalent of [`MapViewOfFile()`].
        ///
        /// [`MapViewOfFile()`]: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwmapviewofsection
        extern "ntdll" fn NtMapViewOfSection(
            section: windows.HANDLE,
            process: windows.HANDLE,
            // Zig wrapper got the nullability of this wrong.
            base_address: *?[*]align(page_size_min) u8,
            // Zig wrapper got type of this wrong.
            zero_bits: windows.ULONG_PTR,
            commit_size: windows.SIZE_T,
            section_offset: ?*windows.LARGE_INTEGER,
            view_size: *windows.SIZE_T,
            inherit_disposition: InheritDisposition,
            allocation_type: virtual_memory.nt.AllocationType,
            protection: virtual_memory.nt.Protection,
        ) callconv(.winapi) windows.NTSTATUS;
    };

    var base_address: ?[*]align(page_size_min) u8 = null; // Windows chooses location
    var view_size: windows.SIZE_T = 0; // map the whole section
    const map_status = win.NtMapViewOfSection(
        mapping,
        windows.GetCurrentProcess(),
        &base_address,
        0,
        0, // CommitSize should be ignored, since this is not backed by the page file.
        null,
        &view_size,
        .ViewShare,
        .{}, // COMMIT is already implied
        .READONLY,
    );

    std.debug.assert(size <= view_size);

    return switch (map_status) {
        .SUCCESS => WindowsMappedView{
            .allocation = base_address.?[0..size],
            .mapping = mapping,
        },
        .INSUFFICIENT_RESOURCES,
        .CONFLICTING_ADDRESSES,
        .PROCESS_IS_TERMINATING, // going to die anyways
        => return Oom.OutOfMemory,
        .INVALID_PAGE_PROTECTION => unreachable,
        .SECTION_PROTECTION => unreachable,
        .MAPPED_ALIGNMENT => unreachable,
        .INVALID_PARAMETER => unreachable,
        else => windows.unexpectedStatus(map_status),
    };
}

pub const Allocated = struct {
    buffer: Buffer,
    allocator: Allocator,

    const Buffer = std.ArrayListAligned(u8, .@"16");

    pub fn contents(view: Allocated) []const u8 {
        return view.buffer.items;
    }

    pub fn deinit(view: *Allocated) void {
        view.buffer.deinit(view.allocator);
        view.* = undefined;
    }
};

pub fn readFileAlloc(
    io: Io,
    dir: Io.Dir,
    sub_path: []const u8,
    allocator: Allocator,
) ReadFileError!Allocated {
    const file = try openFileAt(io, dir, sub_path);
    defer file.close();

    const indicated_size = (try file.stat()).size;
    const buf = try allocator.alignedAlloc(u8, .@"16", indicated_size);
    var reader = file.readerStreaming(io, buf);
    reader.interface.fill(indicated_size) catch |e| switch (e) {
        error.EndOfStream => {},
        error.ReadError => return reader.err.?,
    };

    return Allocated{
        .buffer = .{ .items = reader.interface.buffered(), .capacity = buf.len },
        .allocator = allocator,
    };
}

const std = @import("std");
const Io = std.Io;
const builtin = @import("builtin");
const sys = @import("sys");
const virtual_memory = @import("allocators").virtual_memory;
const posix = std.posix;
const windows = std.os.windows;
const Allocator = std.mem.Allocator;
const Oom = Allocator.Error;
const page_size_min = std.heap.page_size_min;
