//! Implementation of a WASI file descriptor and its operations.

pub const Rights = packed struct(u60) {
    base: types.Rights.Valid,
    /// Applies to `File` descriptors that inherit from this one.
    inheriting: types.Rights.Valid,

    pub fn init(base: types.Rights.Valid) Rights {
        return .{ .base = base, .inheriting = base };
    }
};

impl: Impl,
rights: Rights,

const File = @This();

pub const Impl = struct {
    ctx: Ctx,
    vtable: *const VTable,
};

pub const Ctx = struct {
    const ctx_size = 16;

    bytes: [ctx_size]u8 align(ctx_size),

    fn checkSize(comptime T: type) void {
        if (@sizeOf(T) > ctx_size) {
            @compileError(@typeName(T) ++ " is too big");
        }
    }

    pub fn init(context: anytype) Ctx {
        const T = @TypeOf(context);
        comptime {
            checkSize(T);
        }

        var ctx = Ctx{ .bytes = undefined };
        @as(*align(ctx_size) T, @ptrCast(&ctx.bytes)).* = context;
        return ctx;
    }

    pub fn get(ctx: Ctx, comptime T: type) T {
        comptime {
            checkSize(T);
        }

        return @as(*align(ctx_size) const T, @ptrCast(&ctx.bytes)).*;
    }
};

pub const StandardStreams = struct {
    stdin: File,
    stdout: File,
    stderr: File,
};

pub const host_file = @import("File/host_file.zig");
pub const host_dir = @import("File/host_dir.zig");

/// A region of memory for scatter/gather **writes**.
///
/// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#ciovec
pub const Ciovec = extern struct {
    inner: std.posix.iovec_const,

    pub fn init(b: []const u8) Ciovec {
        return .{
            .inner = .{ .base = b.ptr, .len = b.len },
        };
    }

    pub fn bytes(ciov: Ciovec) []const u8 {
        return ciov.inner.base[0..ciov.inner.len];
    }

    pub fn castSlice(ciovecs: []const Ciovec) []const std.posix.iovec_const {
        const casted: []const std.posix.iovec_const = @ptrCast(ciovecs);
        std.debug.assert(casted.len == ciovecs.len);
        return casted;
    }
};

/// A region of memory for scatter/gather **reads**.
///
/// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#iovec
pub const Iovec = extern struct {
    inner: std.posix.iovec,

    pub fn init(b: []u8) Iovec {
        return .{
            .inner = .{ .base = b.ptr, .len = b.len },
        };
    }

    pub fn bytes(iov: Iovec) []u8 {
        return iov.inner.base[0..iov.inner.len];
    }

    pub fn castSlice(iovecs: []const Iovec) []const std.posix.iovec {
        const casted: []const std.posix.iovec = @ptrCast(iovecs);
        std.debug.assert(casted.len == iovecs.len);
        return casted;
    }
};

pub const Error = @import("errno.zig").Error;

/// Called when an Zig `std` OS abstract returns an unexpected error.
pub fn unexpectedError(err: anyerror) std.posix.UnexpectedError {
    if (std.posix.unexpected_error_tracing) {
        std.log.err("unexpected error: {t}", .{err});
        if (@errorReturnTrace()) |trace| {
            std.debug.dumpStackTrace(trace.*);
        }
    }

    return error.Unexpected;
}

pub const not_dir = struct {
    pub fn fd_prestat_get(_: Ctx) Error!types.PreStat {
        return Error.NotDir;
    }

    pub fn fd_prestat_dir_name(_: Ctx, _: []u8) Error!void {
        return Error.NotDir;
    }

    pub fn fd_readdir(
        _: Ctx,
        _: types.INode.HashSeed,
        _: []u8,
        _: types.DirCookie,
    ) Error!types.Size {
        return Error.NotDir;
    }
};

pub const unimplemented = struct {
    pub fn fd_advise(_: Ctx, _: types.FileSize, _: types.FileSize, _: types.Advice) Error!void {
        return Error.Unimplemented;
    }

    pub fn fd_allocate(_: Ctx, _: types.FileSize, _: types.FileSize) Error!void {
        return Error.Unimplemented;
    }

    pub fn fd_datasync(_: Ctx) Error!void {
        return Error.Unimplemented;
    }

    pub fn fd_fdstat_set_flags(_: Ctx, _: types.FdFlags.Valid) Error!void {
        return Error.Unimplemented;
    }

    pub fn fd_filestat_get(
        _: Ctx,
        _: types.Device.HashSeed,
        _: types.INode.HashSeed,
    ) Error!types.FileStat {
        return Error.Unimplemented;
    }

    pub fn fd_filestat_set_size(_: Ctx, _: types.FileSize) Error!void {
        return Error.Unimplemented;
    }

    pub fn fd_filestat_set_times(
        _: Ctx,
        _: types.Timestamp,
        _: types.Timestamp,
        _: types.FstFlags.Valid,
    ) Error!void {
        return Error.Unimplemented;
    }

    pub fn fd_pread(_: Ctx, _: []const Iovec, _: types.FileSize, _: u32) Error!u32 {
        return Error.Unimplemented;
    }

    pub fn fd_read(_: Ctx, _: []const Iovec, _: u32) Error!u32 {
        return Error.Unimplemented;
    }

    pub fn fd_seek(_: Ctx, _: types.FileDelta, _: types.Whence) Error!types.FileSize {
        return Error.Unimplemented;
    }

    pub fn fd_sync(_: Ctx) Error!void {
        return Error.Unimplemented;
    }

    pub fn fd_tell(_: Ctx) Error!types.FileSize {
        return Error.Unimplemented;
    }

    pub fn path_readlink(_: Ctx, _: []const u8, _: []u8) Error!types.Size {
        return Error.Unimplemented;
    }
};

pub const OpenedPath = struct {
    file: File.Impl,
    /// Allows restricting the rights on the file when certain operations are not supported.
    rights: types.Rights.Valid,
};

pub const SockRecvResult = struct {
    len: types.Size,
    flags: types.RoFlags,
};

/// Do not call function pointers without checking the corresponding `File`'s `rights`.
pub const VTable = struct {
    fd_advise: *const fn (
        ctx: Ctx,
        offset: types.FileSize,
        len: types.FileSize,
        advice: types.Advice,
    ) Error!void,

    fd_allocate: *const fn (ctx: Ctx, offset: types.FileSize, len: types.FileSize) Error!void,

    fd_close: *const fn (ctx: Ctx, allocator: Allocator) Error!void,

    fd_datasync: *const fn (ctx: Ctx) Error!void,

    fd_fdstat_get: *const fn (ctx: Ctx) Error!types.FdStat.File,

    fd_fdstat_set_flags: *const fn (ctx: Ctx, flags: types.FdFlags.Valid) Error!void,

    // fd_fdstat_set_rights is managed by `File`, not by individual implementations.

    fd_filestat_get: *const fn (
        ctx: Ctx,
        device_hash_seed: types.Device.HashSeed,
        inode_hash_seed: types.INode.HashSeed,
    ) Error!types.FileStat,

    fd_filestat_set_size: *const fn (ctx: Ctx, size: types.FileSize) Error!void,

    fd_filestat_set_times: *const fn (
        ctx: Ctx,
        atim: types.Timestamp,
        mtim: types.Timestamp,
        fst_flags: types.FstFlags.Valid,
    ) Error!void,

    fd_prestat_get: *const fn (ctx: Ctx) Error!types.PreStat,

    fd_prestat_dir_name: *const fn (ctx: Ctx, path: []u8) Error!void,

    fd_pread: *const fn (
        ctx: Ctx,
        iovs: []const Iovec,
        offset: types.FileSize,
        total_len: u32,
    ) Error!u32,

    fd_pwrite: *const fn (
        ctx: Ctx,
        iovs: []const Ciovec,
        offset: types.FileSize,
        total_len: u32,
    ) Error!u32,

    fd_read: *const fn (ctx: Ctx, iovs: []const Iovec, total_len: u32) Error!u32,

    fd_readdir: *const fn (
        ctx: Ctx,
        inode_hash_seed: types.INode.HashSeed,
        // allocator: Allocator,
        buf: []u8,
        cookie: types.DirCookie,
    ) Error!types.Size,

    // fd_renumber

    fd_seek: *const fn (
        ctx: Ctx,
        delta: types.FileDelta,
        whence: types.Whence,
    ) Error!types.FileSize,

    fd_sync: *const fn (ctx: Ctx) Error!void,

    fd_tell: *const fn (ctx: Ctx) Error!types.FileSize,

    fd_write: *const fn (ctx: Ctx, iovs: []const Ciovec, total_len: u32) Error!u32,

    path_create_directory: *const fn (ctx: Ctx, path: []const u8) Error!void,

    path_filestat_get: *const fn (
        ctx: Ctx,
        scratch: *ArenaAllocator,
        device_hash_seed: types.Device.HashSeed,
        inode_hash_seed: types.INode.HashSeed,
        flags: types.LookupFlags.Valid,
        path: Path,
    ) Error!types.FileStat,

    path_filestat_set_times: *const fn (
        ctx: Ctx,
        lookup_flags: types.LookupFlags.Valid,
        path: []const u8,
        atim: types.Timestamp,
        mtim: types.Timestamp,
        fst_flags: types.FstFlags.Valid,
    ) Error!void,

    path_open: *const fn (
        ctx: Ctx,
        allocator: Allocator,
        scratch: *ArenaAllocator,
        dir_flags: types.LookupFlags.Valid,
        path: Path,
        open_flags: types.OpenFlags.Valid,
        rights: types.Rights.Valid,
        fd_flags: types.FdFlags.Valid,
    ) Error!OpenedPath,

    path_readlink: *const fn (ctx: Ctx, path: []const u8, buf: []u8) Error!types.Size,

    path_remove_directory: *const fn (ctx: Ctx, path: []const u8) Error!void,

    path_symlink: *const fn (ctx: Ctx, old_path: []const u8, new_path: []const u8) Error!void,

    path_unlink_file: *const fn (ctx: Ctx, path: []const u8) Error!void,

    sock_accept: *const fn (ctx: Ctx, flags: types.FdFlags.Valid) Error!File.Impl,

    sock_recv: *const fn (
        ctx: Ctx,
        iovs: []const Iovec,
        total_len: u32,
        flags: types.RiFlags.Valid,
    ) Error!SockRecvResult,

    sock_send: *const fn (ctx: Ctx, iovs: []const Ciovec, total_len: u32) Error!types.Size,

    sock_shutdown: *const fn (ctx: Ctx, how: types.SdFlags.Valid) Error!void,
};

fn hasVTable(file: *const File, vtable: *const VTable) bool {
    return @intFromPtr(file.impl.vtable) == @intFromPtr(vtable);
}

fn api(
    file: *const File,
    comptime right: Api,
    comptime func: std.meta.FieldEnum(VTable),
) error{AccessDenied}!@FieldType(VTable, @tagName(func)) {
    if (@field(file.rights.base, @tagName(right))) {
        return @field(file.impl.vtable, @tagName(func));
    } else {
        std.log.err("{t} requires right {t} to be called", .{ func, right });
        return error.AccessDenied;
    }
}

/// Provide file advisory information on a file descriptor.
///
/// This is similar to `posix_fadvise` in POSIX.
///
/// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#fd_advise
pub fn fd_advise(
    file: *File,
    offset: types.FileSize,
    len: types.FileSize,
    advice: types.Advice,
) Error!void {
    return (try file.api(.fd_advise, .fd_advise))(file.impl.ctx, offset, len, advice);
}

/// Force the allocation of space in a file.
///
/// This is similar to `posix_fallocate` in POSIX.
///
/// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#fd_allocate
pub fn fd_allocate(
    file: *File,
    /// A `types.FileSize` indicating the offset at which to start the allocation.
    offset: types.FileSize,
    /// A `types.FileSize` indicating the length of the area that is allocated.
    len: types.FileSize,
) Error!void {
    return (try file.api(.fd_allocate, .fd_allocate))(file.impl.ctx, offset, len);
}

/// Closes the file descriptor and deinitializes any other state, after which it is illegal
/// behavior to use `file`.
///
/// This is similar to `close` in POSIX.
///
/// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#fd_close
pub fn fd_close(file: *File, allocator: Allocator) Error!void {
    try file.impl.vtable.fd_close(file.impl.ctx, allocator);
    file.* = undefined;
}

/// Synchronize the data of a file to disk.
///
/// This is similar to `fdatasync` in POSIX.
///
/// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#fd_datasync
pub fn fd_datasync(file: *File) Error!void {
    return (try file.api(.fd_datasync, .fd_datasync))(file.impl.ctx);
}

/// Get the attributes of a file descriptor.
///
/// This returns similar flags to `fcntl(fd, F_GETFL)` in POSIX, as well as additional fields.
///
/// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#fd_fdstat_get
pub fn fd_fdstat_get(file: *File) Error!types.FdStat {
    // No corresponding rights flag for this function.
    return .{
        .file = try file.impl.vtable.fd_fdstat_get(file.impl.ctx),
        .rights_base = types.Rights{ .valid = file.rights.base },
        .rights_inheriting = types.Rights{ .valid = file.rights.inheriting },
    };
}

/// Adjust the flags associated with a file descriptor.
///
/// This is similar to `fcntl(fd, F_SETFL, flags)` in POSIX.
///
/// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#fd_fdstat_set_flags
pub fn fd_fdstat_set_flags(
    file: *File,
    /// The desired values of the file descriptor flags.
    flags: types.FdFlags.Valid,
) Error!void {
    return (try file.api(.fd_fdstat_set_flags, .fd_fdstat_set_flags))(file.impl.ctx, flags);
}

/// Adjust the rights associated with a file descriptor.
///
/// This can only be used to remove rights, and returns `Error.NotCapable` if called in a way that
/// would attempt to add rights.
///
/// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#fd_fdstat_set_rights
pub fn fd_fdstat_set_rights(
    file: *File,
    /// The desired rights of the file descriptor.
    rights_base: types.Rights.Valid,
    rights_inheriting: types.Rights.Valid,
) Error!void {
    // No corresponding rights flag for this function.
    if (!file.rights.base.contains(rights_base) or
        !file.rights.inheriting.contains(rights_inheriting))
    {
        return Error.NotCapable;
    }

    file.rights.base = rights_base;
    file.rights.inheriting = rights_inheriting;
}

/// Returns the attributes of an open file.
///
/// This is similar to `fstat` in POSIX.
///
/// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#fd_filestat_get
pub fn fd_filestat_get(
    file: *File,
    device_hash_seed: types.Device.HashSeed,
    inode_hash_seed: types.INode.HashSeed,
) Error!types.FileStat {
    const get = try file.api(.fd_filestat_get, .fd_filestat_get);
    return get(file.impl.ctx, device_hash_seed, inode_hash_seed);
}

/// Adjust the size of an open file.
///
/// If this increases the file's size, the extra bytes are filled with zeros.
///
/// This is similar to `ftruncate` in POSIX.
///
/// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#fd_filestat_set_size
pub fn fd_filestat_set_size(file: *File, size: types.FileSize) Error!void {
    return (try file.api(.fd_filestat_set_size, .fd_filestat_set_size))(file.impl.ctx, size);
}

/// Adjust the timestamps of an open file or directory.
///
/// This is similar to futimens in POSIX.
///
/// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#fd_filestat_set_times
pub fn fd_filestat_set_times(
    file: *File,
    ///  The desired values of the data access timestamp.
    atim: types.Timestamp,
    /// The desired values of the data modification timestamp.
    mtim: types.Timestamp,
    /// A bitmask indicating which timestamps to adjust.
    fst_flags: types.FstFlags.Valid,
) Error!void {
    const setTimes = try file.api(.fd_filestat_set_times, .fd_filestat_set_times);
    return setTimes(file.impl.ctx, atim, mtim, fst_flags);
}

/// Read from a file descriptor, without using and updating the file descriptor's offset.
///
/// This is similar to `preadv` in Linux (and other Unix-es).
///
/// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#fd_pread
pub fn fd_pread(
    file: *File,
    /// List of scatter/gather vectors from which to store data.
    iovs: []const Iovec,
    /// The offset within the file at which to read.
    offset: types.FileSize,
    total_len: u32,
) Error!u32 {
    return (try file.api(.fd_read, .fd_pread))(file.impl.ctx, iovs, offset, total_len);
}

// Is this what it's called?
const manual_function_devirtualization = switch (builtin.mode) {
    .ReleaseSafe, .ReleaseFast => true,
    .Debug, .ReleaseSmall => false,
};

/// Return a description of the given preopened file descriptor.
///
/// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#fd_prestat_get
pub fn fd_prestat_get(file: *File) Error!types.PreStat {
    if (manual_function_devirtualization and file.hasVTable(&host_dir.vtable)) {
        @branchHint(.likely);
        return host_dir.fd_prestat_get(file.impl.ctx);
    } else {
        return file.impl.vtable.fd_prestat_get(file.impl.ctx);
    }
}

pub fn fd_prestat_dir_name(
    file: *File,
    /// Buffer to guest memory where the name is written.
    path: []u8,
) Error!void {
    if (manual_function_devirtualization and file.hasVTable(&host_dir.vtable)) {
        @branchHint(.likely);
        return host_dir.fd_prestat_dir_name(file.impl.ctx, path);
    } else {
        return file.impl.vtable.fd_prestat_dir_name(file.impl.ctx, path);
    }
}

/// Write to a file descriptor, without using and updating the file descriptor's offset.
///
/// This is similar to `pwritev` in Linux (and other Unix-es).
///
/// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#fd_pwrite
pub fn fd_pwrite(
    file: *File,
    /// List of scatter/gather vectors from which to retrieve data.
    iovs: []const Ciovec,
    /// The offset within the file at which to write.
    offset: types.FileSize,
    total_len: u32,
) Error!u32 {
    return (try file.api(.fd_write, .fd_pwrite))(file.impl.ctx, iovs, offset, total_len);
}

/// Read from a file descriptor.
///
/// This is similar to `readv` in POSIX.
///
/// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#fd_read
pub fn fd_read(
    file: *File,
    /// List of scatter/gather vectors to which to store data.
    iovs: []const Iovec,
    /// Total length of all buffers in `iovs`.
    total_len: u32,
) Error!u32 {
    return (try file.api(.fd_read, .fd_read))(file.impl.ctx, iovs, total_len);
}

/// Read directory entries from a directory.
///
/// This is similar to `getdents` in POSIX.
///
/// When successful, the contents of the output buffer consist of a sequence of directory entries.
/// Each directory entry consists of a `types.DirEnt` object, followed by `types.DirEnt.namlen`
/// bytes holding the name of the directory entry.
///
/// This function fills the output buffer as much as possible, potentially truncating the last
/// directory entry. This allows the caller to grow its read buffer size in case it's too small to
/// fit a single large directory entry, or skip the oversized directory entry.
///
/// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#fd_readdir
pub fn fd_readdir(
    file: *File,
    /// Allows hiding implementation details from the WASM guest by hashing `inode`s with the given
    /// seed.
    inode_hash_seed: types.INode.HashSeed,
    // allocator: Allocator,
    /// Buffer to guest memory.
    buf: []u8,
    cookie: types.DirCookie,
) Error!types.Size {
    if (!file.rights.base.fd_readdir) {
        return error.AccessDenied;
    }

    const args = .{ file.impl.ctx, inode_hash_seed, buf, cookie };
    if (manual_function_devirtualization and file.hasVTable(&host_dir.vtable)) {
        @branchHint(.likely);
        return @call(.auto, host_dir.fd_readdir, args);
    } else {
        return @call(.auto, file.impl.vtable.fd_readdir, args);
    }
}

// fd_renumber is managed by FD table

/// Move the offset of a file descriptor.
///
/// This is similar to `lseek` in POSIX.
///
/// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#fd_seek
pub fn fd_seek(file: *File, delta: types.FileDelta, whence: types.Whence) Error!types.FileSize {
    return (try file.api(.fd_seek, .fd_seek))(file.impl.ctx, delta, whence);
}

/// Synchronize the data and metadata of a file to disk.
///
/// This is similar to `fsync` in POSIX.
///
/// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#fd_sync
pub fn fd_sync(file: *File) Error!void {
    try (try file.api(.fd_sync, .fd_sync))(file.impl.ctx);
}

/// Return the current offset of a file descriptor.
///
/// This is similar to `lseek(fd, 0, SEEK_CUR)` in POSIX.
///
/// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#fd_tell
pub fn fd_tell(file: *File) Error!types.FileSize {
    return (try file.api(.fd_tell, .fd_tell))(file.impl.ctx);
}

/// Write to a file descriptor.
///
/// This is similar to `writev` in POSIX.
///
/// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#fd_write
pub fn fd_write(
    file: *File,
    /// List of scatter/gather vectors from which to retrieve data.
    iovs: []const Ciovec,
    /// Total length of all data in `iovs`, in bytes.
    total_len: u32,
) Error!u32 {
    return (try file.api(.fd_write, .fd_write))(file.impl.ctx, iovs, total_len);
}

/// Create a directory.
///
/// This is similar to `mkdirat` in POSIX.
///
/// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#path_create_directory
pub fn path_create_directory(file: *File, path: []const u8) Error!void {
    try (try file.api(.path_create_directory, .path_create_directory))(file.impl.ctx, path);
}

/// Return the attributes of a file or directory.
///
/// This is similar to `stat` in POSIX.
///
/// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#path_filestat_get
pub fn path_filestat_get(
    file: *File,
    scratch: *ArenaAllocator,
    device_hash_seed: types.Device.HashSeed,
    inode_hash_seed: types.INode.HashSeed,
    /// Flags determining the method of how the path is resolved.
    flags: types.LookupFlags.Valid,
    /// The path of the file or directory to inspect.
    path: Path,
) Error!types.FileStat {
    const get = try file.api(.path_filestat_get, .path_filestat_get);
    return get(file.impl.ctx, scratch, device_hash_seed, inode_hash_seed, flags, path);
}

/// Adjust the timestamps of a file or directory.
///
/// This is similar to `utimensat` in POSIX.
///
/// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#path_filestat_set_times
pub fn path_filestat_set_times(
    file: *File,
    /// Flags determining the method of how the path is resolved.
    lookup_flags: types.LookupFlags.Valid,
    path: []const u8,
    /// The desired values of the data access timestamp.
    atim: types.Timestamp,
    /// The desired values of the data modification timestamp.
    mtim: types.Timestamp,
    /// A bitmask indicating which timestamps to adjust.
    fst_flags: types.FstFlags.Valid,
) Error!void {
    const set_times = try file.api(.path_filestat_set_times, .path_filestat_set_times);
    return set_times(file.impl.ctx, lookup_flags, path, atim, mtim, fst_flags);
}

// pub fn path_link

/// Open a file or directory.
///
/// This is similar to `openat` in POSIX.
///
/// The returned file descriptor is not guaranteed to be the lowest-numbered file descriptor not
/// currently open; it is randomized to prevent applications from depending on making assumptions
/// about indexes, since this is error-prone in multi-threaded contexts. The returned file
/// descriptor is guaranteed to be less than `std.math.maxInt(i32) + 1`.
///
/// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#path_open
pub fn path_open(
    dir: *File,
    allocator: Allocator,
    scratch: *ArenaAllocator,
    dir_flags: types.LookupFlags.Valid,
    path: Path,
    open_flags: types.OpenFlags.Valid,
    /// The initial rights of the newly created file descriptor.
    ///
    /// The implementation is allowed to return a file descriptor with fewer rights than specified,
    /// if and only if those rights do not apply to the type of file being opened.
    ///
    /// The base rights are rights that will apply to operations using the file descriptor itself,
    /// while the inheriting rights are rights that apply to file descriptors derived from it.
    rights_base: types.Rights.Valid,
    rights_inheriting: types.Rights.Valid,
    fd_flags: types.FdFlags.Valid,
) Error!File {
    const derived_rights = dir.rights.inheriting;
    if (!derived_rights.contains(rights_base) or
        !derived_rights.contains(rights_inheriting))
    {
        return Error.NotCapable;
    }

    const pathOpen = try dir.api(.path_open, .path_open);
    const opened: OpenedPath = try pathOpen(
        dir.impl.ctx,
        allocator,
        scratch,
        dir_flags,
        path,
        open_flags,
        rights_base,
        fd_flags,
    );

    std.debug.assert(derived_rights.contains(opened.rights));

    std.log.debug(
        "opened {f} with base rights {f} restricted to {f} inherited {f}",
        .{ path, rights_base, opened.rights, derived_rights },
    );

    return File{
        .impl = opened.file,
        .rights = Rights{
            .base = rights_base.intersection(opened.rights).intersection(derived_rights),
            .inheriting = rights_inheriting,
        },
    };
}

/// Read the contents of a symbolic link.
///
/// Returns the number of bytes placed in the buffer.
///
/// This is similar to readlinkat in POSIX.
///
/// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#path_readlink
pub fn path_readlink(
    file: *File,
    path: []const u8,
    /// Buffer in guest memory to which to write the contents of the symbolic link.
    buf: []u8,
) Error!types.Size {
    const readLink = try file.api(.path_readlink, .path_readlink);
    return readLink(file.impl.ctx, path, buf);
}

/// Remove a directory.
///
/// Returns `Error.DirNotEmpty` if the directory is not empty.
///
/// This is similar to `unlinkat(fd, path, AT_REMOVEDIR)` in POSIX.
///
/// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#path_remove_directory
pub fn path_remove_directory(
    file: *File,
    /// The path to a directory to remove.
    path: []const u8,
) Error!void {
    const removeDirectory = try file.api(.path_remove_directory, .path_remove_directory);
    try removeDirectory(file.impl.ctx, path);
}

/// Create a symbolic link.
///
/// This is similar to `symlinkat` in POSIX.
///
/// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#path_symlink
pub fn path_symlink(
    file: *File,
    /// The contents of the symbolic link.
    old_path: []const u8,
    /// The destination path at which to create the symbolic link.
    new_path: []const u8,
) Error!void {
    try (try file.api(.path_symlink, .path_symlink))(file.impl.ctx, old_path, new_path);
}

/// Unlink a file. Returns `Error.IsDir` if the path refers to a directory.
///
/// This is similar to `unlinkat(fd, path, 0)` in POSIX.
///
/// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#path_unlink_file
pub fn path_unlink_file(
    file: *File,
    /// The path to a file to unlink.
    path: []const u8,
) Error!void {
    try (try file.api(.path_unlink_file, .path_unlink_file))(file.impl.ctx, path);
}

/// Accept a new incoming connection.
///
/// This is similar to `accept` in POSIX.
///
/// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#sock_accept
pub fn sock_accept(
    socket: *File,
    /// The desired values of the file descriptor flags.
    flags: types.FdFlags.Valid,
) Error!File {
    const sock = try (try socket.api(.sock_accept, .sock_accept))(socket.impl.ctx, flags);
    _ = sock;
    @panic("TODO: Apply rights to `sock`");
}

/// Receive a message from a socket.
///
/// This is similar to `recv` in POSIX, though it also supports reading the data into multiple
/// buffers in the manner of `readv`.
///
/// Returns the number of bytes stored in `iovs` and message flags.
///
/// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#sock_recv
pub fn sock_recv(
    socket: *File,
    /// List of scatter/gather vectors to which to store data.
    iovs: []const Iovec,
    /// Total length of all buffers in `iovs`.
    total_len: u32,
    /// Message flags.
    flags: types.RiFlags.Valid,
) Error!SockRecvResult {
    return (try socket.api(.fd_read, .sock_recv))(socket.impl.ctx, iovs, total_len, flags);
}

/// Send a message on a socket.
///
/// Returns the number of bytes transmitted.
///
/// This is similar to `send` in POSIX, though it also supports writing the data from multiple
/// buffers in the manner of `writev`.
///
/// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#sock_send
pub fn sock_send(
    socket: *File,
    /// List of scatter/gather vectors to which to retrieve data
    iovs: []const Ciovec,
    /// Total length, in bytes, of all of the data to send.
    total_len: u32,
    // flags: types.SiFlags.Valid, // No flags are defined
) Error!types.Size {
    return (try socket.api(.fd_write, .sock_send))(socket.impl.ctx, iovs, total_len);
}

pub fn sock_shutdown(
    socket: *File,
    /// Which channels on the socket to shut down.
    how: types.SdFlags.Valid,
) Error!void {
    try (try socket.api(.sock_shutdown, .sock_shutdown))(socket.impl.ctx, how);
}

const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const ArenaAllocator = std.heap.ArenaAllocator;
const Api = @import("api.zig").Api;
const types = @import("types.zig");
const Path = @import("Path.zig");
