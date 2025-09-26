/// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#rights
pub const Rights = packed struct(u64) {
    /// The right to invoke `fd_datasync`.
    ///
    /// If `path_open` is set, includes the right to invoke `path_open` with `fdflags::dsync`.
    fd_datasync: bool = false,
    /// The right to invoke `fd_read` and `sock_recv`.
    ///
    /// If `rights::fd_seek` is set, includes the right to invoke `fd_pread`.
    fd_read: bool = false,
    /// The right to invoke `fd_seek`. This flag implies `rights::fd_tell`.
    fd_seek: bool = false,
    /// The right to invoke `fd_fdstat_set_flags`.
    fd_fdstat_set_flags: bool = false,
    /// The right to invoke `fd_sync`.
    ///
    /// If `path_open` is set, includes the right to invoke
    /// `path_open` with `fdflags::rsync` and `fdflags::dsync`.
    fd_sync: bool = false,
    /// The right to invoke `fd_seek` in such a way that the file offset
    /// remains unaltered (i.e., `whence::cur` with offset zero), or to
    /// invoke `fd_tell`.
    fd_tell: bool = false,
    /// The right to invoke `fd_write` and `sock_send`.
    /// If `rights::fd_seek` is set, includes the right to invoke `fd_pwrite`.
    fd_write: bool = false,
    /// The right to invoke `fd_advise`.
    fd_advise: bool = false,
    /// The right to invoke `fd_allocate`.
    fd_allocate: bool = false,
    /// The right to invoke `path_create_directory`.
    path_create_directory: bool = false,
    /// If `path_open` is set, the right to invoke `path_open` with `oflags::creat`.
    path_create_file: bool = false,
    /// The right to invoke `path_link` with the file descriptor as the
    /// source directory.
    path_link_source: bool = false,
    /// The right to invoke `path_link` with the file descriptor as the
    /// target directory.
    path_link_target: bool = false,
    /// The right to invoke `path_open`.
    path_open: bool = false,
    /// The right to invoke `fd_readdir`.
    fd_readdir: bool = false,
    /// The right to invoke `path_readlink`.
    path_readlink: bool = false,
    /// The right to invoke `path_rename` with the file descriptor as the source directory.
    path_rename_source: bool = false,
    /// The right to invoke `path_rename` with the file descriptor as the target directory.
    path_rename_target: bool = false,
    /// The right to invoke `path_filestat_get`.
    path_filestat_get: bool = false,
    /// The right to change a file's size.
    ///
    /// If `path_open` is set, includes the right to invoke `path_open` with `oflags::trunc`.
    ///
    /// Note: there is no function named `path_filestat_set_size`. This follows POSIX design,
    /// which only has `ftruncate` and does not provide `ftruncateat`.
    /// While such function would be desirable from the API design perspective, there are virtually
    /// no use cases for it since no code written for POSIX systems would use it.
    /// Moreover, implementing it would require multiple syscalls, leading to inferior performance.
    path_filestat_set_size: bool = false,
    /// The right to invoke `path_filestat_set_times`.
    path_filestat_set_times: bool = false,
    /// The right to invoke `fd_filestat_get`.
    fd_filestat_get: bool = false,
    /// The right to invoke `fd_filestat_set_size`.
    fd_filestat_set_size: bool = false,
    /// The right to invoke `fd_filestat_set_times`.
    fd_filestat_set_times: bool = false,
    /// The right to invoke `path_symlink`.
    path_symlink: bool = false,
    /// The right to invoke `path_remove_directory`.
    path_remove_directory: bool = false,
    /// The right to invoke `path_unlink_file`.
    path_unlink_file: bool = false,
    /// If `rights::fd_read` is set, includes the right to invoke `poll_oneoff` to subscribe to
    /// `eventtype::fd_read`.
    ///
    /// If `rights::fd_write` is set, includes the right to invoke `poll_oneoff` to subscribe to
    /// `eventtype::fd_write`.
    poll_fd_readwrite: bool = false,
    /// The right to invoke `sock_shutdown`.
    sock_shutdown: bool = false,
    /// The right to invoke `sock_accept`.
    sock_accept: bool = false,
    padding: u34 = 0,
};

impl: Impl,
rights: Rights,

const File = @This();

const Impl = struct {
    ctx: Ctx,
    vtable: *const VTable,
};

pub const Ctx = union {
    ptr: *anyopaque,
    /// Unbuffered access to an OS file descriptor.
    real: std.fs.File,
};

pub const StandardStreams = struct {
    stdin: File,
    stdout: File,
    stderr: File,
};

pub const os = @import("File/os.zig");

pub const VTable = struct {
    const Api = struct {
        // fd_write: *const fn(ctx: Ctx, ),
    };

    api: Api,
    deinit: *const fn (ctx: Ctx, allocator: Allocator) void,

    // Ensure that rights checks get compiled down to an array access + bitwise AND, for fun
    comptime {
        for (@typeInfo(Api).@"struct".fields) |f| {
            const fn_offset = @offsetOf(VTable, @tagName(f)) / @sizeOf(*const fn () void);
            std.debug.assert(fn_offset == @bitOffsetOf(Rights, @tagName(f)));
        }
    }
};

pub fn deinit(file: *File, allocator: Allocator) void {
    file.impl.vtable.deinit(file.impl.ctx, allocator);
    file.* = undefined;
}

const std = @import("std");
const Allocator = std.mem.Allocator;
