/// https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#rights
pub const Rights = packed struct(u64) {
    pub const Valid = packed struct(u30) {
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
    };

    valid: Valid = .{},
    padding: u34 = 0,

    fn checkValid(rights: Rights) error{InvalidRightsFlags}!Valid {
        return if (rights.padding == 0) rights.valid else error.InvalidRightsFlags;
    }

    fn assumeValid(rights: Rights) Valid {
        return rights.checkValid() catch unreachable;
    }
};

impl: Impl,
rights: Rights.Valid,

const File = @This();

const Impl = struct {
    ctx: Ctx,
    vtable: *const VTable,
};

pub const Ctx = union {
    ptr: *anyopaque,
    /// Unbuffered access to an OS file descriptor.
    os: struct { file: std.fs.File, close: os.Close },
};

pub const StandardStreams = struct {
    stdin: File,
    stdout: File,
    stderr: File,
};

pub const os = @import("File/os.zig");
pub const preopen = @import("File/preopen.zig");

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

pub const invalid = struct {
    pub fn fd_prestat_get(_: Ctx) Error!types.Prestat {
        return Error.NotDir;
    }

    pub fn fd_prestat_dir_name(_: Ctx, _: []u8) Error!void {
        return Error.NotDir;
    }

    pub fn fd_readdir(_: Ctx, _: []u8, _: types.DirCookie) Error!types.Size {
        return Error.NotDir;
    }
};

pub const VTable = struct {
    /// Do not call function pointers without checking the `File`'s `rights`.
    const Api = struct {
        // Could add scratch: *ArenaAllocator parameter

        fd_prestat_get: *const fn (ctx: Ctx) Error!types.Prestat,
        fd_prestat_dir_name: *const fn (ctx: Ctx, path: []u8) Error!void,
        fd_pwrite: *const fn (
            ctx: Ctx,
            iovs: []const Ciovec,
            offset: types.FileSize,
            total_len: u32,
        ) Error!u32,
        // fd_read
        fd_readdir: *const fn (
            ctx: Ctx,
            // allocator: Allocator,
            buf: []u8,
            cookie: types.DirCookie,
        ) Error!types.Size,
        fd_write: *const fn (ctx: Ctx, iovs: []const Ciovec, total_len: u32) Error!u32,
    };

    api: VTable.Api,
    deinit: *const fn (ctx: Ctx, allocator: Allocator) void,
};

fn hasVTable(file: *const File, vtable: *const VTable) bool {
    return @intFromPtr(file.impl.vtable) == @intFromPtr(vtable);
}

fn api(
    file: *const File,
    comptime right: Api,
    comptime func: std.meta.FieldEnum(VTable.Api),
) error{AccessDenied}!@FieldType(VTable.Api, @tagName(func)) {
    return if (@field(file.rights, @tagName(right)))
        @field(file.impl.vtable.api, @tagName(func))
    else
        error.AccessDenied;
}

// Is this what it's called?
const manual_function_devirtualization = switch (builtin.mode) {
    .ReleaseSafe, .ReleaseFast => true,
    .Debug, .ReleaseSmall => false,
};

pub fn fd_prestat_get(file: *File) Error!types.Prestat {
    if (manual_function_devirtualization and file.hasVTable(&preopen.vtable)) {
        @branchHint(.likely);
        return preopen.fd_prestat_get(file.impl.ctx);
    } else {
        return file.impl.vtable.api.fd_prestat_get(file.impl.ctx);
    }
}

pub fn fd_prestat_dir_name(file: *File, path: []u8) Error!void {
    if (manual_function_devirtualization and file.hasVTable(&preopen.vtable)) {
        @branchHint(.likely);
        return preopen.fd_prestat_dir_name(file.impl.ctx, path);
    } else {
        return file.impl.vtable.api.fd_prestat_dir_name(file.impl.ctx, path);
    }
}

pub fn fd_readdir(
    file: *File,
    // allocator: Allocator,
    buf: []u8,
    cookie: types.DirCookie,
) Error!types.Size {
    if (!file.rights.fd_readdir) {
        return error.AccessDenied;
    }

    const args = .{ file.impl.ctx, buf, cookie };
    if (manual_function_devirtualization and file.hasVTable(&preopen.vtable)) {
        @branchHint(.likely);
        return @call(.auto, preopen.fd_readdir, args);
    } else {
        return @call(.auto, file.impl.vtable.api.fd_readdir, args);
    }
}

pub fn fd_pwrite(
    file: *File,
    iovs: []const Ciovec,
    offset: types.FileSize,
    total_len: u32,
) Error!u32 {
    return (try file.api(.fd_write, .fd_pwrite))(file.impl.ctx, iovs, offset, total_len);
}

pub fn fd_write(file: *File, iovs: []const Ciovec, total_len: u32) Error!u32 {
    return (try file.api(.fd_write, .fd_write))(file.impl.ctx, iovs, total_len);
}

// pub fn fd_fdstat_set_rights(file: *File, base: Rights, inheriting: Rights) Error!void
// if padding bits set => error
// if actual rights contains (do bitwise &) rights they want => OK
// otherwise => error

pub fn deinit(file: *File, allocator: Allocator) void {
    file.impl.vtable.deinit(file.impl.ctx, allocator);
    file.* = undefined;
}

const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const Api = @import("api.zig").Api;
const types = @import("types.zig");
