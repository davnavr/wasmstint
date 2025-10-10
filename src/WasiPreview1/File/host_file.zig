//! Unbuffered access to a real, genuine, 100% all-natural OS file descriptor.

pub const Close = enum { close, leave_open };

const HostFile = struct {
    file: std.fs.File,
    close: Close,
};

pub const possible_rights = types.Rights.Valid.init(&.{
    .fd_datasync,
    .fd_read,
    .fd_seek,
    .fd_fdstat_set_flags,
    .fd_sync,
    .fd_tell,
    .fd_write,
    .fd_advise,
    .fd_allocate,
    .fd_readdir,
    .fd_filestat_get,
    .fd_filestat_set_size,
    .fd_filestat_set_times,
    .sock_shutdown,
    .sock_accept,
});

/// Callers must ensure that `fd` is an open file handle.
///
/// Ownership of `fd` is transferred to the `File`.
pub fn wrapFile(fd: std.fs.File, close: Close) File.Impl {
    return File.Impl{
        .ctx = Ctx.init(HostFile{ .file = fd, .close = close }),
        .vtable = &vtable,
    };
}

/// Creates wrappers for the standard streams, and makes guest calls to `fd_close` a no-op.
pub fn wrapStandardStreams() File.StandardStreams {
    const write_rights = File.Rights.init(types.Rights.Valid{ .fd_write = true });
    // Leave standard streams open in case an interpreter error/panic occurs
    return .{
        .stdin = File{
            .rights = File.Rights.init(types.Rights.Valid{ .fd_read = true }),
            .impl = wrapFile(std.fs.File.stdin(), .leave_open),
        },
        .stdout = File{
            .rights = write_rights,
            .impl = wrapFile(std.fs.File.stdout(), .leave_open),
        },
        .stderr = File{
            .rights = write_rights,
            .impl = wrapFile(std.fs.File.stderr(), .leave_open),
        },
    };
}

pub fn closeHandle(handle: std.posix.fd_t) Error!void {
    switch (builtin.os.tag) {
        .windows => std.os.windows.CloseHandle(handle),
        else => switch (std.posix.errno(std.posix.system.close(handle))) {
            .SUCCESS => {},
            .BADF => unreachable,
            .INTR => {}, // https://github.com/ziglang/zig/issues/2425
            .IO => return error.InputOutput,
            .NOSPC => return error.NoSpaceLeft,
            .DQUOT => return error.DiskQuota,
            else => |unknown| return std.posix.unexpectedErrno(unknown),
        },
    }
}

fn fd_close(ctx: Ctx, allocator: std.mem.Allocator) Error!void {
    const self = ctx.get(HostFile);
    _ = allocator;
    switch (self.close) {
        .leave_open => {},
        .close => try closeHandle(self.file.handle),
    }
}

fn fd_fdstat_get(ctx: Ctx) Error!types.FdStat.File {
    const self = ctx.get(HostFile);
    // TODO: On Windows, more efficient to use NtQueryInformationFile: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntqueryinformationfile
    // TODO: On Linux, more efficient to use statx, asking only for mode
    const @"type" = types.FileType.fromZigKind(
        (try self.file.stat()).kind,
    ) catch |e| switch (e) {
        error.UnknownSocketType => .unknown, // TODO: Requires getsockopt
    };

    // TODO: On Windows, check for FILE_APPEND_DATA (might be in FILE_ACCESS_INFORMATION via NtQueryInformationFile)
    const access: std.posix.O = @bitCast(@as(
        @typeInfo(std.posix.O).@"struct".backing_integer.?,
        @intCast(
            std.posix.fcntl(
                self.file.handle,
                std.posix.F.GETFL,
                undefined,
            ) catch |e| return switch (e) {
                error.Locked => error.WouldBlock,
                else => |err| err,
            },
        ),
    ));

    return .{
        .type = @"type",
        .flags = types.FdFlags{ .valid = types.FdFlags.Valid.fromFlagsPosix(access) },
    };
}

fn fd_pwrite(
    ctx: Ctx,
    iovs: []const File.Ciovec,
    offset: types.FileSize,
    total_len: u32,
) Error!u32 {
    const self = ctx.get(HostFile);
    const file = self.file;
    switch (builtin.os.tag) {
        .linux,
        .freebsd,
        .netbsd,
        .dragonfly,
        .illumos,
        => |ux| {
            var ciovs = File.Ciovec.castSlice(iovs);
            // Prevent EINVAL when total length overflows `ssize_t`
            if (total_len > std.math.maxInt(isize)) {
                @branchHint(.cold);
                var len_sum = total_len;
                while (len_sum > std.math.maxInt(isize)) {
                    const removed = ciovs[ciovs.len - 1];
                    len_sum -= removed.len;
                    ciovs.len -= 1;
                }
            }

            // Duplicated code from `std.posix.pwritev` (MIT License).
            const pwritev = if (ux == .linux and std.os.linux.wrapped.lfs64_abi)
                std.c.pwritev64
            else
                std.posix.system.pwritev;

            while (true) {
                // Zig unfortunately conflates NXIO, SPIPE, and OVERFLOW into one error
                const written = pwritev(
                    file.handle,
                    ciovs.ptr,
                    @min(ciovs.len, std.posix.IOV_MAX),
                    @as(i64, @bitCast(offset.bytes)),
                );

                return switch (std.posix.errno(written)) {
                    .SUCCESS => @intCast(written),
                    .INTR => continue,
                    .INVAL => error.InvalidArgument,
                    .FAULT => unreachable,
                    .SRCH => error.ProcessNotFound,
                    .AGAIN => error.WouldBlock,
                    .BADF => error.BadFd,
                    .DESTADDRREQ => unreachable, // `connect` was never called.
                    .OPNOTSUPP => unreachable,
                    .DQUOT => error.DiskQuota,
                    .FBIG => error.FileTooBig,
                    .IO => error.InputOutput,
                    .NOSPC => error.NoSpaceLeft,
                    .PERM => error.PermissionDenied,
                    .PIPE => error.BrokenPipe,
                    .NXIO => error.NoDevice,
                    // .SPIPE => if (offset.bytes == 0)
                    //     fd_write(ctx, iovs, total_len)
                    // else
                    //     error.SeekPipe,
                    .SPIPE => error.SeekPipe,
                    .OVERFLOW => return error.Overflow,
                    .BUSY => return error.DeviceBusy,
                    else => |errno| std.posix.unexpectedErrno(errno),
                };
            }
        },
        .windows => {
            // NtWriteFile allows "seek-and-write", but not proper `pwritev` or even `pwrite`
            std.log.err("TODO: fd_pwrite on Windows", .{});
            return error.Unimplemented;
        },
        .wasi => @compileError("WASM on WASM fd_pwrite"),
        else => if (iovs.len == 0) {
            return 0;
        } else {
            // Fall back on `pwrite`, just like Zig's `std`.
            const result = std.posix.pwrite(
                file.handle,
                iovs[0].bytes(),
                offset.bytes,
            ) catch |e| switch (e) {
                error.NotOpenForWriting => error.BadFd,
                else => |known| known,
            };

            return @bitCast(result);
        },
    }
}

fn fd_write(ctx: Ctx, iovs: []const File.Ciovec, total_len: u32) Error!u32 {
    const self = ctx.get(HostFile);

    // OS needs a chance to return errors, even if length is 0
    _ = total_len;
    // if (total_len == 0) {
    //     return 0;
    // }

    // TODO: How to handle Windows? multiple WriteFile calls?
    const written = self.file.writev(File.Ciovec.castSlice(iovs)) catch |e| return switch (e) {
        error.NotOpenForWriting => error.BadFd,
        else => |known| known,
    };

    return @intCast(written);
}

fn sock_accept(ctx: Ctx, flags: types.FdFlags.Valid) Error!File.Impl {
    _ = ctx;
    _ = flags;
    return Error.Unimplemented;
}

fn sock_recv(
    ctx: Ctx,
    iovs: []const File.Iovec,
    total_len: u32,
    flags: types.RiFlags.Valid,
) Error!File.SockRecvResult {
    _ = ctx;
    _ = iovs;
    _ = total_len;
    _ = flags;
    return Error.Unimplemented;
}

fn sock_send(ctx: Ctx, iovs: []const File.Ciovec, total_len: u32) Error!types.Size {
    _ = ctx;
    _ = iovs;
    _ = total_len;
    return Error.Unimplemented;
}

pub fn sock_shutdown(ctx: Ctx, how: types.SdFlags.Valid) Error!void {
    _ = ctx;
    _ = how;
    return Error.Unimplemented;
}

const vtable = File.VTable{
    .fd_advise = File.unimplemented.fd_advise,
    .fd_allocate = File.unimplemented.fd_allocate,
    .fd_close = fd_close,
    .fd_datasync = File.unimplemented.fd_datasync,
    .fd_fdstat_get = fd_fdstat_get,
    .fd_fdstat_set_flags = File.unimplemented.fd_fdstat_set_flags,
    .fd_filestat_get = File.unimplemented.fd_filestat_get,
    .fd_filestat_set_size = File.unimplemented.fd_filestat_set_size,
    .fd_filestat_set_times = File.unimplemented.fd_filestat_set_times,
    .fd_pread = File.unimplemented.fd_pread,
    .fd_prestat_get = File.not_dir.fd_prestat_get,
    .fd_prestat_dir_name = File.not_dir.fd_prestat_dir_name,
    .fd_pwrite = fd_pwrite,
    .fd_read = File.unimplemented.fd_read,
    .fd_readdir = File.not_dir.fd_readdir,
    .fd_seek = File.unimplemented.fd_seek,
    .fd_sync = File.unimplemented.fd_sync,
    .fd_tell = File.unimplemented.fd_tell,
    .fd_write = fd_write,
    .path_create_directory = path_create_directory,
    .path_filestat_get = path_filestat_get,
    .path_filestat_set_times = path_filestat_set_times,
    .path_open = path_open,
    .path_readlink = File.unimplemented.path_readlink,
    .path_remove_directory = path_remove_directory,
    .path_symlink = path_symlink,
    .path_unlink_file = path_unlink_file,
    .sock_accept = sock_accept,
    .sock_recv = sock_recv,
    .sock_send = sock_send,
    .sock_shutdown = sock_shutdown,
};

fn path_create_directory(_: Ctx, _: []const u8) Error!void {
    @trap();
}

fn path_filestat_get(
    _: Ctx,
    _: *ArenaAllocator,
    _: types.Device.HashSeed,
    _: types.INode.HashSeed,
    _: types.LookupFlags.Valid,
    _: Path,
) Error!types.FileStat {
    @trap();
}

fn path_filestat_set_times(
    _: Ctx,
    _: types.LookupFlags.Valid,
    _: []const u8,
    _: types.Timestamp,
    _: types.Timestamp,
    _: types.FstFlags.Valid,
) Error!void {
    @trap();
}

fn path_open(
    _: Ctx,
    _: *ArenaAllocator,
    _: types.LookupFlags.Valid,
    _: Path,
    _: types.OpenFlags.Valid,
    _: types.Rights.Valid,
    _: types.FdFlags.Valid,
) Error!File.OpenedPath {
    @trap();
}

fn path_remove_directory(_: Ctx, _: []const u8) Error!void {
    @trap();
}

fn path_symlink(_: Ctx, _: []const u8, _: []const u8) Error!void {
    @trap();
}

fn path_unlink_file(_: Ctx, _: []const u8) Error!void {
    @trap();
}

const std = @import("std");
const builtin = @import("builtin");
const ArenaAllocator = std.heap.ArenaAllocator;
const File = @import("../File.zig");
const types = @import("../types.zig");
const Path = @import("../Path.zig");
const Ctx = File.Ctx;
const Error = File.Error;
