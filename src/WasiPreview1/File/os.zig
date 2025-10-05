//! Unbuffered access to a real, genuine, 100% all-natural OS file descriptor.

pub const Close = enum { close, leave_open };

/// Callers must ensure that `fd` is an open file handle.
pub fn wrapFile(fd: std.fs.File, close: Close, rights: types.Rights.Valid) File {
    return .{
        .rights = .init(rights),
        .impl = .{
            .ctx = .{ .os = .{ .file = fd, .close = close } },
            .vtable = &vtable,
        },
    };
}

pub fn wrapStandardStreams() File.StandardStreams {
    const write_rights = types.Rights.Valid{ .fd_write = true };
    // Leave standard streams open in case an interpreter error/panic occurs
    return .{
        .stdin = wrapFile(std.fs.File.stdin(), .leave_open, .{ .fd_read = true }),
        .stdout = wrapFile(std.fs.File.stdout(), .leave_open, write_rights),
        .stderr = wrapFile(std.fs.File.stderr(), .leave_open, write_rights),
    };
}

fn deinit(ctx: Ctx, allocator: std.mem.Allocator) void {
    _ = allocator;
    switch (ctx.os.close) {
        .leave_open => {},
        .close => ctx.os.file.close(),
    }
}

fn fd_fdstat_get(ctx: Ctx) Error!types.FdStat.File {
    // TODO: On Windows, more efficient to use NtQueryInformationFile: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntqueryinformationfile
    // TODO: On Linux, more efficient to use statx, asking only for mode
    const @"type" = types.FileType.fromZigKind(
        (try ctx.os.file.stat()).kind,
    ) catch |e| switch (e) {
        error.UnknownSocketType => .unknown, // TODO: Requires getsockopt
    };

    // TODO: On Windows, check for FILE_APPEND_DATA (might be in FILE_ACCESS_INFORMATION via NtQueryInformationFile)
    const access: std.posix.O = @bitCast(@as(
        @typeInfo(std.posix.O).@"struct".backing_integer.?,
        @intCast(
            std.posix.fcntl(
                ctx.os.file.handle,
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
        .flags = types.FdFlags{
            .valid = .{
                .append = access.APPEND,
                .dsync = if (@hasField(std.posix.O, "DSYNC")) access.DSYNC else false,
                .nonblock = access.NONBLOCK,
                // O_RSYNC not implemented on Linux
                .rsync = if (@hasField(std.posix.O, "RSYNC")) access.RSYNC else false,
                .sync = access.SYNC, // FILE_FLAG_WRITE_THROUGH on Windows? https://github.com/golang/go/issues/35358
            },
        },
    };
}

fn fd_pwrite(
    ctx: Ctx,
    iovs: []const File.Ciovec,
    offset: types.FileSize,
    total_len: u32,
) Error!u32 {
    const file = ctx.os.file;
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
    // OS needs a chance to return errors, even if length is 0
    _ = total_len;
    // if (total_len == 0) {
    //     return 0;
    // }

    // TODO: How to handle Windows? multiple WriteFile calls?
    const written = ctx.os.file.writev(File.Ciovec.castSlice(iovs)) catch |e| return switch (e) {
        error.NotOpenForWriting => error.BadFd,
        else => |known| known,
    };

    return @intCast(written);
}

const vtable = File.VTable{
    .api = .{
        .fd_fdstat_get = fd_fdstat_get,
        .fd_prestat_get = File.invalid.fd_prestat_get,
        .fd_prestat_dir_name = File.invalid.fd_prestat_dir_name,
        .fd_readdir = File.invalid.fd_readdir,
        .fd_write = fd_write,
        .fd_pwrite = fd_pwrite,
    },
    .deinit = deinit,
};

const std = @import("std");
const builtin = @import("builtin");
const File = @import("../File.zig");
const types = @import("../types.zig");
const Ctx = File.Ctx;
const Error = File.Error;
