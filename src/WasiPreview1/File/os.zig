//! Unbuffered access to a real, genuine, 100% all-natural OS file descriptor.

/// Callers must ensure that `fd` is an open file handle.
pub fn wrapFile(fd: std.fs.File, rights: Rights) File {
    return .{
        .rights = rights,
        .impl = .{ .ctx = .{ .real = fd }, .vtable = &vtable },
    };
}

pub fn wrapStandardStreams() File.StandardStreams {
    const write_rights: Rights = .{ .fd_write = true };
    return .{
        .stdin = wrapFile(std.fs.File.stdin(), .{ .fd_read = true }),
        .stdout = wrapFile(std.fs.File.stdout(), write_rights),
        .stderr = wrapFile(std.fs.File.stderr(), write_rights),
    };
}

fn deinit(ctx: Ctx, allocator: std.mem.Allocator) void {
    _ = allocator;
    ctx.real.close();
}

fn fd_pwrite(
    ctx: Ctx,
    iovs: []const File.Ciovec,
    offset: types.FileSize,
    total_len: u32,
) Error!u32 {
    const file = ctx.real;
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
                    .SPIPE => if (offset.bytes == 0) {
                        return fd_write(ctx, iovs, total_len);
                    } else error.SeekPipe,
                    .OVERFLOW => return error.Overflow,
                    .BUSY => return error.DeviceBusy,
                    else => |errno| std.posix.unexpectedErrno(errno),
                };
            }
        },
        .windows => {
            // NtWriteFile allows "seek-and-write", but not proper `pwritev` or even `pwrite`
            std.log.err("TODO: fd_pwrite on Windows");
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
    const written = ctx.real.writev(File.Ciovec.castSlice(iovs)) catch |e| return switch (e) {
        error.NotOpenForWriting => error.BadFd,
        else => |known| known,
    };

    return @intCast(written);
}

const vtable = File.VTable{
    .api = .{
        .fd_pwrite = &fd_pwrite,
        .fd_write = &fd_write,
    },
    .deinit = &deinit,
};

const std = @import("std");
const builtin = @import("builtin");
const File = @import("../File.zig");
const types = @import("../types.zig");
const Ctx = File.Ctx;
const Rights = File.Rights;
const Error = File.Error;
