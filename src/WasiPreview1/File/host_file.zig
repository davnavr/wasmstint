//! Unbuffered access to a real, genuine, 100% all-natural OS file descriptor.

/// Indicates whether the underlying OS file descriptor can be closed by the WASI guest.
pub const Close = enum {
    close,
    /// Used to prevent the WASI guest program from closing the host's standard streams.
    leave_open,
};

const HostFile = struct {
    file: std.Io.File,
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

pub const write_rights = types.Rights.Valid.init(&.{
    .fd_write,
    .fd_allocate,
    .fd_readdir,
    .fd_filestat_set_size,
    .fd_filestat_set_times,
});

comptime {
    std.debug.assert(possible_rights.contains(write_rights));
}

/// Callers must ensure that `fd` is an open file handle.
///
/// Ownership of `fd` is transferred to the `File`.
pub fn wrapFile(fd: std.Io.File, close: Close) File.Impl {
    return File.Impl{
        .ctx = Ctx.init(HostFile{ .file = fd, .close = close }),
        .vtable = &vtable,
    };
}

/// Creates wrappers for the standard streams, and makes guest calls to `fd_close` a no-op.
pub fn wrapStandardStreams() File.StandardStreams {
    const common_rights = .{
        .fd_filestat_get,
        // .fd_tell, // should only be enabled if stream is a "file"
    };

    const out_rights = File.Rights.init(
        types.Rights.Valid.init(&(.{.fd_write} ++ common_rights)),
    );

    // Leave standard streams open in case an interpreter error/panic occurs
    return .{
        .stdin = File{
            .rights = File.Rights.init(
                types.Rights.Valid.init(&(.{.fd_read} ++ common_rights)),
            ),
            .impl = wrapFile(std.Io.File.stdin(), .leave_open),
        },
        .stdout = File{
            .rights = out_rights,
            .impl = wrapFile(std.Io.File.stdout(), .leave_open),
        },
        .stderr = File{
            .rights = out_rights,
            .impl = wrapFile(std.Io.File.stderr(), .leave_open),
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

const log = std.log.scoped(.host_file);

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
    if (builtin.os.tag == .windows) {
        var status_block: std.os.windows.IO_STATUS_BLOCK = undefined;
        var info: std.os.windows.FILE_ALL_INFORMATION = undefined;

        // Equivalent in `kernel32` is `GetFileInformationByHandle`
        // Simplified version of implementation of `std.fs.File.stat`
        const status = host_os.windows.ntQueryInformationFile(
            self.file.handle,
            &status_block,
            // Need both `FILE_ACCESS_INFORMATION` and `FILE_STANDARD_INFORMATION`
            .FileAllInformation,
            &info,
        );
        switch (status) {
            .SUCCESS, .BUFFER_OVERFLOW => {},
            .INVALID_PARAMETER => unreachable,
            .ACCESS_DENIED => return Error.AccessDenied,
            .INVALID_DEVICE_REQUEST => {
                const char_device = types.FdStat.File{
                    .type = types.FileType.character_device,
                    .flags = types.FdFlags{ .valid = .{} },
                };

                // Not a file, check for a console handle (standard streams)
                switch (host_os.windows.GetFileType(self.file.handle)) {
                    .disk => unreachable,
                    .char => return char_device,
                    .pipe => {
                        // Zig `isCygwinPty` wrapper does useless work, it checks if file is console
                        const pipe_pty = host_os.windows.isMsysOrCygwinPty(self.file.handle);
                        switch (pipe_pty.tag) {
                            .not_a_pty => {},
                            .msys, .cygwin => return char_device,
                        }
                    },
                    .unknown => switch (std.os.windows.GetLastError()) {
                        .SUCCESS => {},
                        else => |bad| return std.os.windows.unexpectedError(bad),
                    },
                    .remote, _ => |bad| {
                        log.err("unknown FILE_TYPE 0x{X} in fd_fdstat_get", .{@intFromEnum(bad)});
                    },
                }

                return types.FdStat.File{ .type = .unknown, .flags = .{ .valid = .{} } };
            },
            else => return std.os.windows.unexpectedStatus(status),
        }

        // TODO: Windows might need symlink check in fd_fdstat_get
        // Zig checks for `FILE_ATTRIBUTE_REPARSE_POINT` in `BasicInformation` to detect symlinks

        const fd_flags = types.FdFlags.Valid.fromFlagsWindows(info.AccessInformation.AccessFlags);

        return types.FdStat.File{
            // Zig checks `BasicInformation.FileAttributes` instead.
            .type = if (info.StandardInformation.Directory != 0) .directory else .regular_file,
            .flags = types.FdFlags{ .valid = fd_flags },
        };
    } else return .{
        .flags = types.FdFlags{
            .valid = types.FdFlags.Valid.fromFlagsPosix(
                try host_os.unix_like.fcntlGetFl(self.file.handle),
            ),
        },
        .type = type: {
            if (builtin.os.tag == .linux) fallback: {
                var statx: std.os.linux.Statx = undefined;
                host_os.linux.statx(
                    self.file.handle,
                    "",
                    .{ .EMPTY_PATH = true, .SYMLINK_NOFOLLOW = true },
                    .{ .TYPE = true },
                    &statx,
                ) catch |e| switch (e) {
                    error.StatxNotSupported => {
                        log.debug("statx is not supported, falling back to stat", .{});
                        break :fallback;
                    },
                    error.MissingRequestedFields => {
                        @branchHint(.cold);
                        log.debug("statx did not provide type: 0x{X}", .{statx.mask});
                        break :type .unknown; // exotic file type
                    },
                    else => |err| return err,
                };

                const S = std.os.linux.S;

                break :type switch (statx.mode & S.IFMT) {
                    S.IFDIR => .directory,
                    S.IFCHR => .character_device,
                    S.IFBLK => .block_device,
                    S.IFREG => .regular_file,
                    S.IFIFO => .unknown,
                    S.IFLNK => .symbolic_link,
                    S.IFSOCK => .unknown, // TODO: Requires getsockopt
                    else => .unknown,
                };
            }

            const stat = std.posix.fstat(self.file.handle) catch |e| switch (e) {
                error.Canceled, error.Streaming => unreachable,
                else => unreachable,
            };

            break :type types.FileType.fromPosixMode(stat.mode) catch |e| switch (e) {
                error.UnknownSocketType => .unknown, // TODO: Requires getsockopt
            };
        },
    };
}

fn fd_filestat_get(
    ctx: Ctx,
    device_hash_seed: types.Device.HashSeed,
    inode_hash_seed: types.INode.HashSeed,
) Error!types.FileStat {
    const self = ctx.get(HostFile);
    return host_os.fileStat(self.file.handle, device_hash_seed, inode_hash_seed);
}

fn overflowsSignedSize(total_len: u32) bool {
    return total_len > std.math.maxInt(isize);
}

/// Returns a subslice of `iovs` to avoid OS syscalls returning `EINVAL` due to `total_len`
/// overflowing `ssize_t`.
fn iovsBytesLenBounded(iovs: anytype, total_len: u32) @TypeOf(iovs) {
    if (!overflowsSignedSize(total_len)) {
        return iovs;
    } else {
        @branchHint(.cold);
        var final = iovs;
        var len_sum = total_len;
        while (overflowsSignedSize(len_sum)) {
            const removed = final[final.len - 1];
            len_sum -= @intCast(removed.len);
            final.len -= 1;
        }

        return final;
    }
}

// fn fd_pread(ctx: Ctx, iovs: []const File.Iovec, total_len: u32) Error!u32 {
//     const self = ctx.get(HostFile);
//     switch (builtin.os.tag) {
//         // Does not have `preadv`, fallback to `pread`
//         // Check copied from `std.posix.preadv`
//         .windows, .macos, .ios, .watchos, .tvos, .visionos, .haiku, .serenity => {
//             // `NtReadFile` allows "seek-and-read", but not proper `pwritev` or even `pwrite`
//             log.err("TODO: fd_pwrite on " ++ @tagName(builtin.os.tag), .{});
//             return error.Unimplemented;
//         },
//         else => {
//             const ciovs = iovsBytesLenBounded(File.Ciovec.castSlice(iovs), total_len);
//             // Duplicated code from `std.posix.preadv`
//             // Zig conflates `ENXIO`, `ESPIPE`, and `EOVERFLOW`
//             const preadv = if (builtin.os.tag == .linux and std.os.linux.wrapped.lfs64_abi)
//                 std.c.preadv
//             else
//                 std.posix.system.preadv;
//             while (true) {
//                 const written = preadv(
//                     self.file.handle,
//                     ciovs.ptr,
//                     @min(ciovs.len, std.posix.IOV_MAX),
//                     @as(i64, @bitCast(offset.bytes)),
//                 );
//             }
//         },
//     }
// }

fn fd_pwrite(
    ctx: Ctx,
    iovs: []const File.Ciovec,
    offset: types.FileSize,
    total_len: u32,
) Error!u32 {
    const self = ctx.get(HostFile);
    switch (builtin.os.tag) {
        // Does not have `pwritev`, fallback to `pwrite`
        // Check copied from `std.posix.pwritev`
        .windows, .macos, .ios, .watchos, .tvos, .visionos, .haiku => {
            // `NtWriteFile` allows "seek-and-write", but not proper `pwritev` or even `pwrite`
            log.err("TODO: fd_pwrite on " ++ @tagName(builtin.os.tag), .{});
            return error.Unimplemented;
        },
        else => {
            const ciovs = iovsBytesLenBounded(File.Ciovec.castSlice(iovs), total_len);

            // Duplicated code from `std.posix.pwritev`.
            while (true) {
                // Zig unfortunately conflates NXIO, SPIPE, and OVERFLOW into one error
                const written = host_os.unix_like.pwritev(
                    self.file.handle,
                    ciovs.ptr,
                    @min(ciovs.len, std.posix.IOV_MAX),
                    @as(i64, @bitCast(offset.bytes)),
                );

                return switch (std.posix.errno(written)) {
                    .SUCCESS => @intCast(written),
                    .INTR => {
                        @branchHint(.unlikely);
                        continue;
                    },
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
                    .SPIPE => error.SeekPipe,
                    .OVERFLOW => error.Overflow,
                    .BUSY => error.DeviceBusy,
                    else => |errno| std.posix.unexpectedErrno(errno),
                };
            }
        },
    }
}

fn fd_read(ctx: Ctx, iovs: []const File.Iovec, total_len: u32) Error!u32 {
    const self = ctx.get(HostFile);
    log.debug("attempting to read up to {} bytes", .{total_len});
    if (builtin.os.tag == .windows) {
        if (total_len == 0) {
            @branchHint(.unlikely);
            return 0;
        } else if (iovs.len > 1) {
            @branchHint(.unlikely); // More common to write a single iovec
            // Could use `scratch` allocator to create a buffer
            log.debug(
                "consider buffering fd_read on windows: iovs.len={d}, total_len={d}",
                .{ iovs.len, total_len },
            );
        }

        const buffer = iovs[0].bytes();
        std.debug.assert(buffer.len > 0);
        std.debug.assert(buffer.len <= total_len);
        // Copied from `std.os.windows.ReadFile`
        while (true) {
            // `ReadFile` sets this to `0` anyway.
            var number_of_bytes_read: std.os.windows.DWORD = undefined;
            // `kernel32.ReadFile` handles reading from consoles, not just normal files
            const success = std.os.windows.kernel32.ReadFile(
                self.file.handle,
                buffer.ptr,
                @as(u32, @intCast(buffer.len)),
                &number_of_bytes_read,
                null,
            ) != 0;

            return if (success)
                number_of_bytes_read
            else switch (std.os.windows.GetLastError()) {
                .IO_PENDING => unreachable,
                .OPERATION_ABORTED => {
                    @branchHint(.unlikely);
                    continue;
                },
                .BROKEN_PIPE => error.BrokenPipe,
                .HANDLE_EOF => 0,
                .NETNAME_DELETED => error.ConnectionResetByPeer,
                .LOCK_VIOLATION => error.LockViolation,
                .ACCESS_DENIED => error.AccessDenied,
                .INVALID_HANDLE => error.BadFd,
                else => |err| std.os.windows.unexpectedError(err),
            };
        }
    } else {
        const os_iovs = iovsBytesLenBounded(File.Iovec.castSlice(iovs), total_len);

        // Copied from `std.posix.readv`
        // Zig conflates `ENOBUFS` and `ENOMEM`
        while (true) {
            const amt = std.posix.system.readv(
                self.file.handle,
                os_iovs.ptr,
                @min(os_iovs.len, std.posix.IOV_MAX),
            );

            return switch (std.posix.errno(amt)) {
                .SUCCESS => @intCast(amt),
                .INTR => {
                    @branchHint(.unlikely);
                    continue;
                },
                .INVAL => error.InvalidArgument,
                .FAULT => unreachable,
                .SRCH => error.ProcessNotFound,
                .AGAIN => error.WouldBlock,
                .BADF => error.BadFd,
                .IO => error.InputOutput,
                .ISDIR => error.IsDir,
                .NOBUFS => error.NoBufferSpace,
                .NOMEM => error.SystemResources,
                .NOTCONN => error.SocketNotConnected,
                .CONNRESET => error.ConnectionResetByPeer,
                .TIMEDOUT => error.ConnectionTimedOut,
                else => |err| std.posix.unexpectedErrno(err),
            };
        }
    }
}

fn fd_tell(ctx: Ctx) Error!types.FileSize {
    const self = ctx.get(HostFile);
    // Zig conflates multiple errors (e.g. `EINVAL`, `ESPIPE`, etc.) into `error.Unseekable`
    //return self.file.getPos();
    //return std.posix.lseek_CUR_get(self.file.handle);
    //return std.os.windows.SetFilePointerEx_CURRENT_get(self.file.handle);

    if (builtin.os.tag == .windows) {
        // Similar code to `std.os.windows.kernel32.SetFilePointerEx_CURRENT_get()`

        // var offset: std.os.windows.LARGE_INTEGER = undefined;
        var io: std.os.windows.IO_STATUS_BLOCK = undefined;
        var info: std.os.windows.FILE_POSITION_INFORMATION = undefined;
        const status = host_os.windows.ntQueryInformationFile(
            self.file.handle,
            &io,
            .FilePositionInformation,
            &info,
        );
        return switch (status) {
            .SUCCESS, .BUFFER_OVERFLOW => types.FileSize{
                .bytes = @as(u64, @bitCast(info.CurrentByteOffset)),
            },
            .INFO_LENGTH_MISMATCH => unreachable,
            .ACCESS_DENIED => error.AccessDenied,
            .INVALID_DEVICE_REQUEST => error.SeekPipe, // probably a console handle
            else => std.os.windows.unexpectedStatus(status),
        };
    } else if (@hasDecl(std.posix.system, "SEEK") and std.posix.SEEK != void) {
        // Duplicated code from `std.posix.lseek_CUR_get()`.
        // Could also add check for 32-bit linux to use `llseek` instead
        const pos = host_os.unix_like.lseek(self.file.handle, 0, std.posix.SEEK.CUR);
        return switch (std.posix.errno(pos)) {
            .SUCCESS => types.FileSize{ .bytes = @bitCast(pos) },
            .BADF => unreachable,
            .INVAL => Error.InvalidArgument, // guest could try to go beyond end
            .OVERFLOW => Error.Overflow,
            .SPIPE => Error.SeekPipe,
            .NXIO => Error.NoDevice,
            else => |err| std.posix.unexpectedErrno(err),
        };
    } else {
        @compileError("fd_tell on " + @tagName(builtin.os.tag));
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
    // TODO: Use `std.posix.writev`
    const written = std.fs.File.adaptFromNewApi(self.file).writev(
        File.Ciovec.castSlice(iovs),
    ) catch |e| return switch (e) {
        error.NotOpenForWriting => error.BadFd,
        error.Canceled => unreachable,
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
    .fd_filestat_get = fd_filestat_get,
    .fd_filestat_set_size = File.unimplemented.fd_filestat_set_size,
    .fd_filestat_set_times = File.unimplemented.fd_filestat_set_times,
    .fd_pread = File.unimplemented.fd_pread, // fd_pread,
    .fd_prestat_get = File.not_dir.fd_prestat_get,
    .fd_prestat_dir_name = File.not_dir.fd_prestat_dir_name,
    .fd_pwrite = fd_pwrite,
    .fd_read = fd_read,
    .fd_readdir = File.not_dir.fd_readdir,
    .fd_seek = File.unimplemented.fd_seek,
    .fd_sync = File.unimplemented.fd_sync,
    .fd_tell = fd_tell,
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
    _: std.mem.Allocator,
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
const host_os = @import("../host_os.zig");
const File = @import("../File.zig");
const types = @import("../types.zig");
const Path = @import("../Path.zig");
const Ctx = File.Ctx;
const Error = File.Error;
