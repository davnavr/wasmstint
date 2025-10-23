//! Abstractions over OS APIs for implementing the WASI preview 1 API.

// Platform specific modules.
pub const windows = @import("host_os/windows.zig");
pub const unix_like = @import("host_os/unix_like.zig");

pub const Fd = std.posix.fd_t;

pub const WasiError = @import("errno.zig").Error;

/// Used to implement [`fd_filestat_get()`].
///
/// [`fd_filestat_get()`]: https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#fd_filestat_get
pub fn fileStat(
    fd: Fd,
    device_hash_seed: wasi_types.Device.HashSeed,
    inode_hash_seed: wasi_types.INode.HashSeed,
) WasiError!wasi_types.FileStat {
    if (builtin.os.tag == .windows) {
        // Kernel32 equivalent is `GetFileInformationByHandleEx`

        // Can't use `FILE_FS_OBJECTID_INFORMATION`, since 16-byte GUID can't fit in 64-bit dev #
        const fs_volume_info = info: {
            var io: std.os.windows.IO_STATUS_BLOCK = undefined;
            var info: std.os.windows.FILE_FS_VOLUME_INFORMATION = undefined;
            const status = std.os.windows.ntdll.NtQueryVolumeInformationFile(
                fd,
                &io,
                &info,
                @sizeOf(@TypeOf(info)),
                .FileFsVolumeInformation,
            );
            switch (status) {
                .SUCCESS, .BUFFER_OVERFLOW => break :info info,
                .INVALID_PARAMETER => unreachable,
                .ACCESS_DENIED => return error.AccessDenied,
                inline .INVALID_DEVICE_REQUEST => |bad| {
                    std.log.debug("could not obtain volume information: " ++ @tagName(bad), .{});
                    return windows.fileStatNonDisk(fd, device_hash_seed, inode_hash_seed);
                },
                else => return std.os.windows.unexpectedStatus(status),
            }
        };

        const dev = wasi_types.Device.init(device_hash_seed, fs_volume_info.VolumeSerialNumber);

        // Introduced to support Windows Subsystem for Linux (likely version 1) with
        // Windows 10 update 1803.
        const stat_lx_support = struct {
            var flag = std.atomic.Value(bool).init(true);
            const min_version = std.Target.Os.WindowsVersion.win10_rs4;
            const is_min_version = builtin.os.isAtLeast(.windows, min_version) == true;
            const likely_has: std.builtin.BranchHint = if (is_min_version) .likely else .none;
        };

        if (stat_lx_support.flag.load(.unordered)) {
            @branchHint(stat_lx_support.likely_has);
            var io: std.os.windows.IO_STATUS_BLOCK = undefined;
            var stat_lx_info: windows.FILE_STAT_LX_INFORMATION = undefined;
            const status = windows.ntQueryInformationFile(
                fd,
                &io,
                .FileStatLxInformation,
                &stat_lx_info,
            );
            switch (status) {
                .SUCCESS, .BUFFER_OVERFLOW => {
                    @branchHint(stat_lx_support.likely_has);
                    return wasi_types.FileStat{
                        .dev = dev,
                        .ino = wasi_types.INode.init(
                            inode_hash_seed,
                            @bitCast(stat_lx_info.FileId.IndexNumber),
                        ),
                        // Possible that this handles other files types when in WSL. If this
                        // code is in a WSL file system, that the call to query `STAT_LX` is
                        // likely to be supported anyway.
                        .type = switch (stat_lx_info.LxMode.fmt) {
                            .dir => wasi_types.FileType.directory,
                            .chr => .character_device,
                            .reg => .regular_file,
                            .fifo, _ => .unknown,
                        },
                        .nlink = stat_lx_info.NumberOfLinks,
                        .size = wasi_types.FileSize{ .bytes = @bitCast(stat_lx_info.EndOfFile) },
                        // See code querying `FILE_ALL_INFORMATION` below for why these times are
                        // used.
                        .atim = wasi_types.Timestamp.fromWindowsSystemTimeRelative(
                            stat_lx_info.LastAccessTime,
                        ),
                        .mtim = wasi_types.Timestamp.fromWindowsSystemTimeRelative(
                            stat_lx_info.LastWriteTime,
                        ),
                        .ctim = wasi_types.Timestamp.fromWindowsSystemTimeRelative(
                            stat_lx_info.ChangeTime,
                        ),
                    };
                },
                .INVALID_INFO_CLASS, .NOT_SUPPORTED => {
                    std.log.debug("fallback to querying FILE_ALL_INFORMATION: {t}", .{status});
                    stat_lx_support.flag.store(false, .monotonic);
                },
                .INVALID_PARAMETER => unreachable,
                .ACCESS_DENIED => return error.AccessDenied,
                .INVALID_DEVICE_REQUEST => unreachable,
                else => return std.os.windows.unexpectedStatus(status),
            }
        }

        const all_info = info: {
            var io: std.os.windows.IO_STATUS_BLOCK = undefined;
            var info: std.os.windows.FILE_ALL_INFORMATION = undefined;
            const status = windows.ntQueryInformationFile(fd, &io, .FileAllInformation, &info);
            switch (status) {
                .SUCCESS, .BUFFER_OVERFLOW => break :info info,
                .INFO_LENGTH_MISMATCH => unreachable,
                .ACCESS_DENIED => return error.AccessDenied,
                .INVALID_DEVICE_REQUEST => unreachable,
                else => return std.os.windows.unexpectedStatus(status),
            }
        };

        return wasi_types.FileStat{
            .dev = dev,
            .ino = wasi_types.INode.init(
                inode_hash_seed,
                @bitCast(all_info.InternalInformation.IndexNumber),
            ),
            .type = if (all_info.StandardInformation.Directory != 0)
                .directory
            else
                .regular_file,
            .nlink = all_info.StandardInformation.NumberOfLinks,
            .size = wasi_types.FileSize{
                .bytes = @bitCast(all_info.StandardInformation.AllocationSize),
            },
            // WASI doesn't seem to specify the meaning of the timestamps here.
            // The Windows times are relative to system time, in 100-ns intervals.
            .atim = wasi_types.Timestamp.fromWindowsSystemTimeRelative(
                all_info.BasicInformation.LastAccessTime,
            ),
            .mtim = wasi_types.Timestamp.fromWindowsSystemTimeRelative(
                all_info.BasicInformation.LastWriteTime,
            ),
            .ctim = wasi_types.Timestamp.fromWindowsSystemTimeRelative(
                all_info.BasicInformation.ChangeTime,
            ),
        };
    } else if (@hasDecl(std.posix.system, "Stat") and std.posix.Stat != void) {
        const stat = try std.posix.fstat(fd);
        return wasi_types.FileStat.fromPosixStat(&stat, device_hash_seed, inode_hash_seed);
    } else {
        @compileError("no fileStat implementation for " ++ @tagName(builtin.os.tag));
    }
}

const std = @import("std");
const builtin = @import("builtin");
const wasi_types = @import("types.zig");

test {
    if (builtin.os.tag == .windows) {
        _ = windows;
    }
}
