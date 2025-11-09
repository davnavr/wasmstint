//! Abstractions over OS APIs used for implementing the WASI preview 1 API.

// Platform specific modules.
pub const windows = @import("host_os/windows.zig");
pub const unix_like = @import("host_os/unix_like.zig");
pub const linux = @import("host_os/linux.zig");

pub const path = @import("host_os/path.zig");
pub const Path = path.Slice;
pub const Dir = @import("host_os/Dir.zig");

pub const Handle = std.posix.fd_t;
pub const WasiError = @import("errno.zig").Error;

pub const is_windows = builtin.os.tag == .windows;

pub const InterruptedError = error{
    /// Corresponds to `std.posix.E.INTR`.
    Interrupted,
};

/// Used to implement [`fd_filestat_get()`].
///
/// [`fd_filestat_get()`]: https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#fd_filestat_get
pub fn fileStat(
    fd: Handle,
    device_hash_seed: wasi_types.Device.HashSeed,
    inode_hash_seed: wasi_types.INode.HashSeed,
) WasiError!wasi_types.FileStat {
    if (is_windows) {
        // Kernel32 equivalent is `GetFileInformationByHandleEx`

        const all_info = info: {
            var io: std.os.windows.IO_STATUS_BLOCK = undefined;
            var info: std.os.windows.FILE_ALL_INFORMATION = undefined;
            const status = windows.ntQueryInformationFile(fd, &io, .FileAllInformation, &info);
            switch (status) {
                .SUCCESS, .BUFFER_OVERFLOW => break :info info,
                .INFO_LENGTH_MISMATCH => unreachable,
                .ACCESS_DENIED => return error.AccessDenied,
                .INVALID_INFO_CLASS => unreachable,
                .NOT_SUPPORTED => unreachable,
                inline .INVALID_DEVICE_REQUEST => |bad| {
                    std.log.debug("could not obtain volume information: " ++ @tagName(bad), .{});
                    return windows.fileStatNonDisk(fd, device_hash_seed, inode_hash_seed);
                },
                else => return std.os.windows.unexpectedStatus(status),
            }
        };

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

        return wasi_types.FileStat{
            .dev = wasi_types.Device.init(device_hash_seed, fs_volume_info.VolumeSerialNumber),
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
        const stat = std.posix.fstat(fd) catch |e| switch (e) {
            error.Canceled, error.Streaming => unreachable,
            else => |err| return err,
        };

        return wasi_types.FileStat.fromPosixStat(&stat, device_hash_seed, inode_hash_seed);
    } else {
        @compileError("no fileStat implementation for " ++ @tagName(builtin.os.tag));
    }
}

const std = @import("std");
const builtin = @import("builtin");
const wasi_types = @import("types.zig");

test {
    if (is_windows) {
        _ = windows;
    }

    if (builtin.os.tag == .linux) {
        _ = linux;
    }
}
