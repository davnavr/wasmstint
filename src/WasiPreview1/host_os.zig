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
        // Kernel32 equivalent is `GetFileInformationByHandle`

        // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_stat_lx_information
        // Want to use `FILE_STAT_LX_INFORMATION`, but it is pretty new
        // - No `std.os.windows.FILE_STAT_LX_INFORMATION` in Zig standard library
        // - Introduced as part of WSL
        // - Available since Windows 10 update 1803
        // TODO: Include check and fallback path for builtin version `.win10_rs4` (does invalid class mean INVALID_PARAMETER or INVALID_INFO_CLASS?)

        const file_all_info = info: {
            var io: std.os.windows.IO_STATUS_BLOCK = undefined;
            var info: std.os.windows.FILE_ALL_INFORMATION = undefined;
            const status = std.os.windows.ntdll.NtQueryInformationFile(
                fd,
                &io,
                &info,
                @sizeOf(@TypeOf(info)),
                .FileAllInformation,
            );
            switch (status) {
                .SUCCESS, .BUFFER_OVERFLOW => break :info info,
                .INFO_LENGTH_MISMATCH => unreachable,
                .ACCESS_DENIED => return error.AccessDenied,
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
                else => return std.os.windows.unexpectedStatus(status),
            }
        };

        return wasi_types.FileStat{
            .dev = wasi_types.Device.init(device_hash_seed, fs_volume_info.VolumeSerialNumber),
            .ino = wasi_types.INode.init(
                inode_hash_seed,
                @bitCast(file_all_info.InternalInformation.IndexNumber),
            ),
            .type = if (file_all_info.StandardInformation.Directory != 0)
                .directory
            else
                .regular_file,
            .nlink = file_all_info.StandardInformation.NumberOfLinks,
            .size = wasi_types.FileSize{
                .bytes = @bitCast(file_all_info.StandardInformation.AllocationSize),
            },
            // WASI doesn't seem to specify the meaning of the timestamps here.
            // The Windows times are relative to system time, in 100-ns intervals.
            .atim = wasi_types.Timestamp.fromWindowsSystemTimeRelative(
                file_all_info.BasicInformation.LastAccessTime,
            ),
            .mtim = wasi_types.Timestamp.fromWindowsSystemTimeRelative(
                file_all_info.BasicInformation.LastWriteTime,
            ),
            .ctim = wasi_types.Timestamp.fromWindowsSystemTimeRelative(
                file_all_info.BasicInformation.ChangeTime,
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
