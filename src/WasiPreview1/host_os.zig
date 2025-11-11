//! Abstractions over OS APIs used for implementing the WASI preview 1 API.

pub const WasiError = @import("errno.zig").Error;

/// Used to implement [`fd_filestat_get()`].
///
/// [`fd_filestat_get()`]: https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#fd_filestat_get
pub fn fileStat(
    fd: sys.Handle,
    device_hash_seed: wasi_types.Device.HashSeed,
    inode_hash_seed: wasi_types.INode.HashSeed,
) WasiError!wasi_types.FileStat {
    if (sys.is_windows) {
        // Kernel32 equivalent is `GetFileInformationByHandleEx`

        const all_info = info: {
            var io: std.os.windows.IO_STATUS_BLOCK = undefined;
            var info: std.os.windows.FILE_ALL_INFORMATION = undefined;
            const status = sys.windows.ntQueryInformationFile(fd, &io, .FileAllInformation, &info);
            switch (status) {
                .SUCCESS, .BUFFER_OVERFLOW => break :info info,
                .INFO_LENGTH_MISMATCH => unreachable,
                .ACCESS_DENIED => return error.AccessDenied,
                .INVALID_INFO_CLASS => unreachable,
                .NOT_SUPPORTED => unreachable,
                inline .INVALID_DEVICE_REQUEST => |bad| {
                    std.log.debug("could not obtain volume information: " ++ @tagName(bad), .{});
                    return fileStatWindowsNonDisk(fd, device_hash_seed, inode_hash_seed);
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
                    return fileStatWindowsNonDisk(fd, device_hash_seed, inode_hash_seed);
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

/// Implements `fd_filestat_get()` for `HANDLE`s not referring to a file or directory on disk.
///
/// Asserts that `GetFileType(handle)` does not return `FileType.disk`.
pub fn fileStatWindowsNonDisk(
    handle: sys.Handle,
    device_hash_seed: wasi_types.Device.HashSeed,
    inode_hash_seed: wasi_types.INode.HashSeed,
) WasiError!wasi_types.FileStat {
    // `VolumeSerialNumber` of real files are 32-bit, leaving high 32-bits
    // for our use.
    const fake_device = struct {
        pub const real_console = 0xC0C0_4EA1_0000_0000;
        pub const msys_console: u64 = 0xC0C0_3575_2000_0000;
        pub const cygwin_console: u64 = 0xC0C0_C793_3140_0000;
    };

    // Since non-file handles have no `IndexNumber`, and handles are meaningless
    // when a process dies anyway, this makes up an `inode` based on the handle
    // value. Unfortunately, Windows doesn't provide a way to get a unique ID
    // for different handles that refer to the same "thing".
    const ino_from_handle = wasi_types.INode.init(inode_hash_seed, @intFromPtr(handle));

    const file_type = sys.windows.GetFileType(handle);
    switch (file_type) {
        .disk => unreachable,
        .char => return wasi_types.FileStat{
            .dev = wasi_types.Device.init(
                device_hash_seed,
                fake_device.real_console,
            ),
            .ino = ino_from_handle,
            .type = wasi_types.FileType.character_device,
            .nlink = 1, // can't make hardlinks
            // standard stream sizes seem to always be zero on Linux
            .size = wasi_types.FileSize{ .bytes = 0 },

            // On Linux, atim and mtim seem to be the current time/last time a
            // print (idk about reads) occurred, while ctim was when the stream was
            // created.
            //
            // Windows doesn't track times for console handles, because they aren't
            // files. Possible workarounds:
            // - For `ctim`, could cheat and use the time WASI state was
            //   initialized as the creation time
            // - Could make a new `File` implementation (`console_file.zig`, would
            //   also use `Read/WriteConsole`) that updates times on every
            //   read/write, but that is annoying
            // - Could cheat and supply current time every time `fd_filestat_get` is
            //   called
            //
            // Since there are other ways for a guest to detect a Windows host
            // anyways, this just gives up and puts zeroes.
            .atim = wasi_types.Timestamp.zero,
            .mtim = wasi_types.Timestamp.zero,
            .ctim = wasi_types.Timestamp.zero,
        },
        .pipe => pipe: {
            const pipe_pty = sys.windows.isMsysOrCygwinPty(handle);
            if (pipe_pty.tag == .not_a_pty) {
                break :pipe;
            }

            const INodeBits = packed struct(u64) {
                type: sys.windows.NamedPipePty.Type,
                number: u7,
                low_installation_bits: u54,
            };

            return wasi_types.FileStat{
                .dev = wasi_types.Device.init(
                    device_hash_seed,
                    switch (pipe_pty.tag) {
                        .not_a_pty => unreachable,
                        .msys => fake_device.msys_console,
                        .cygwin => fake_device.cygwin_console,
                    } | std.math.shr(u64, pipe_pty.id.installation_key, 54),
                ),
                .ino = wasi_types.INode.init(
                    inode_hash_seed,
                    @as(
                        u64,
                        @bitCast(INodeBits{
                            .type = pipe_pty.id.type,
                            .number = pipe_pty.id.number,
                            .low_installation_bits = @truncate(pipe_pty.id.installation_key),
                        }),
                    ),
                ),
                .type = wasi_types.FileType.character_device,
                // Windows allows fetching the # of pipe instances
                .nlink = 1,
                // Windows allows peeking size of data in pipe
                .size = wasi_types.FileSize{ .bytes = 0 },
                // See `.char` handler for why these are zero
                .atim = wasi_types.Timestamp.zero,
                .mtim = wasi_types.Timestamp.zero,
                .ctim = wasi_types.Timestamp.zero,
            };
        },
        .unknown => switch (std.os.windows.GetLastError()) {
            .SUCCESS => {},
            else => |bad| return std.os.windows.unexpectedError(bad),
        },
        .remote, _ => {},
    }

    std.log.err(
        "fd_filestat_get on unknown windows file type {s} {X}",
        .{ std.enums.tagName(sys.windows.FileType, file_type) orelse "invalid", file_type },
    );
    return error.AccessDenied;
}

const std = @import("std");
const builtin = @import("builtin");
const sys = @import("sys");
const wasi_types = @import("types.zig");
