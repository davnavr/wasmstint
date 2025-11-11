//! An OS handle referring to an open directory.
//!
//! Provides wrappers over synchronous OS APIs for operations on directories.

handle: Handle,

const Dir = @This();

pub const OpenError = error{
    AccessDenied,
    AntivirusInterference,
    DeviceBusy,
    FileNotFound,
    NetworkNotFound,
    NoDevice,
    NotDir,
    PermissionDenied,
    ProcessFdQuotaExceeded,
    SymLinkLoop,
    SystemFdQuotaExceeded,
    SystemResources,
} || std.Io.Dir.PathNameError || std.posix.UnexpectedError || host_os.InterruptedError;

pub const OpenOptions = struct {
    access_sub_paths: bool = true,
    iterate: bool = true,
    follow_symlinks: bool = true,
    interrupt_retry_count: u7 = 5,
};

/// Equivalent of `std.Io.Dir.openDir`.
pub fn openDir(dir: Dir, path: Path, options: OpenOptions) OpenError!Dir {
    const attempt_count = @as(u8, options.interrupt_retry_count) + 1;
    if (host_os.is_windows) {
        if (host_os.windows.has_obj_dont_reparse != true) {
            @compileError(std.fmt.comptimePrint(
                "OBJ_DONT_REPARSE to handle !follow_symlinks requires windows version {t}, got {t}",
                .{
                    @tagName(host_os.windows.obj_dont_reparse_min_version),
                    @tagName(builtin.os.version_range.windows.min),
                },
            ));
        }

        const base_access_flags = host_os.windows.AccessMask.init(&.{
            .STANDARD_RIGHTS_READ,
            .FILE_READ_ATTRIBUTES,
            .FILE_READ_EA,
            .SYNCHRONIZE,
        });
        const access_flags = base_access_flags
            .setFlagConditional(options.access_sub_paths, .FILE_TRAVERSE)
            .setFlagConditional(options.iterate, .FILE_LIST_DIRECTORY);

        var opened: host_os.Handle = undefined;
        var io: std.os.windows.IO_STATUS_BLOCK = undefined;
        var object_name = host_os.windows.initUnicodeString(@constCast(path));
        var attrs = std.os.windows.OBJECT_ATTRIBUTES{
            .Length = @sizeOf(std.os.windows.OBJECT_ATTRIBUTES),
            //.RootDirectory = if (std.fs.path.isAbsoluteWindowsWtf16(path)) null else dir.handle,
            .RootDirectory = dir.handle,
            // TODO: Try std.os.windows.removeDotDirsSanitized and look into proper converion of
            // Win32 paths to NT paths
            .ObjectName = &object_name,
            .Attributes = if (options.follow_symlinks) 0 else host_os.windows.OBJ_DONT_REPARSE,
            .SecurityDescriptor = null,
            .SecurityQualityOfService = null,
        };

        for (0..attempt_count) |_| {
            const status = host_os.windows.NtCreateFile(
                &opened,
                access_flags,
                &attrs,
                &io,
                null,
                host_os.windows.FileAttributes.init(&.{.FILE_ATTRIBUTE_NORMAL}),
                host_os.windows.share_access_default,
                host_os.windows.CreateDisposition.FILE_OPEN,
                host_os.windows.CreateOptions.init(&.{
                    .FILE_DIRECTORY_FILE,
                    .FILE_SYNCHRONOUS_IO_NONALERT,
                    .FILE_OPEN_FOR_BACKUP_INTENT,
                }),
                null,
                0,
            );

            return switch (status) {
                .SUCCESS => Dir{ .handle = opened },
                .ACCESS_DENIED => error.AccessDenied,
                host_os.windows.STATUS_REPARSE_POINT_ENCOUNTERED => if (options.follow_symlinks)
                    unreachable
                else
                    error.SymLinkLoop,
                .OBJECT_NAME_INVALID => error.BadPathName,
                .OBJECT_NAME_NOT_FOUND, .OBJECT_PATH_NOT_FOUND => error.FileNotFound,
                .BAD_NETWORK_PATH, .BAD_NETWORK_NAME => error.NetworkNotFound,
                .DELETE_PENDING => {
                    @branchHint(.cold);
                    _ = std.os.windows.kernel32.SleepEx(
                        42, // arbitrary amount
                        std.os.windows.TRUE,
                    );
                    continue;
                },
                .VIRUS_INFECTED, .VIRUS_DELETED => error.AntivirusInterference,
                else => std.os.windows.unexpectedStatus(status),
            };
        }

        return error.Interrupted;
    } else {
        var flags = std.posix.O{
            .ACCMODE = .RDONLY,
            .NOFOLLOW = !options.follow_symlinks,
            .DIRECTORY = true,
            .CLOEXEC = true,
        };

        if (@hasField(std.posix.O, "PATH") and !options.iterate) {
            flags.PATH = true;
        }

        for (0..attempt_count) |_| {
            const result = host_os.unix_like.openat(
                dir.handle,
                path,
                flags,
                @as(std.posix.mode_t, 0),
            );
            return switch (std.posix.errno(result)) {
                .SUCCESS => return Dir{ .handle = @intCast(result) },
                .INTR => {
                    @branchHint(.unlikely);
                    continue;
                },
                .INVAL => error.BadPathName,
                .ACCES => error.AccessDenied,
                .LOOP => error.SymLinkLoop,
                .MFILE => error.ProcessFdQuotaExceeded,
                .NAMETOOLONG => error.NameTooLong,
                .NFILE => error.SystemFdQuotaExceeded,
                .NODEV => error.NoDevice,
                .NOENT => error.FileNotFound,
                .NOMEM => error.SystemResources,
                .NOTDIR => error.NotDir,
                .PERM => error.PermissionDenied,
                .BUSY => error.DeviceBusy,
                .NXIO => error.NoDevice,
                .ILSEQ => error.BadPathName,
                else => |err| std.posix.unexpectedErrno(err),
            };
        }

        return error.Interrupted;
    }
}

const has_dirent = @hasDecl(std.posix.system, "dirent") and std.posix.system.dirent != void;

/// Does not include *any* null-terminators, if they are usually used in host OS APIs.
pub const max_name_bytes = if (host_os.is_windows)
    std.os.windows.NAME_MAX * 2
else
    std.posix.system.NAME_MAX;

const LinuxEntry = std.os.linux.dirent64;

const WindowsEntry = host_os.windows.FILE_ID_FULL_DIR_INFORMATION;

pub const Entry = switch (builtin.os.tag) {
    .linux => LinuxEntry,
    .windows => WindowsEntry,
    else => |bad| @compileError("no dirent for " ++ @tagName(bad) ++ ", try linking libc"),
};

pub const entry_align = if (host_os.is_windows) 2 else 1;

pub const entry = struct {
    pub const NameLen = std.math.IntFittingRange(0, max_name_bytes);

    pub fn nameBytesLen(ent: *align(entry_align) const Entry) NameLen {
        return @intCast(switch (builtin.os.tag) {
            .linux => len: {
                const max = ent.reclen - @offsetOf(Entry, "name") - 1;
                const actual = std.mem.len(@as([*:0]const u8, @ptrCast(&ent.name)));
                std.debug.assert(actual <= max);
                break :len actual;
            },
            .windows => ent.FileNameLength,
            else => |bad| @compileError("name len of entry for " ++ @tagName(bad)),
        });
    }

    pub fn name(ent: *align(entry_align) const Entry) host_os.Path {
        return switch (builtin.os.tag) {
            .linux => @as([*]const u8, @ptrCast(&ent.name))[0..nameBytesLen(ent) :0],
            .windows => @as(
                [*]const std.os.windows.WCHAR,
                @ptrCast(&ent.FileName),
            )[0..@divExact(nameBytesLen(ent), 2)],
            else => |bad| @compileError("name of entry for " ++ @tagName(bad)),
        };
    }

    pub const Type = switch (builtin.os.tag) {
        .linux => host_os.linux.DT,
        else => |bad| @compileError("directory entry type for " ++ @tagName(bad)),
    };

    pub fn typeOf(ent: *align(entry_align) const Entry) Type {
        switch (builtin.os.tag) {
            .linux => return @enumFromInt(ent.type),
            else => |bad| @compileError("directory entry type for " ++ @tagName(bad)),
        }
    }
};

/// It is illegal behavior to have more than one `Iterator` active for a given `Dir`.
///
/// Asserts that `Iterator.min_buffer_size <= buffer.len`.
pub fn iterate(dir: Dir, buffer: []align(Iterator.buffer_align) u8) Iterator {
    std.debug.assert(Iterator.min_buffer_size <= buffer.len);
    return Iterator{
        .dir = dir,
        .needs_reset = false,
        .buffer = buffer,
        .remaining = buffer[0..1],
    };
}

/// Thin wrapper over OS directory iteration APIs, similar to `std.fs.Dir.Iterator`
pub const Iterator = struct {
    pub const min_buffer_size = @sizeOf(Entry) + max_name_bytes;

    pub const buffer_align = @max(entry_align, @alignOf(Entry));

    dir: Dir,
    needs_reset: bool,
    buffer: []align(buffer_align) u8,
    remaining: []align(entry_align) const u8,

    fn current(iter: *const Iterator) ?*align(entry_align) const Entry {
        if (iter.remaining.len <= @sizeOf(Entry)) {
            return null;
        }

        switch (builtin.os.tag) {
            .linux => {
                const peeked_entry: *align(1) const LinuxEntry = @ptrCast(iter.remaining);
                std.debug.assert(@sizeOf(LinuxEntry) <= peeked_entry.reclen);
                return if (iter.remaining.len < peeked_entry.reclen) null else peeked_entry;
            },
            .windows => {
                const peeked_entry: *align(2) const WindowsEntry = @ptrCast(iter.remaining);
                return if (iter.remaining.len - @sizeOf(WindowsEntry) < peeked_entry.FileNameLength)
                    null
                else
                    peeked_entry;
            },
            else => |bad| @compileError("peek current dir entry for " ++ @tagName(bad)),
        }
    }

    pub const Error = std.posix.UnexpectedError || error{
        AccessDenied,
    };

    fn peekWindows(iter: *Iterator) Error!?*align(2) const Entry {
        if (!iter.needs_reset) {
            if (iter.current()) |peeked_entry| {
                return peeked_entry;
            }
        }

        @memset(iter.buffer, undefined);
        iter.remaining = iter.buffer[0..0];

        var io: std.os.windows.IO_STATUS_BLOCK = undefined;
        const status = host_os.windows.queryDirectoryFile(
            iter.dir.handle,
            &io,
            iter.buffer,
            .FileIdFullDirectoryInformation,
            if (iter.needs_reset) .restart else .@"resume",
        );
        return switch (status) {
            .NO_MORE_FILES => null, // does this case every actually run?
            .INVALID_INFO_CLASS => @panic("FileIdFullDirectoryInformation not supported"),
            .SUCCESS => {
                iter.needs_reset = false;
                iter.remaining = iter.buffer[0..io.Information];
                return if (io.Information > 0) @ptrCast(@alignCast(iter.remaining)) else null;
            },
            .BUFFER_OVERFLOW,
            .BUFFER_TOO_SMALL,
            => unreachable, // min buffer size prevents this
            .ACCESS_DENIED => error.AccessDenied,
            else => std.os.windows.unexpectedStatus(status),
        };
    }

    fn peekPosix(iter: *Iterator) Error!?*align(1) const Entry {
        if (iter.needs_reset) {
            @branchHint(.unlikely);
            std.posix.lseek_SET(iter.dir.handle, 0) catch |e| switch (e) {
                error.AccessDenied => unreachable, // directory should allow iteration
                error.Unexpected => |err| return err,
                error.Canceled => unreachable,
                error.Unseekable => unreachable,
            };
            iter.needs_reset = false;
        }

        if (iter.current()) |peeked_entry| {
            return peeked_entry;
        }

        iter.remaining = iter.buffer[0..0];
        @memset(iter.buffer, 0);

        if (builtin.os.tag == .linux) {
            const result = std.os.linux.getdents64(
                iter.dir.handle,
                iter.buffer.ptr,
                iter.buffer.len,
            );

            return switch (std.os.linux.E.init(result)) {
                .SUCCESS => if (result == 0) null else {
                    iter.remaining = iter.buffer[0..result];
                    const peeked_entry: *align(1) const LinuxEntry = @ptrCast(iter.remaining);
                    return peeked_entry;
                },
                .BADF => unreachable,
                .FAULT => unreachable,
                .NOTDIR => unreachable,
                .NOENT => null, // directory deleted during iteration
                .ACCES => error.AccessDenied,
                else => |err| std.posix.unexpectedErrno(err),
            };
        } else {
            @panic("use posix.system.getdirentries or posix.system.getdents");
        }
    }

    /// May deinitialize any previous `Entry`s that were returned by `.next()`.
    pub fn peek(iter: *Iterator) Error!?*align(entry_align) const Entry {
        if (host_os.is_windows) {
            return iter.peekWindows();
        } else {
            return iter.peekPosix();
        }
    }

    /// Advances the `Iterator` past the previous `.peek()`ed entry.
    ///
    /// Deinitializes the `Entry` that was returned by the previous call to `.peek()`.
    pub fn advance(iter: *Iterator) void {
        const ent = iter.current().?;
        const size = switch (builtin.os.tag) {
            .linux => ent.reclen,
            .windows => if (ent.NextEntryOffset == 0) iter.remaining.len else ent.NextEntryOffset,
            else => |bad| @compileError("directory entry reclen for " ++ @tagName(bad)),
        };

        iter.remaining = @alignCast(iter.remaining[size..]);
    }

    pub fn next(iter: *Iterator) Error!?*align(entry_align) const Entry {
        const ent = (try iter.peek()) orelse return null;
        iter.advance();
        return ent;
    }

    pub fn reset(iter: *Iterator) void {
        iter.needs_reset = true;
        iter.remaining = iter.buffer[0..1];
    }
};

pub fn close(dir: Dir) void {
    std.posix.close(dir.handle);
}

const std = @import("std");
const builtin = @import("builtin");
const host_os = @import("../host_os.zig");
const Path = host_os.Path;
const Handle = host_os.Handle;
