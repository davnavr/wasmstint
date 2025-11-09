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
    interrupt_retry_count: u8 = 5,
};

/// Equivalent of `std.Io.Dir.openDir`.
pub fn openDir(dir: Dir, path: Path, options: OpenOptions) OpenError!Dir {
    if (host_os.is_windows) {
        @panic("TODO: see host_dir.zig on usage of OBJ_DONT_REPARSE w/ NtCreateFile");
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

        for (0..(@as(u9, options.interrupt_retry_count) + 1)) |_| {
            const result = host_os.unix_like.openat(
                dir.handle,
                path,
                flags,
                @as(std.posix.mode_t, 0),
            );
            return switch (std.posix.errno(result)) {
                .SUCCESS => return Dir{ .handle = @intCast(result) },
                .INTR => continue,
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

pub const max_name_bytes = if (host_os.is_windows)
    std.os.windows.NAME_MAX * 2
else
    std.posix.system.NAME_MAX;

const LinuxEntry = std.os.linux.dirent64;

pub const Entry = if (builtin.link_libc and has_dirent)
    std.c.dirent
else switch (builtin.os.tag) {
    .linux => LinuxEntry,
    .windows => @compileError("TODO: windows directory entry type"),
    else => |bad| @compileError("no dirent for " ++ @tagName(bad) ++ ", try linking libc"),
};

pub const entry_align = if (host_os.is_windows) 2 else 1;

pub const entry = struct {
    pub const NameLen = std.math.IntFittingRange(0, max_name_bytes);

    pub fn nameBytesLen(ent: *align(entry_align) const Entry) NameLen {
        return switch (builtin.os.tag) {
            .linux => @intCast(ent.reclen - @offsetOf(Entry, "name") - 1),
            else => |bad| @compileError("name len of entry for " ++ @tagName(bad)),
        };
    }

    pub fn name(ent: *align(entry_align) const Entry) host_os.Path {
        return if (host_os.is_windows)
            @compileError("TODO: name on windows")
        else switch (builtin.os.tag) {
            .linux => @as([*]const u8, @ptrCast(&ent.name))[0..nameBytesLen(ent) :0],
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

/// Equivalent of `std.fs.Dir.Iterator`, except that it exposes the underlying OS-specific
/// directory entry structures.
pub const Iterator = struct {
    pub const min_buffer_size = @sizeOf(Entry) + max_name_bytes;

    pub const buffer_align = @max(entry_align, @alignOf(Entry));

    dir: Dir,
    needs_reset: bool,
    buffer: []align(buffer_align) u8,
    remaining: []align(entry_align) const u8,

    fn current(iter: *const Iterator) ?*align(entry_align) const Entry {
        switch (builtin.os.tag) {
            .linux => {
                if (iter.remaining.len <= @sizeOf(LinuxEntry)) {
                    return null;
                }

                const peeked_entry: *align(1) const LinuxEntry = @ptrCast(iter.remaining);
                std.debug.assert(@sizeOf(LinuxEntry) <= peeked_entry.reclen);
                return if (iter.remaining.len < peeked_entry.reclen) null else peeked_entry;
            },
            else => |bad| @compileError("peek current dir entry for " ++ @tagName(bad)),
        }
    }

    pub const Error = std.posix.UnexpectedError || error{
        AccessDenied,
    };

    fn peekWindows(iter: *Iterator) Error!?*align(2) const Entry {
        // if (iter.needs_reset) // Set flag in NtQueryDirectoryFile
        _ = iter;
        @panic("TODO: NtQueryDirectoryFile & FILE_DIRECTORY_INFORMATION + NtQueryDirectoryFileEx FILE_INTERNAL_INFORMATION on file name");
    }

    fn peekPosix(iter: *Iterator) Error!?*align(1) const Entry {
        if (builtin.os.tag == .linux) {
            if (iter.current()) |peeked_entry| {
                return peeked_entry;
            }

            @memset(iter.buffer, 0);
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
            else => |bad| @compileError(
                "determine reclen for entry for implementation on " ++ @tagName(bad),
            ),
        };
        iter.remaining = iter.remaining[size..];
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
