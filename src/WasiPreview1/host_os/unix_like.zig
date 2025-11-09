//! Low-level wrappers over UNIX-like OS APIs.
//!
//! Linux man pages: https://man7.org/linux/man-pages/dir_section_2.html
//! POSIX specification: https://pubs.opengroup.org/onlinepubs/9799919799/
//! FreeBSD manual pages: https://man.freebsd.org/cgi/man.cgi

/// https://man7.org/linux/man-pages/man2/F_GETFL.2const.html
pub fn fcntlGetFl(fd: Fd) WasiError!std.posix.O {
    return @bitCast(@as(
        @typeInfo(std.posix.O).@"struct".backing_integer.?,
        @intCast(
            std.posix.fcntl(
                fd,
                std.posix.F.GETFL,
                undefined,
            ) catch |e| return switch (e) {
                error.Locked => error.WouldBlock,
                else => |err| err,
            },
        ),
    ));
}

pub const lfs64_abi = builtin.os.tag == .linux and std.os.linux.wrapped.lfs64_abi;

// Duplicated code from `std.posix.pwritev` (MIT License).
pub const pwritev = if (lfs64_abi) std.c.pwritev64 else system.pwritev;

// Could also add check for 32-bit linux to use `llseek` instead
pub const lseek = if (lfs64_abi) std.c.lseek64 else system.lseek;

pub const openat = if (lfs64_abi) std.c.openat64 else system.openat;

const std = @import("std");
const system = std.posix.system;
const builtin = @import("builtin");
const Fd = std.posix.fd_t;
const host_os = @import("../host_os.zig");
const WasiError = host_os.WasiError;
const wasi_types = @import("../types.zig");
