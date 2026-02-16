//! Low-level wrappers over UNIX-like OS APIs.
//!
//! Linux man pages: https://man7.org/linux/man-pages/dir_section_2.html
//! POSIX specification: https://pubs.opengroup.org/onlinepubs/9799919799/
//! FreeBSD manual pages: https://man.freebsd.org/cgi/man.cgi

/// https://man7.org/linux/man-pages/man2/writev.2.html
pub const pwritev = if (lfs64_abi) std.c.pwritev64 else system.pwritev;

/// https://man7.org/linux/man-pages/man2/lseek.2.html
pub const lseek = if (lfs64_abi) std.c.lseek64 else system.lseek;

/// https://man7.org/linux/man-pages/man2/openat2.2.html
pub const openat = if (lfs64_abi) std.c.openat64 else system.openat;

/// https://man7.org/linux/man-pages/man2/lstat.2.html
pub const fstat = if (builtin.os.tag == .linux)
    @compileError("support for fstat on Linux was dropped after Zig 0.16.0")
else
    system.fstat;

const std = @import("std");
const system = std.posix.system;
const lfs64_abi = std.posix.lfs64_abi;
const builtin = @import("builtin");
const Fd = std.posix.fd_t;
