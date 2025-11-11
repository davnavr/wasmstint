//! Provides low-level wrappers over synchronous OS APIs.
//!
//! Named `sys` to avoid confusion with `std.os`.

// Platform specific modules.
pub const windows = @import("sys/windows.zig");
pub const unix_like = @import("sys/unix_like.zig");
pub const linux = @import("sys/linux.zig");

pub const Handle = std.posix.fd_t;

pub const is_windows = builtin.os.tag == .windows;

pub const path = @import("sys/path.zig");
pub const Path = path.Slice;
pub const PathZ = path.SliceZ;
pub const Dir = @import("sys/Dir.zig");

pub const InterruptedError = error{
    /// Corresponds to `std.posix.E.INTR`.
    Interrupted,
};

const std = @import("std");
const builtin = @import("builtin");

test {
    if (is_windows) {
        _ = windows;
    }

    if (builtin.os.tag == .linux) {
        _ = linux;
    }
}
