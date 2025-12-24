//! A pre-opened directory, which grant a WASI program the ability to perform operations within
//! an existing host directory.

dir: sys.Dir,
permissions: Permissions,
guest_path: Path,

const PreopenDir = @This();

pub const Permissions = packed struct(u1) {
    write: bool,
    // maybe a bit to indicate if allow-list of files should be used?

    pub const none = Permissions{
        .write = false,
    };
};

pub fn openAtZ(
    dir: sys.Dir,
    /// Host path to the directory to open.
    sub_path: sys.PathZ,
    /// Specifies the operations the guest can perform within the directory.
    permissions: Permissions,
    /// Cannot be empty.
    guest_path: Path,
) sys.Dir.OpenError!PreopenDir {
    if (guest_path.len == 0) {
        return error.BadPathName; // empty path
    }

    const opened_dir = try dir.openDirZ(sub_path, sys.Dir.OpenOptions{
        .access_sub_paths = true, // always needed to e.g. access files in the directory
        .iterate = true, // guest may choose to ask for entries at any time
    });

    errdefer comptime unreachable;

    std.log.debug(
        "preopen host {any} @ {f} at guest path {f} -> host {any}",
        .{ dir, sys.path.fmt(sub_path), guest_path, opened_dir.handle },
    );

    return PreopenDir{
        .dir = opened_dir,
        .permissions = permissions,
        .guest_path = guest_path,
    };
}

const std = @import("std");
const builtin = @import("builtin");
const sys = @import("sys");
const Path = @import("Path.zig");
