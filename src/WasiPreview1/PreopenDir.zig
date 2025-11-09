//! A pre-opened directory, which grant a WASI program the ability to perform operations within
//! an existing host directory.

dir: host_os.Dir,
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

pub fn openAt(
    dir: host_os.Dir,
    /// Host path to the directory to open.
    sub_path: host_os.Path,
    /// Specifies the operations the guest can perform within the directory.
    permissions: Permissions,
    /// Cannot be empty.
    guest_path: Path,
) host_os.Dir.OpenError!PreopenDir {
    if (guest_path.len == 0) {
        return error.BadPathName; // empty path
    }

    const opened_dir = try dir.openDir(sub_path, host_os.Dir.OpenOptions{
        .access_sub_paths = true, // always needed to e.g. access files in the directory
        .iterate = true, // guest may choose to ask for entries at any time
    });

    errdefer comptime unreachable;

    std.log.debug(
        "preopen host {any} @ {f} at guest path {f} -> host {any}",
        .{ dir, std.unicode.fmtUtf8(sub_path), guest_path, opened_dir.handle },
    );

    return PreopenDir{
        .dir = opened_dir,
        .permissions = permissions,
        .guest_path = guest_path,
    };
}

const std = @import("std");
const builtin = @import("builtin");
const host_os = @import("host_os.zig");
const Path = @import("Path.zig");
