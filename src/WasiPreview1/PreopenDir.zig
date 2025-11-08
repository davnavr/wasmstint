dir: Io.Dir,
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
    dir: Io.Dir,
    io: Io,
    /// Host path to the directory to open.
    sub_path: []const u8,
    /// Specifies the operations the guest can perform within the directory.
    permissions: Permissions,
    /// Cannot be empty.
    guest_path: Path,
) Io.Dir.OpenError!PreopenDir {
    if (guest_path.len == 0) {
        return error.BadPathName; // empty path
    }

    const open_options = std.fs.Dir.OpenOptions{
        .access_sub_paths = true, // always needed to e.g. access files in the directory
        .iterate = true, // guest may choose to ask for entries at any time
    };

    const opened_dir = try dir.openDir(io, sub_path, open_options);

    errdefer comptime unreachable;

    std.log.debug(
        "preopen host {any} @ {f} at guest path {f} -> host {any}",
        .{ dir.handle, std.unicode.fmtUtf8(sub_path), guest_path, opened_dir.handle },
    );

    return PreopenDir{
        .dir = opened_dir,
        .permissions = permissions,
        .guest_path = guest_path,
    };
}

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const Path = @import("Path.zig");
