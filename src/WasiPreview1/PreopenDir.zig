dir: std.fs.Dir,
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
    dir: std.fs.Dir,
    sub_path: [:0]const u8,
    permissions: Permissions,
    guest_path: Path,
) std.fs.Dir.OpenError!PreopenDir {
    if (guest_path.len == 0) {
        return error.BadPathName;
    }

    const open_options = std.fs.Dir.OpenOptions{
        .access_sub_paths = true, // always needed to e.g. access files in the directory
        .iterate = true, // guest may choose to ask for entries at any time
    };

    const opened_dir = switch (builtin.os.tag) {
        .windows, .wasi => try dir.openDir(sub_path, open_options),
        else => try dir.openDirZ(sub_path, open_options),
    };

    std.log.debug(
        "preopen host {any} @ {f} at guest path {f} -> host {any}",
        .{ dir.fd, std.unicode.fmtUtf8(sub_path), guest_path, opened_dir.fd },
    );

    errdefer comptime unreachable;

    return .{
        .dir = opened_dir,
        .permissions = permissions,
        .guest_path = guest_path,
    };
}

const std = @import("std");
const builtin = @import("builtin");
const Path = @import("Path.zig");
