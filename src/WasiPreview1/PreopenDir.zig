dir: std.fs.Dir,
permissions: Permissions,
guest_path: Path,

const PreopenDir = @This();

pub const Permissions = packed struct(u2) {
    mode: Mode,
    subdirectories: Subdirectories,
    // maybe a bit to indicate if allow-list of files should be used?

    pub const default = Permissions{
        .mode = .read_only,
        .subdirectories = .none,
    };

    pub const Mode = enum(u1) {
        read_only,
        read_write,
        // most OS's don't support write_only
    };

    pub const Subdirectories = enum(u1) {
        /// All subdirectories are accessible with the same permissions as the opened directory.
        available,
        /// Only the files in the directory are available, not its subdirectories.
        none,
    };
};

pub fn openAtZ(
    dir: std.fs.Dir,
    sub_path: [:0]const u8,
    permissions: Permissions,
    guest_path: Path,
) std.fs.Dir.OpenError!PreopenDir {
    const open_options = std.fs.Dir.OpenOptions{
        .access_sub_paths = true, // always needed to e.g. access files in the directory
        .iterate = true, // guest may choose to ask for entries at any time
        .no_follow = true, // we have to check realpaths ourselves
    };
    return .{
        .dir = switch (builtin.os.tag) {
            .windows, .wasi => try dir.openDir(sub_path, open_options),
            else => try dir.openDirZ(sub_path, open_options),
        },
        .permissions = permissions,
        .guest_path = guest_path,
    };
}

const std = @import("std");
const builtin = @import("builtin");
const Path = @import("Path.zig");
