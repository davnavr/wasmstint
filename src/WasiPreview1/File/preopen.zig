//! A pre-opened OS file-descriptor referring to a directory.

const Context = struct {
    dir: std.fs.Dir,
    permissions: PreopenDir.Permissions,
    // Guest `Path` is split to reduce padding
    guest_path_len: Path.Len, // maybe u1 bit in Path.Len to indicate ownership/constness?
    guest_path_ptr: Path.Ptr,

    fn guestPath(ctx: *const Context) Path {
        return .{ .ptr = ctx.guest_path_ptr, .len = ctx.guest_path_len };
    }
};

inline fn context(ctx: Ctx) *Context {
    return @ptrCast(@alignCast(ctx.ptr));
}

pub fn init(preopen: *PreopenDir, allocator: std.mem.Allocator) std.mem.Allocator.Error!File {
    defer preopen.* = undefined;

    const can_write = preopen.permissions.mode == .read_write;
    const can_access_subdirs = preopen.permissions.subdirectories == .available;

    // Right now `main.zig` allocates paths in an `arena`, so no `dupe` call is necessary
    const ctx = try allocator.create(Context);
    errdefer comptime unreachable;
    ctx.* = Context{
        .dir = preopen.dir,
        .permissions = preopen.permissions,
        .guest_path_len = preopen.guest_path.len,
        .guest_path_ptr = preopen.guest_path.ptr,
    };

    return File{
        .rights = File.Rights.Valid{
            // TODO: remove subdirs access, it is too confusing
            .path_create_directory = can_access_subdirs & can_write,
            .path_create_file = can_write,
            .path_link_source = can_write,
            .path_link_target = can_write,
            .path_open = true,
            .fd_readdir = true,
            .path_readlink = true,
            .path_rename_source = can_write,
            .path_rename_target = can_write,
            .path_filestat_get = true,
            .path_symlink = can_write,
            .path_remove_directory = can_write,
            .path_unlink_file = can_write,
        },
        .impl = .{
            .ctx = Ctx{ .ptr = @ptrCast(ctx) },
            .vtable = &vtable,
        },
    };
}

pub fn fd_prestat_get(ctx: Ctx) File.Error!types.Prestat {
    const self = context(ctx);
    return .init(
        types.Prestat.Type.dir,
        types.Prestat.Dir{ .pr_name_len = self.guestPath().len },
    );
}

pub fn fd_prestat_dir_name(ctx: Ctx, path: []u8) File.Error!void {
    const self = context(ctx);
    if (self.guest_path_len < path.len) return File.Error.InvalidArgument;

    @memcpy(path[0..self.guest_path_len], self.guestPath().bytes());
}

pub const vtable = File.VTable{
    .api = .{
        .fd_write = undefined,
        .fd_pwrite = undefined,
        .fd_prestat_get = fd_prestat_get,
        .fd_prestat_dir_name = fd_prestat_dir_name,
    },
    .deinit = deinit,
};

fn deinit(ctx: Ctx, allocator: std.mem.Allocator) void {
    const self = context(ctx);
    self.dir.close();
    // self.guestPath is not deallocated
    allocator.destroy(self);
}

const std = @import("std");
const types = @import("../types.zig");
const PreopenDir = @import("../PreopenDir.zig");
const Path = @import("../Path.zig");
const File = @import("../File.zig");
const Ctx = File.Ctx;
