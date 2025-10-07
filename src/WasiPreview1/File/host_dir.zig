//! Wraps a host OS file descriptor referring to a directory.

const HostDir = struct {
    dir: std.fs.Dir,
    info: *Info,

    const Info = struct {
        permissions: PreopenDir.Permissions,
        // Guest `Path` is split to reduce padding
        guest_path_len: Path.Len, // maybe u1 bit in Path.Len to indicate ownership/constness?
        guest_path_ptr: Path.Ptr,
        read_next_cookie: types.DirCookie, // TODO: Hash cookies? Could use `std.hash.int`
        read_state: ReadState,
    };

    fn guestPath(ctx: *const HostDir) Path {
        return .{ .ptr = ctx.info.guest_path_ptr, .len = ctx.info.guest_path_len };
    }
};

/// Ownership of the file descriptor is transferred to the `File`.
pub fn initPreopened(preopen: *PreopenDir, allocator: Allocator) Allocator.Error!File {
    defer preopen.* = undefined;

    const perm = preopen.permissions;

    // Right now `main.zig` allocates paths in an `arena`, so no `dupe` call is necessary
    const info = try allocator.create(HostDir.Info);
    errdefer comptime unreachable;

    info.* = HostDir.Info{
        .permissions = perm,
        .guest_path_len = preopen.guest_path.len,
        .guest_path_ptr = preopen.guest_path.ptr,
        .read_next_cookie = .start,
        .read_state = ReadState{
            .iter = preopen.dir.iterate(),
            .name_buf = undefined,
            .cached = .current_dir,
        },
    };

    return File{
        .rights = File.Rights.init(types.Rights.Valid{
            .path_create_directory = perm.write,
            .path_create_file = perm.write,
            .path_link_source = true,
            .path_link_target = perm.write,
            .path_open = true,
            .fd_readdir = true,
            .path_readlink = true,
            .path_rename_source = perm.write,
            .path_rename_target = perm.write,
            .path_filestat_get = true,
            .path_symlink = perm.write,
            .path_remove_directory = perm.write,
            .path_unlink_file = perm.write,
        }),
        .impl = File.Impl{
            .ctx = Ctx.init(HostDir{ .dir = preopen.dir, .info = info }),
            .vtable = &vtable,
        },
    };
}

fn fd_fdstat_get(ctx: Ctx) Error!types.FdStat.File {
    _ = ctx;
    std.log.debug("TODO: proper implementation of fd_fdstat_get for directory", .{});
    // return .{ .type = .directory };
    return Error.Unimplemented;
}

pub fn fd_prestat_get(ctx: Ctx) Error!types.PreStat {
    const self = ctx.get(HostDir);
    return .init(
        types.PreStat.Type.dir,
        types.PreStat.Dir{ .pr_name_len = self.guestPath().len },
    );
}

pub fn fd_prestat_dir_name(ctx: Ctx, path: []u8) Error!void {
    const self = ctx.get(HostDir);
    if (self.info.guest_path_len < path.len) {
        return Error.InvalidArgument;
    }

    @memcpy(path[0..self.info.guest_path_len], self.guestPath().bytes());
}

const EntryBuf = struct {
    bytes: []u8,

    const WriteEntryResult = enum { full, partial, none };

    fn entrySize(name: Path) u17 {
        return @sizeOf(types.DirEnt) + name.len;
    }

    fn writeEntry(
        buf: *EntryBuf,
        next: types.DirCookie,
        inode: types.INode,
        name: Path,
        @"type": types.FileType,
    ) WriteEntryResult {
        if (buf.bytes.len == 0) {
            return .none;
        }

        const entry_size = entrySize(name);
        const written: WriteEntryResult = if (entry_size > buf.bytes.len) .partial else .full;

        var ent_buf: [@sizeOf(types.DirEnt)]u8 align(@alignOf(types.DirEnt)) = undefined;
        pointer.writeToBytes(
            types.DirEnt,
            &ent_buf,
            types.DirEnt{ .next = next, .ino = inode, .namlen = name.len, .type = @"type" },
        );
        const ent_len = @min(ent_buf.len, buf.bytes.len);
        @memcpy(buf.bytes[0..ent_len], ent_buf[0..ent_len]);
        buf.bytes = buf.bytes[ent_len..];

        const name_len = @min(name.len, buf.bytes.len);
        @memcpy(buf.bytes[0..name_len], name.bytes()[0..name_len]);
        buf.bytes = buf.bytes[name_len..];

        return written;
    }
};

const ReadState = struct {
    iter: std.fs.Dir.Iterator,
    name_buf: [std.fs.max_name_bytes]u8 align(16),
    cached: Cached,

    const Cached = union(enum) {
        current_dir,
        parent_dir,
        entry: struct {
            kind: std.fs.File.Kind,
            name_len: std.math.IntFittingRange(0, std.fs.max_name_bytes),
        },
        none,
    };

    fn peekCached(state: *const ReadState) ?std.fs.Dir.Entry {
        return switch (state.cached) {
            .current_dir => .{ .name = ".", .kind = .directory },
            .parent_dir => .{ .name = "..", .kind = .directory },
            .entry => |entry| .{ .name = state.name_buf[0..entry.name_len], .kind = entry.kind },
            .none => null,
        };
    }

    const NextError = std.fs.Dir.Iterator.Error || error{
        /// `std.fs.Dir.Iterator.ErrorLinux`.
        ///
        /// Corresponds to `ENOENT`.
        DirNotFound,
    };

    fn nextCached(state: *ReadState) ?std.fs.Dir.Entry {
        if (state.peekCached()) |entry| {
            state.cached = switch (state.cached) {
                .current_dir => .parent_dir,
                .parent_dir, .entry, .none => .none,
            };
            return entry;
        } else {
            return null;
        }
    }

    fn next(state: *ReadState) NextError!?std.fs.Dir.Entry {
        return state.nextCached() orelse switch (builtin.os.tag) {
            .linux => state.iter.nextLinux(),
            else => state.iter.next(),
        };
    }

    fn reset(state: *ReadState) void {
        state.iter.reset();
        @memset(&state.name_buf, undefined);
        state.cached = .current_dir;
    }
};

pub fn fd_readdir(
    ctx: Ctx,
    inode_hash_seed: types.INode.HashSeed,
    // allocator: Allocator,
    buf: []u8,
    cookie: types.DirCookie,
) Error!types.Size {
    const self = ctx.get(HostDir);

    // TODO: Buffer required to support `fd_readdir` seeking, especially on Windows
    // See https://github.com/WebAssembly/wasi-filesystem/issues/7

    if (cookie.n <= self.info.read_next_cookie.n) {
        @branchHint(.unlikely);
        self.info.read_state.reset();

        if (cookie.n != types.DirCookie.start.n) {
            // Seek forwards to previous position
            var seek_cookie = types.DirCookie.start;
            while (seek_cookie.n < cookie.n) {
                defer seek_cookie.n += 1;
                _ = (try self.info.read_state.next()) orelse return error.InvalidArgument;
            }
        }
    } else if (self.info.read_next_cookie.n < cookie.n) {
        @branchHint(.unlikely);

        // Seek to skip some entries
        var seek_cookie = cookie;
        while (seek_cookie.n < self.info.read_next_cookie.n) {
            defer seek_cookie.n += 1;
            _ = (try self.info.read_state.next()) orelse return error.InvalidArgument;
        }
    }

    var current_cookie = cookie;
    defer self.info.read_next_cookie = current_cookie;
    var entries = EntryBuf{ .bytes = buf };
    while (entries.bytes.len > 0) {
        const next = (try self.info.read_state.next()) orelse break;
        const name = Path.init(next.name) catch |e| switch (e) {
            error.PathTooLong => unreachable, // no supported OS's allow names this long
            // Could silently skip non-UTF-8 entries, but Zig `std` feels the need to catch it
            error.InvalidUtf8 => |err| return err,
        };

        errdefer comptime unreachable;

        const @"type" = types.FileType.fromZigKind(next.kind) catch |e| switch (e) {
            // TODO: need `getsockopt()` to determine exact type of socket
            error.UnknownSocketType => .unknown,
        };

        // Zig doesn't expose POSIX inode/Windows IndexNumber in `Dir.Iterator`, but WASI doesn't
        // seem to do anything with inodes anyway.

        // TODO: Copy `std.fs.Dir.Iterator` impls to obtain inode information that it skips
        // TODO: This returns different results than fd_fdstat_get impl, maybe do a `stat()` here (needed to find socket type anyway)?
        // TODO: Could use NtQueryInformationFile & FILE_INTERNAL_INFORMATION on Windows

        const next_cookie = types.DirCookie{ .n = current_cookie.n + 1 };
        const written = entries.writeEntry(
            next_cookie,
            .init(inode_hash_seed, 0x0123_4567_89AB_CDEF),
            name,
            @"type",
        );
        switch (written) {
            .none => unreachable,
            .full => current_cookie = next_cookie,
            .partial => {
                @memcpy(self.info.read_state.name_buf[0..name.len], name.bytes());
                self.info.read_state.cached = .{
                    .entry = .{ .kind = next.kind, .name_len = @intCast(name.len) },
                };
                break;
            },
        }
    }

    return @intCast(buf.len - entries.bytes.len);
}

fn fd_close(ctx: Ctx, allocator: Allocator) Error!void {
    const self = ctx.get(HostDir);
    // self.guestPath is not deallocated
    defer allocator.destroy(self.info);
    try host_file.closeHandle(self.dir.fd);
}

fn path_create_directory(ctx: Ctx, path: []const u8) Error!void {
    _ = ctx;
    _ = path;
    return Error.Unimplemented;
}

fn path_filestat_get(
    ctx: Ctx,
    flags: types.LookupFlags.Valid,
    path: []const u8,
) Error!types.FileStat {
    _ = ctx;
    _ = flags;
    _ = path;
    return Error.Unimplemented;
}

fn path_filestat_set_times(
    ctx: Ctx,
    lookup_flags: types.LookupFlags.Valid,
    path: []const u8,
    atim: types.Timestamp,
    mtim: types.Timestamp,
    fst_flags: types.FstFlags.Valid,
) Error!void {
    _ = ctx;
    _ = lookup_flags;
    _ = path;
    _ = atim;
    _ = mtim;
    _ = fst_flags;
    return Error.Unimplemented;
}

fn path_open(
    ctx: Ctx,
    dir_flags: types.LookupFlags.Valid,
    path: []const u8,
    open_flags: types.OpenFlags.Valid,
    rights_base: types.Rights.Valid,
    rights_inheriting: types.Rights.Valid,
    fd_flags: types.FdFlags.Valid,
) Error!File {
    _ = ctx;
    _ = dir_flags;
    _ = path;
    _ = open_flags;
    _ = rights_base;
    _ = rights_inheriting;
    _ = fd_flags;
    return Error.Unimplemented;
}

fn path_remove_directory(ctx: Ctx, path: []const u8) Error!void {
    _ = ctx;
    _ = path;
    return Error.Unimplemented;
}

pub fn path_symlink(ctx: Ctx, old_path: []const u8, new_path: []const u8) Error!void {
    _ = ctx;
    _ = old_path;
    _ = new_path;
    return Error.Unimplemented;
}

pub fn path_unlink_file(ctx: Ctx, path: []const u8) Error!void {
    _ = ctx;
    _ = path;
    return Error.Unimplemented;
}

pub const vtable = File.VTable{
    .fd_advise = fd_advise,
    .fd_allocate = fd_allocate,
    .fd_close = fd_close,
    .fd_datasync = fd_datasync,
    .fd_fdstat_get = fd_fdstat_get,
    .fd_fdstat_set_flags = fd_fdstat_set_flags,
    .fd_filestat_get = File.unimplemented.fd_filestat_get,
    .fd_filestat_set_size = fd_filestat_set_size,
    .fd_filestat_set_times = File.unimplemented.fd_filestat_set_times,
    .fd_pread = fd_pread,
    .fd_prestat_get = fd_prestat_get,
    .fd_prestat_dir_name = fd_prestat_dir_name,
    .fd_pwrite = fd_pwrite,
    .fd_read = fd_read,
    .fd_readdir = fd_readdir,
    .fd_seek = fd_seek,
    .fd_sync = File.unimplemented.fd_sync,
    .fd_tell = fd_tell,
    .fd_write = fd_write,
    .path_create_directory = path_create_directory,
    .path_filestat_get = path_filestat_get,
    .path_filestat_set_times = path_filestat_set_times,
    .path_open = path_open,
    .path_readlink = File.unimplemented.path_readlink,
    .path_remove_directory = path_remove_directory,
    .path_symlink = path_symlink,
    .path_unlink_file = path_unlink_file,
    .sock_accept = sock_accept,
    .sock_recv = sock_recv,
    .sock_send = sock_send,
    .sock_shutdown = sock_shutdown,
};

fn fd_advise(_: Ctx, _: types.FileSize, _: types.FileSize, _: types.Advice) Error!void {
    @trap();
}

fn fd_allocate(_: Ctx, _: types.FileSize, _: types.FileSize) Error!void {
    @trap();
}

fn fd_datasync(_: Ctx) Error!void {
    @trap();
}

fn fd_fdstat_set_flags(_: Ctx, _: types.FdFlags.Valid) Error!void {
    @trap();
}

fn fd_filestat_set_size(_: Ctx, _: types.FileSize) Error!void {
    @trap();
}

fn fd_pread(_: Ctx, _: []const File.Iovec, _: types.FileSize, _: u32) Error!u32 {
    @trap();
}

fn fd_read(_: Ctx, _: []const File.Iovec, _: u32) Error!u32 {
    @trap();
}

fn fd_pwrite(_: Ctx, _: []const File.Ciovec, _: types.FileSize, _: u32) Error!u32 {
    @trap();
}

fn fd_seek(_: Ctx, _: types.FileDelta, _: types.Whence) Error!types.FileSize {
    @trap();
}

fn fd_tell(_: Ctx) Error!types.FileSize {
    @trap();
}

fn fd_write(_: Ctx, _: []const File.Ciovec, _: u32) Error!u32 {
    @trap();
}

fn sock_accept(_: Ctx, _: types.FdFlags.Valid) Error!File {
    @trap();
}

fn sock_recv(
    _: Ctx,
    _: []const File.Iovec,
    _: u32,
    _: types.RiFlags.Valid,
) Error!File.SockRecvResult {
    @trap();
}

fn sock_send(_: Ctx, _: []const File.Ciovec, _: u32) Error!types.Size {
    @trap();
}

fn sock_shutdown(_: Ctx, _: types.SdFlags.Valid) Error!void {
    @trap();
}

const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const ArenaAllocator = std.heap.ArenaAllocator;
const types = @import("../types.zig");
const pointer = @import("wasmstint").pointer;
const PreopenDir = @import("../PreopenDir.zig");
const Path = @import("../Path.zig");
const File = @import("../File.zig");
const Error = File.Error;
const Ctx = File.Ctx;
const host_file = @import("host_file.zig");
