//! Wraps a host OS file descriptor referring to a directory.

const HostDir = struct {
    dir: std.fs.Dir,
    info: *Info,

    const Info = struct {
        // Guest `Path` is split to reduce padding
        guest_path_len: Path.Len, // maybe u1 bit in Path.Len to indicate ownership/constness?
        guest_path_ptr: Path.Ptr,
        read_next_cookie: types.DirCookie, // TODO: Hash cookies? Could use `std.hash.int`
        read_state: ReadState,
    };

    fn guestPath(ctx: *const HostDir) ?Path {
        return if (ctx.info.guest_path_len > 0)
            Path{ .ptr = ctx.info.guest_path_ptr, .len = ctx.info.guest_path_len }
        else
            null;
    }
};

const initial_rights = types.Rights.Valid.init(&.{
    .path_link_source,
    .path_open,
    .fd_readdir,
    .path_readlink,
    .path_filestat_get,
});

const write_rights = types.Rights.Valid.init(&.{
    .path_create_directory,
    .path_create_file,
    .path_link_target,
    .path_rename_source,
    .path_rename_target,
    .path_symlink,
    .path_remove_directory,
    .path_unlink_file,
});

/// Ownership of the file descriptor is transferred to the `File`.
pub fn initPreopened(preopen: *PreopenDir, allocator: Allocator) Allocator.Error!File {
    std.debug.assert(preopen.guest_path.len > 0);

    defer preopen.* = undefined;

    const perm = preopen.permissions;

    // Right now `main.zig` allocates paths in an `arena`, so no `dupe` call is necessary
    const info = try allocator.create(HostDir.Info);
    errdefer comptime unreachable;

    info.* = HostDir.Info{
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
        .rights = File.Rights.init(
            initial_rights.unionWithConditional(perm.write, write_rights),
        ),
        .impl = File.Impl{
            .ctx = Ctx.init(HostDir{ .dir = preopen.dir, .info = info }),
            .vtable = &vtable,
        },
    };
}

const log = std.log.scoped(.host_dir);

fn fd_fdstat_get(ctx: Ctx) Error!types.FdStat.File {
    _ = ctx;
    return .{ .type = .directory, .flags = std.mem.zeroes(types.FdFlags) };
}

pub fn fd_prestat_get(ctx: Ctx) Error!types.PreStat {
    const self = ctx.get(HostDir);
    return if (self.guestPath()) |guest_path|
        types.PreStat.init(
            types.PreStat.Type.dir,
            types.PreStat.Dir{ .pr_name_len = guest_path.len },
        )
    else
        Error.NotCapable;
}

pub fn fd_prestat_dir_name(ctx: Ctx, path: []u8) Error!void {
    const self = ctx.get(HostDir);
    if (self.guestPath()) |guest_path| {
        if (self.info.guest_path_len < guest_path.len) {
            return Error.InvalidArgument;
        }

        @memcpy(path[0..self.info.guest_path_len], guest_path.bytes());
    } else {
        return Error.NotCapable;
    }
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

const todo_openat2_on_linux_is_not_yet_supported = true; // TODO

/// https://man7.org/linux/man-pages/man2/openat2.2.html
fn accessSubPathLinux(
    dir: std.fs.Dir,
    scratch: *ArenaAllocator,
    flags: types.LookupFlags.Valid,
    path: Path,
    args: anytype,
    comptime accessor: anytype,
) (error{NoSysOpenat2} || Error)!@typeInfo(accessor).@"fn".return_type.? {
    if (todo_openat2_on_linux_is_not_yet_supported) {
        return error.NoSysOpenat2;
    }

    const path_z = try scratch.allocator().dupeZ(u8, path.bytes());
    const rc = std.os.linux.syscall4(
        std.os.linux.SYS.openat2,
        dir.fd,
        path_z,
        undefined, // how struct,
        undefined, // how size
    ); // FallbackImplementation if E_NOSYS or E2BIG

    _ = flags;
    _ = args;
    _ = rc;
}

// FreeBSD also supports `O_RESOLVE_BENEATH` in openat
//fn accessSubPathFreeBsd()

fn AccessSubPathPortableReturn(comptime Accessor: type) type {
    return @typeInfo(@typeInfo(Accessor).@"fn".return_type.?).error_union.payload;
}

fn accessSubPathPortable(
    dir: std.fs.Dir,
    scratch: *ArenaAllocator,
    flags: types.LookupFlags.Valid,
    path: Path,
    args: anytype,
    comptime accessor: anytype,
) Error!AccessSubPathPortableReturn(@TypeOf(accessor)) {
    const max_component_len = 64;

    if (path.len == 0) {
        return Error.InvalidArgument; // is this right?
    }

    const initial_components: []const Path.Component = components: {
        var component_iter = std.mem.splitAny(u8, path.bytes(), "\\/");
        var component_buf = try std.ArrayList(Path.Component).initCapacity(scratch.allocator(), 1);
        while (component_iter.next()) |comp_slice| {
            if (std.mem.eql(u8, "..", comp_slice)) {
                if (component_buf.pop() == null) {
                    return Error.AccessDenied; // tried to escape sandbox
                }
            } else if (std.mem.eql(u8, ".", comp_slice) or comp_slice.len == 0) {
                continue;
            }

            const comp = Path.Component{
                .start = @intCast(comp_slice.ptr - path.ptr),
                .len = @intCast(comp_slice.len),
            };

            // log.debug("component {f}", .{comp.toPath(path)});

            if (component_buf.items.len >= max_component_len) {
                return Error.PathTooLong; // too many components
            }

            try component_buf.append(scratch.allocator(), comp);
        }

        if (scratch.allocator().resize(component_buf.allocatedSlice(), component_buf.items.len)) {
            component_buf.capacity = component_buf.items.len;
        }

        break :components component_buf.items;
    };

    if (initial_components.len == 0) {
        @branchHint(.unlikely);
        // Can't use `dup` here
        log.err("TODO: path_open to same directory {f}", .{path});
        return Error.Unimplemented;
    }

    log.debug("{d} components in {f}", .{ initial_components.len, path });

    // Can't compare realpath of dir and target, that's a TOCTOU

    // Strategy here is to open each subdirectory, expanding symlinks, until the parent of the
    // target is reached.
    const final_name = initial_components[initial_components.len - 1];

    var final_dir = dir;

    for (0.., initial_components[0 .. initial_components.len - 1]) |i, comp| {
        var old_dir = final_dir;
        defer if (i > 0 and i < initial_components.len - 1) {
            log.debug("closing intermediate directory {any}", .{old_dir.fd});
            old_dir.close();
        };

        const comp_bytes = comp.bytes(path);

        // TODO: Use O_PATH on Linux
        // TODO(zig): no_follow weird on windows https://github.com/ziglang/zig/issues/18335
        final_dir = old_dir.openDir(
            comp_bytes,
            .{ .access_sub_paths = true, .no_follow = true },
        ) catch |e| return switch (e) {
            error.SymLinkLoop => if (!flags.symlink_follow)
                error.SymLinkLoop
            else {
                // readLink + std.path.isAbsolute
                // Need separate array list (stackFallback(1, scratch.allocator())) to store expanded components
                log.debug("TODO: Expand symlinks in path_open for {f}", .{path});
                return error.Unimplemented;
            },
            error.InvalidUtf8, error.InvalidWtf8 => unreachable,
            error.NetworkNotFound => error.DirNotFound,
            else => |err| err,
        };

        log.debug("opened intermediate directory {f} ({any})", .{ comp.toPath(path), final_dir.fd });
    }

    defer if (initial_components.len > 1) {
        log.debug("closing final directory {any}", .{final_dir.fd});
        final_dir.close();
    };

    // TODO: Shoot! `final_name` could be a symlink! Better API might require passing FD to accessor

    return @call(.auto, accessor, .{ scratch, path, final_dir, final_name } ++ args);
}

/// Allows safely accessing a path below the directory.
fn accessSubPath(
    dir: std.fs.Dir,
    /// Used for temporary allocations of file paths.
    scratch: *ArenaAllocator,
    flags: types.LookupFlags.Valid,
    /// The path the guest wants to access.
    ///
    /// Attempts to navigate outside the handle (e.g. with `../` or symlinks) are caught.
    path: Path,
    /// Tuple containing additional arguments to pass.
    args: anytype,
    /// Namespace that provides functions that perform the operation on the path.
    ///
    /// This is not a single function to (eventually) allow specialized behavior on some platforms.
    /// - On Linux, this can be implemented with the `openat2` system call, which is what is used
    ///   to implement [WASI support in `wasmtime`].
    /// - On FreeBSD, this could probably be done with `O_RESOLVE_BENEATH` and `openat`.
    ///
    /// For the portable implementation, a handle to a parent directory (potentially a subdirectory)
    /// and the name of the target is provided.
    ///
    /// [WASI support in `wasmtime`]: https://docs.rs/cap-primitives/3.4.4/src/cap_primitives/rustix/linux/fs/open_impl.rs.html
    comptime accessor: type,
) Error!accessor.Result {
    // TODO: On Linux, fallback to portable implementation on E_NOSYS (check compile time OS version)
    fallback: switch (builtin.os.tag) {
        .linux => {
            if (todo_openat2_on_linux_is_not_yet_supported) break :fallback;

            // I think Zig's supported linux architectures all at least have a number for `openat2`
            if (!@hasField(std.os.linux.SYS, "openat2")) break :fallback;

            return accessSubPathLinux(
                dir,
                scratch,
                flags,
                path,
                args,
                accessor.linux,
            ) catch |e| switch (e) {
                error.NoSysOpenat2 => {
                    const linux_openat2_version = std.SemanticVersion{
                        .major = 5,
                        .minor = 6,
                        .patch = 0,
                    };

                    if (comptime builtin.os.isAtLeast(.linux, linux_openat2_version)) {
                        unreachable;
                    } else {
                        _ = scratch.reset();
                        break :fallback;
                    }
                },
                else => |err| return err,
            };
        },
        // .freebsd => {},
        else => {},
    }

    return accessSubPathPortable(dir, scratch, flags, path, args, accessor.portable);
}

const path_filestat_get_impl = struct {
    const Result = types.FileStat;

    fn portable(
        scratch: *ArenaAllocator,
        path: Path,
        final_dir: std.fs.Dir,
        final_name: Path.Component,
        device_hash_seed: types.Device.HashSeed,
        inode_hash_seed: types.INode.HashSeed,
    ) Error!types.FileStat {
        // TODO: Possible duplicate code with `host_file.fd_fdstat_get`
        if (builtin.os.tag == .windows) {
            // TODO: On Windows, need to use NtQueryInformationFile: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntqueryinformationfile
            log.err("path_filestat_get of {f} on windows", .{path});
            return Error.Unimplemented;
        } else if (@hasDecl(std.posix.system, "Stat") and std.posix.Stat != void) {
            // TODO: Use statx on Linux
            const final_name_z = try scratch.allocator().dupeZ(u8, final_name.bytes(path));
            const o_flags = if (@hasDecl(std.posix.AT, "SYMLINK_NOFOLLOW"))
                std.posix.AT.SYMLINK_NOFOLLOW
            else
                0;
            const stat = try std.posix.fstatatZ(final_dir.fd, final_name_z, o_flags);
            const zig_stat = std.fs.File.Stat.fromPosix(stat);

            return types.FileStat{
                .dev = types.Device.init(device_hash_seed, stat.dev),
                .ino = types.INode.init(inode_hash_seed, stat.ino),
                .type = types.FileType.fromZigKind(zig_stat.kind) catch |e| switch (e) {
                    // TODO: need `getsockopt()` to determine exact type of socket
                    error.UnknownSocketType => .unknown,
                },
                .nlink = stat.nlink,
                .size = types.FileSize{ .bytes = zig_stat.size },
                .atim = types.Timestamp{ .ns = @truncate(@as(u128, @bitCast(zig_stat.atime))) },
                .mtim = types.Timestamp{ .ns = @truncate(@as(u128, @bitCast(zig_stat.mtime))) },
                .ctim = types.Timestamp{ .ns = @truncate(@as(u128, @bitCast(zig_stat.ctime))) },
            };
        } else {
            @compileError("path_filestat_get impl for " ++ @tagName(builtin.os.tag));
        }
    }
};

fn path_filestat_get(
    ctx: Ctx,
    scratch: *ArenaAllocator,
    device_hash_seed: types.Device.HashSeed,
    inode_hash_seed: types.INode.HashSeed,
    flags: types.LookupFlags.Valid,
    path: Path,
) Error!types.FileStat {
    log.debug("path_filestat_get attempting to access {f}", .{path});
    errdefer |e| log.err("path_filestat_get for {f} failed with {t}", .{ path, e });

    const self = ctx.get(HostDir);
    return accessSubPath(
        self.dir,
        scratch,
        flags,
        path,
        .{ device_hash_seed, inode_hash_seed },
        path_filestat_get_impl,
    );
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

const path_open_impl = struct {
    const Result = File.OpenedPath;

    fn portable(
        scratch: *ArenaAllocator,
        path: Path,
        final_dir: std.fs.Dir,
        final_name: Path.Component,
        open_flags: types.OpenFlags.Valid,
        rights: types.Rights.Valid,
        fd_flags: types.FdFlags.Valid,
    ) Error!Result {
        // Open final handle
        // TODO(zig): openAny https://github.com/ziglang/zig/issues/16738
        if (builtin.os.tag == .windows) {
            log.err("path_open final component {f} on windows", .{path});
            return error.Unimplemented;
        } else if (@hasDecl(std.posix.system, "O") and std.posix.O != void) {
            const final_name_z = try scratch.allocator().dupeZ(u8, final_name.bytes(path));

            var o_flags = fd_flags.toFlagsPosix() catch return error.InvalidArgument;
            o_flags.NOFOLLOW = true;
            open_flags.setPosixFlags(&o_flags);

            if (@hasField(std.posix.O, "CLOEXEC")) o_flags.CLOEXEC = true;
            if (@hasField(std.posix.O, "LARGEFILE")) o_flags.LARGEFILE = true;
            if (@hasField(std.posix.O, "NOCTTY")) o_flags.NOCTTY = true;

            if (!open_flags.directory) {
                // TODO: Darn, need to figure out if directory or file! (fstatat?)
                o_flags.ACCMODE = if (rights.canWrite()) .RDWR else .RDONLY;
            }

            errdefer |e| log.err("OS error {t} opening {f}", .{ e, path });

            const new_fd = std.posix.openatZ(
                final_dir.fd,
                final_name_z,
                o_flags,
                0,
            ) catch |e| return switch (e) {
                error.InvalidWtf8, error.NetworkNotFound => unreachable, // Windows-only
                error.FileLocksNotSupported => unreachable,
                else => |err| err,
            };

            errdefer std.posix.close(new_fd);

            if (open_flags.directory) {
                log.err("TODO: opened directory {f}", .{path});
                return error.Unimplemented;
            } else {
                const as_file = std.fs.File{ .handle = new_fd };
                const kind = (try as_file.stat()).kind;
                return switch (kind) {
                    .directory => {
                        log.err("TODO: {f} is an opened directory", .{path});
                        return error.Unimplemented;
                    },
                    else => File.OpenedPath{
                        .file = host_file.wrapFile(as_file, .close),
                        .rights = rights.intersection(host_file.possible_rights),
                    },
                };
            }
        } else {
            @compileError("path_open impl for " ++ @tagName(builtin.os.tag));
        }
    }
};

fn path_open(
    ctx: Ctx,
    scratch: *ArenaAllocator,
    dir_flags: types.LookupFlags.Valid,
    path: Path,
    open_flags: types.OpenFlags.Valid,
    rights: types.Rights.Valid,
    fd_flags: types.FdFlags.Valid,
) Error!File.OpenedPath {
    // Linux allows returning `ENOMEM`, so this can return `error.OutOfMemory`.

    log.debug("path_open attempting to access {f}", .{path});

    const self = ctx.get(HostDir);
    return accessSubPath(
        self.dir,
        scratch,
        dir_flags,
        path,
        .{ open_flags, rights, fd_flags },
        path_open_impl,
    );
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

fn sock_accept(_: Ctx, _: types.FdFlags.Valid) Error!File.Impl {
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
