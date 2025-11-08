//! Wraps a host OS file descriptor referring to a directory.

const HostDir = struct {
    dir: std.Io.Dir,
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

const possible_rights = types.Rights.Valid.init(&.{
    .path_link_source,
    .path_open,
    .fd_readdir,
    .fd_filestat_get,
    .path_readlink,
    .path_filestat_get,
    .path_create_directory,
    .path_create_file,
    .path_link_target,
    .path_rename_source,
    .path_rename_target,
    .path_symlink,
    .path_remove_directory,
    .path_unlink_file,
});

const initial_rights = types.Rights.Valid.init(&.{
    .path_link_source,
    .path_open,
    .fd_readdir,
    .path_readlink,
    .path_filestat_get,
    .fd_filestat_get,
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

const initial_inheriting_rights = possible_rights.unionWith(host_file.possible_rights);

comptime {
    std.debug.assert(possible_rights.contains(initial_rights));
    std.debug.assert(possible_rights.contains(write_rights));
    std.debug.assert(initial_inheriting_rights.contains(.init(&.{.fd_filestat_get})));
}

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
            .iter = std.fs.Dir.adaptFromNewApi(preopen.dir).iterate(),
            .name_buf = undefined,
            .cached = .current_dir,
        },
    };

    return File{
        .rights = File.Rights{
            .base = initial_rights.unionWithConditional(perm.write, write_rights),
            // TODO: Could allow caller to restrict rights, maybe add params on `PreopenDir`?
            .inheriting = initial_inheriting_rights
                .withoutConditional(perm.write, write_rights)
                .withoutConditional(perm.write, host_file.write_rights),
        },
        .impl = File.Impl{
            .ctx = Ctx.init(HostDir{ .dir = preopen.dir, .info = info }),
            .vtable = &vtable,
        },
    };
}

const log = std.log.scoped(.host_dir);

fn init(
    dir: std.Io.Dir,
    allocator: Allocator,
    rights: types.Rights.Valid,
) Allocator.Error!File.OpenedPath {
    // No guest path, don't have to worry about UAF
    const info = try allocator.create(HostDir.Info);
    errdefer comptime unreachable;

    info.* = HostDir.Info{
        .guest_path_len = 0,
        .guest_path_ptr = @as([]const u8, "").ptr,
        .read_next_cookie = .start,
        .read_state = ReadState{
            .iter = std.fs.Dir.adaptFromNewApi(dir).iterate(),
            .name_buf = undefined,
            .cached = .current_dir,
        },
    };

    return File.OpenedPath{
        .rights = rights.intersection(possible_rights),
        .file = File.Impl{
            .ctx = Ctx.init(HostDir{ .dir = dir, .info = info }),
            .vtable = &vtable,
        },
    };
}

fn fd_filestat_get(
    ctx: Ctx,
    device_hash_seed: types.Device.HashSeed,
    inode_hash_seed: types.INode.HashSeed,
) Error!types.FileStat {
    const self = ctx.get(HostDir);
    std.log.err("fd_filestat_get for directories is not implemented", .{});
    _ = self;
    _ = device_hash_seed;
    _ = inode_hash_seed;
    return Error.Unimplemented;
    // const stat = try self.dir.stat();
    // return types.FileStat{ .type = .directory, .flags = std.mem.zeroes(types.FdFlags) };
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
        } else if (path.len < self.info.guest_path_len) {
            return Error.InvalidArgument;
        } else {
            @memcpy(path[0..self.info.guest_path_len], guest_path.bytes());
        }
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

        // Zig doesn't expose POSIX inode/Windows IndexNumber in `Dir.Iterator`.

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
    try host_file.closeHandle(self.dir.handle);
}

fn fd_fdstat_get(ctx: Ctx) Error!types.FdStat.File {
    _ = ctx;
    return types.FdStat.File{
        .type = .directory,
        .flags = std.mem.zeroes(types.FdFlags),
    };
}

fn path_create_directory(ctx: Ctx, path: []const u8) Error!void {
    _ = ctx;
    _ = path;
    return Error.Unimplemented;
}

const WindowsOpenFlags = struct {
    access_mask: host_os.windows.AccessMask,
    comptime file_attributes: std.os.windows.ULONG = std.os.windows.FILE_ATTRIBUTE_NORMAL,
    share_access: host_os.windows.ShareAccess = share_access_default,
    create_disposition: host_os.windows.CreateDisposition,
    create_options: host_os.windows.CreateOptions,

    const share_access_default = host_os.windows.ShareAccess.init(
        &.{ .FILE_SHARE_READ, .FILE_SHARE_WRITE, .FILE_SHARE_DELETE },
    );
};

const OsOpenFlags = if (builtin.os.tag == .windows)
    WindowsOpenFlags
else if (@hasDecl(std.posix.system, "O") and std.posix.O != void)
    std.posix.O
else
    @compileError("specify open flags type " ++ @tagName(builtin.os.tag));

const SetOpenFlagsError = error{ InvalidArgument, NotSupported, Unimplemented };

fn SetOpenFlags(comptime Args: type) type {
    const args_fields = @typeInfo(Args).@"struct".fields;
    return @Type(.{
        .@"fn" = std.builtin.Type.Fn{
            .calling_convention = .auto,
            .is_generic = false,
            .is_var_args = false,
            .return_type = SetOpenFlagsError!OsOpenFlags,
            .params = params: {
                var params: [args_fields.len]std.builtin.Type.Fn.Param = undefined;
                for (args_fields, &params) |src, *dst| {
                    dst.* = std.builtin.Type.Fn.Param{
                        .is_generic = false,
                        .is_noalias = false,
                        .type = src.type,
                    };
                }
                break :params &params;
            },
        },
    });
}

/// Uses the Linux [`openat2`] syscall to safely access a path within `dir`.
///
/// [`openat2`]: https://man7.org/linux/man-pages/man2/openat2.2.html
fn accessSubPathLinux(
    dir: std.Io.Dir,
    scratch: *ArenaAllocator,
    flags: types.LookupFlags.Valid,
    path: Path,
    set_open_flags_args: anytype,
    comptime setOpenFlags: SetOpenFlags(@TypeOf(set_open_flags_args)),
    do_in_path_args: anytype,
    comptime doInPath: anytype,
) (error{NoOpenAt2} || Error)!AccessSubPathReturnType(@TypeOf(doInPath)) {
    const supported = struct {
        var flag = std.atomic.Value(bool).init(true);
    };

    if (!supported.flag.load(.unordered)) {
        return error.NoOpenAt2;
    }

    const OpenHow = extern struct {
        // 3 fields are what are supported in initial design for `openat2`
        flags: u64 = 0,
        mode: u64 = 0,
        resolve: Resolve = Resolve{},

        const Resolve = packed struct(u64) {
            NO_XDEV: bool = false,
            NO_MAGICLINKS: bool = false,
            NO_SYMLINKS: bool = false,
            BENEATH: bool = false,
            IN_ROOT: bool = false,
            CACHED: bool = false,
            _6: u58 = 0,
        };
    };

    const o_flags: std.os.linux.O = flags: {
        var initial: std.os.linux.O = try @call(.auto, setOpenFlags, set_open_flags_args);
        std.debug.assert(!initial.NOFOLLOW);
        initial.NOFOLLOW = !flags.symlink_follow;
        break :flags initial;
    };

    const how = OpenHow{
        .flags = @as(u32, @bitCast(o_flags)),
        .resolve = OpenHow.Resolve{
            .BENEATH = true,
            // .IN_ROOT = true, //  causes `EINVAL`, `wasmtime` doesn't use it anyway
            .NO_MAGICLINKS = true,
        },
    };

    // errdefer |e| log.err("OS error {t} opening {f}", .{ e, path });

    const path_z = try scratch.allocator().dupeZ(u8, path.bytes());
    const new_fd: std.os.linux.fd_t = while (true) {
        const result = std.os.linux.syscall4(
            std.os.linux.SYS.openat2,
            @bitCast(@as(isize, dir.handle)),
            @intFromPtr(path_z.ptr),
            @intFromPtr(&how),
            @sizeOf(OpenHow),
        );

        switch (host_os.linux.errno(result)) {
            .SUCCESS => break @intCast(result),
            .INTR => continue,
            .NOSYS => {
                supported.flag.store(false, .monotonic);
                return error.NoOpenAt2;
            },
            .ACCES => return error.AccessDenied,
            .@"2BIG" => unreachable, // provided `how` fields are always supported
            .BADF => unreachable,
            .BUSY => return error.DeviceBusy,
            .DQUOT => return error.DiskQuota,
            .EXIST => return error.PathAlreadyExists,
            .FAULT => unreachable,
            .FBIG, .OVERFLOW => return error.FileTooBig,
            .INVAL => return error.InvalidArgument, // filesystem doesn't like file name
            .ISDIR => return error.IsDir,
            .LOOP => return error.SymLinkLoop,
            .MFILE => return error.ProcessFdQuotaExceeded,
            .NAMETOOLONG => return error.NameTooLong,
            .NFILE => return error.SystemFdQuotaExceeded,
            .NODEV, .NXIO => return error.NoDevice,
            .NOENT => return error.FileNotFound,
            .SRCH => return error.ProcessNotFound,
            .NOMEM => return error.OutOfMemory,
            .NOSPC => return error.NoSpaceLeft,
            .NOTDIR => return error.NotDir,
            .PERM => return error.PermissionDenied,
            .OPNOTSUPP => unreachable, // O_TMPFILE is never passed
            .ROFS => return error.ReadOnlyFileSystem,
            .TXTBSY => return error.FileBusy,
            .AGAIN => return error.WouldBlock,
            .XDEV => return error.AccessDenied, // escape from `dir`
            else => |err| return std.posix.unexpectedErrno(err),
        }
    };

    return @call(.auto, doInPath, .{new_fd} ++ .{ scratch, path } ++ do_in_path_args);
}

// FreeBSD also supports `O_RESOLVE_BENEATH` in openat
//fn accessSubPathFreeBsd()

fn AccessSubPathReturnType(comptime Accessor: type) type {
    return @typeInfo(@typeInfo(Accessor).@"fn".return_type.?).error_union.payload;
}

/// Depends on the host OS having a way to open a path relative to an opened directory handle/fd
/// while also indicating if a symlink would have been opened.
///
/// This is an implementation of the path resolution algorithm described
/// [here](https://github.com/WebAssembly/wasi-filesystem/blob/main/path-resolution.md).
fn accessSubPathPortable(
    dir: std.Io.Dir,
    scratch: *ArenaAllocator,
    flags: types.LookupFlags.Valid,
    path: Path,
    set_open_flags_args: anytype,
    comptime setOpenFlags: SetOpenFlags(@TypeOf(set_open_flags_args)),
    do_in_path_args: anytype,
    comptime doInPath: anytype,
) Error!AccessSubPathReturnType(@TypeOf(doInPath)) {
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

            coz.progressNamed("wasmstint.WasiPreview1.host_dir.accessSubPath-component");
            try component_buf.append(scratch.allocator(), comp);
        }

        if (scratch.allocator().resize(component_buf.allocatedSlice(), component_buf.items.len)) {
            component_buf.capacity = component_buf.items.len;
        }

        break :components component_buf.items;
    };

    const final_name: ?[]const u8 = if (initial_components.len > 0)
        initial_components[initial_components.len - 1].bytes(path)
    else
        null;

    // TODO(zig): https://github.com/ziglang/zig/issues/20369
    // errdefer |e| log.err("OS error {t} opening {f}", .{ @as(anyerror, e), path });

    // log.debug("{d} components in {f}", .{ initial_components.len, path });

    // Can't compare realpath of dir and target, that's a TOCTOU

    // Strategy here is to open each subdirectory, expanding symlinks, until the parent of the
    // target is reached.

    var path_arena = ArenaAllocator.init(scratch.allocator());
    var final_dir = std.fs.Dir.adaptFromNewApi(dir);
    if (initial_components.len > 1) {
        for (0.., initial_components[0 .. initial_components.len - 1]) |i, comp| {
            var coz_open_comp_dir = coz.begin("wasmstint.WasiPreview1.host_dir.accessSubPath-openDir");
            defer coz_open_comp_dir.end();

            var old_dir: std.fs.Dir = final_dir;
            defer if (i > 0 and i < initial_components.len - 1) {
                // log.debug("closing intermediate directory {any}", .{old_dir.fd});
                old_dir.close();
            };

            const comp_bytes = comp.bytes(path);
            // TODO: Make own openDir wrapper
            const comp_str = if (builtin.os.tag == .windows)
                std.unicode.utf8ToUtf16LeAllocZ(
                    path_arena.allocator(),
                    comp_bytes,
                ) catch |e| switch (e) {
                    error.InvalidUtf8 => unreachable,
                    error.OutOfMemory => |oom| return oom,
                }
            else
                // try path_arena.allocator().dupeZ(u8, comp_bytes);
                comp_bytes;

            // TODO: Use O_PATH on Linux, requires using platform-specific APIs

            var io = std.Io.Threaded.init_single_threaded;
            const open_options = std.Io.Dir.OpenOptions{
                .access_sub_paths = true,
                // TODO(zig): no_follow weird on windows https://github.com/ziglang/zig/issues/18335
                .follow_symlinks = false,
            };

            final_dir = (if (builtin.os.tag == .windows) next: {
                break :next std.fs.Dir.adaptFromNewApi(
                    io.dirOpenDirWindows(
                        old_dir.adaptToNewApi(),
                        comp_str,
                        open_options,
                    ) catch |e| break :next e,
                );
            } else old_dir.openDir(comp_str, open_options)) catch |e| return switch (e) {
                // error.NotDir might happen on windows because a symlink is obviously not a directory
                error.Canceled => unreachable,
                error.SymLinkLoop => if (builtin.os.tag == .windows)
                    unreachable
                else if (!flags.symlink_follow)
                    error.SymLinkLoop
                else {
                    // readLink + std.path.isAbsolute
                    // Need separate array list (stackFallback(1, scratch.allocator())) to store expanded components
                    log.debug("TODO: Expand symlinks in accessSubPathPortable for {f}", .{path});
                    return error.Unimplemented;
                },
                error.NetworkNotFound => error.DirNotFound,
                else => |err| err,
            };

            // log.debug(
            //     "opened intermediate directory {f} ({any})",
            //     .{ comp.toPath(path), final_dir.fd },
            // );

            _ = path_arena.reset(.retain_capacity);
        }
    }

    defer if (initial_components.len > 1) {
        // log.debug("closing final directory {any}", .{final_dir.fd});
        final_dir.close();
    };

    // Open final handle
    const initial_o_flags: OsOpenFlags = try @call(.auto, setOpenFlags, set_open_flags_args);

    const do_in_path_args_without_fd = .{ scratch, path } ++ do_in_path_args;

    // TODO(zig): openAny https://github.com/ziglang/zig/issues/16738
    if (builtin.os.tag == .windows) {
        const initial_flags: WindowsOpenFlags = initial_o_flags;
        std.debug.assert(!initial_flags.create_options.containsFlag(.FILE_OPEN_REPARSE_POINT));

        errdefer log.err("failed to open final component in {f}", .{path});

        // `NtCreateFile` doesn't seem to support "." or ".\\" as a path to the `final_dir`
        const final_name_bytes = final_name orelse {
            @branchHint(.unlikely);
            const current_process = std.os.windows.GetCurrentProcess();
            var new_fd: std.os.windows.HANDLE = undefined;
            const result = host_os.windows.NtDuplicateObject(
                current_process,
                final_dir.fd,
                current_process,
                &new_fd,
                // TODO: Figure out access denied error or use ReOpenFile
                undefined, // initial_flags.access_mask.bits
                undefined,
                host_os.windows.DUPLICATE_SAME_ATTRIBUTES | std.os.windows.DUPLICATE_SAME_ACCESS,
            );

            return switch (result) {
                .SUCCESS => @call(.auto, doInPath, .{new_fd} ++ do_in_path_args_without_fd),
                // .ACCESS_DENIED => error.AccessDenied,
                // .NOT_ENOUGH_MEMORY => error.OutOfMemory,
                else => std.os.windows.unexpectedStatus(result),
            };
        };

        const final_name_w = std.unicode.utf8ToUtf16LeAllocZ(
            path_arena.allocator(),
            final_name_bytes,
        ) catch |e| switch (e) {
            error.InvalidUtf8 => unreachable,
            error.OutOfMemory => |oom| return oom,
        };

        var final_name_unicode = host_os.windows.initUnicodeString(final_name_w);

        // Documentation for `NtCreateFile` only lists `OBJ_CASE_INSENSITIVE` for `Attributes`
        //
        // `OBJ_DONT_REPARSE` fails on paths like `C:\Users\You\file.txt`, but this only needs to
        // process relative paths.
        //
        // For more information see:
        // https://www.tiraniddo.dev/2020/05/objdontreparse-is-mostly-useless.html
        const obj_dont_reparse_min_version = std.Target.Os.WindowsVersion.win10_rs1;
        const has_obj_dont_reparse =
            builtin.os.version_range.windows.isAtLeast(obj_dont_reparse_min_version);

        const new_fd: std.fs.File.Handle = if (has_obj_dont_reparse == true) opened: {
            var attrs = std.os.windows.OBJECT_ATTRIBUTES{
                .Length = @sizeOf(std.os.windows.OBJECT_ATTRIBUTES),
                .RootDirectory = final_dir.fd,
                .ObjectName = &final_name_unicode,
                .Attributes = host_os.windows.OBJ_DONT_REPARSE,
                .SecurityDescriptor = null,
                .SecurityQualityOfService = null,
            };

            // Recreates some logic for `std.os.windows.OpenFile`
            while (true) {
                var opened_handle: std.fs.File.Handle = undefined;
                var io: std.os.windows.IO_STATUS_BLOCK = undefined;
                const status = host_os.windows.NtCreateFile(
                    &opened_handle,
                    initial_flags.access_mask,
                    &attrs,
                    &io,
                    null,
                    std.os.windows.FILE_ATTRIBUTE_NORMAL,
                    initial_flags.share_access,
                    initial_flags.create_disposition,
                    initial_flags.create_options,
                    null,
                    0,
                );
                switch (status) {
                    .SUCCESS => break :opened opened_handle,
                    host_os.windows.STATUS_REPARSE_POINT_ENCOUNTERED => {
                        log.err(
                            "TODO: windows accessSubPathPortable reparse point while opening {f}",
                            .{path},
                        );
                        // Either use tail calls, or wrap the whole function in a big for loop (0..arbitrary_limit)
                        // continue; // do this when reparse point components are parsed
                        return Error.Unimplemented;
                    },
                    .OBJECT_NAME_COLLISION => return error.PathAlreadyExists,
                    .OBJECT_NAME_INVALID => return error.BadPathName,
                    .OBJECT_NAME_NOT_FOUND, .OBJECT_PATH_NOT_FOUND => return error.FileNotFound,
                    .BAD_NETWORK_PATH, .BAD_NETWORK_NAME => return error.NetworkNotFound,
                    else => return std.os.windows.unexpectedStatus(status),
                }
            }
        } else opened: {
            if (true) {
                @compileError(std.fmt.comptimePrint(
                    "target windows version was {[actual]t}, but accessSubPathPortable " ++
                        "requires at least {[expected]t}.\nIf using zig build, pass " ++
                        "-Dtarget={[cpu]t}-windows.{[expected]t}.\nIf you feel lucky, manually " ++
                        "remove the version check.",
                    .{
                        .actual = builtin.os.version_range.windows.min,
                        .expected = obj_dont_reparse_min_version,
                        .cpu = builtin.cpu.arch,
                    },
                ));
            }

            // BEGIN UNFINISHED CODE //

            // Initial open flags could specify file truncation, but that would either mean no
            // symlink detection or truncating the symlink itself. Unfortunately, this means
            // unconditionally checking for symlinks.

            // Attempting to read the symlink path first followed by doing the real file open means
            // a TOCTOU. A symlink could be created in between `DeviceIoControl` and final
            // `NtCreateFile` call.
            const create_disposition_dont_truncate = switch (initial_flags.create_disposition) {
                .FILE_SUPERSEDE => unreachable, // currently not used
                .FILE_CREATE, .FILE_OPEN, .FILE_OPEN_IF => |flag| flag,
                .FILE_OVERWRITE => .FILE_OPEN,
                .FILE_OVERWRITE_IF => .FILE_OPEN_IF,
            };

            var maybe_symlink_attrs = std.os.windows.OBJECT_ATTRIBUTES{
                .Length = @sizeOf(std.os.windows.OBJECT_ATTRIBUTES),
                .RootDirectory = final_dir.fd,
                .ObjectName = &final_name_unicode,
                .Attributes = 0,
                .SecurityDescriptor = null,
                .SecurityQualityOfService = null,
            };

            // `NtDuplicateObject` is equivalent of `ReOpenFile`, which could be useful here
            while (true) {
                // Logic copied from Zig's `std.os.windows.ReadLink`, except that this does not
                // allow absolute paths.
                var maybe_symlink_handle: std.fs.File.Handle = undefined;
                var maybe_symlink_io: std.os.windows.IO_STATUS_BLOCK = undefined;
                const maybe_symlink_status = std.os.windows.ntdll.NtCreateFile(
                    &maybe_symlink_handle,
                    // Needs to be replaced with `initial_flags.access_mask.bits`
                    // This is enough to figure out symlink information
                    WindowsOpenFlags.AccessMask.init(&.{ .FILE_READ_ATTRIBUTES, .SYNCHRONIZE }).bits,
                    &maybe_symlink_attrs,
                    &maybe_symlink_io,
                    null,
                    std.os.windows.FILE_ATTRIBUTE_NORMAL,
                    // Needs to be replaced with `initial_flags.share_access.bits`
                    WindowsOpenFlags.share_access_default.bits,
                    // Needs to be replaced with `initial_flags.create_disposition`
                    @intFromEnum(create_disposition_dont_truncate),
                    // Needs to be replaced with `initial_flags.create_options`
                    WindowsOpenFlags.CreateOptions.init(
                        &.{ .FILE_SYNCHRONOUS_IO_NONALERT, .FILE_OPEN_REPARSE_POINT },
                    ).bits,
                    null,
                    0,
                );

                switch (maybe_symlink_status) {
                    .SUCCESS => {},
                    .OBJECT_NAME_INVALID => unreachable,
                    .OBJECT_NAME_NOT_FOUND,
                    .OBJECT_PATH_NOT_FOUND,
                    .NO_MEDIA_IN_DEVICE,
                    => switch (initial_flags.create_disposition) {
                        .FILE_SUPERSEDE => unreachable, // not used
                        .FILE_OPEN, .FILE_OVERWRITE => return error.FileNotFound,
                        else => unreachable,
                    },
                    .INVALID_PARAMETER => unreachable,
                    .SHARING_VIOLATION, .ACCESS_DENIED => return error.AccessDenied,
                    .PIPE_BUSY => return error.DeviceBusy,
                    .PIPE_NOT_AVAILABLE => return error.NoDevice,
                    .OBJECT_PATH_SYNTAX_BAD => unreachable,
                    .OBJECT_NAME_COLLISION => switch (initial_flags.create_disposition) {
                        .FILE_SUPERSEDE => unreachable, // not used
                        .FILE_CREATE => return error.PathAlreadyExists,
                        else => unreachable,
                    },
                    .FILE_IS_A_DIRECTORY => unreachable,
                    .NOT_A_DIRECTORY => unreachable,
                    .USER_MAPPED_FILE => return error.AccessDenied,
                    .INVALID_HANDLE => unreachable,
                    .DELETE_PENDING => {
                        // See comment in `std.os.windows.OpenFile`
                        std.Thread.sleep(std.time.ns_per_ms);
                        continue;
                    },
                    else => return std.os.windows.unexpectedStatus(maybe_symlink_status),
                }

                errdefer std.os.windows.CloseHandle(maybe_symlink_handle);

                const create_file_status = struct {
                    const FILE_SUPERSEDED = 0x0000_0000;
                    const FILE_OPENED = 0x0000_0001;
                    const FILE_CREATED = 0x0000_0002;
                    const FILE_OVERWRITTEN = 0x0000_0003;
                    const FILE_EXISTS = 0x0000_0004;
                    const FILE_DOES_NOT_EXIST = 0x0000_0005;
                };

                // `ReOpenFile` in `kernel32` could be used here, it doesn't support truncation flags used
                // in `path_open`, but manually handling truncation happens anyway to avoid TOCTOU.
                switch (maybe_symlink_io.Information) {
                    // assumed to be caught in error handling paths above
                    create_file_status.FILE_EXISTS, create_file_status.FILE_DOES_NOT_EXIST => unreachable,
                    create_file_status.FILE_SUPERSEDED => unreachable,
                    create_file_status.FILE_OPENED => {
                        // Check for symlink
                        log.err("windows accessSubPath check for symlink for path {f}", .{path});
                        return Error.Unimplemented; // Stub
                    },
                    create_file_status.FILE_CREATED => {
                        // Change permissions of created file
                        if (true) {
                            log.err("windows accessSubPath ReOpenFile {f}", .{path});
                            return Error.Unimplemented; // Stub
                        }

                        break :opened maybe_symlink_handle;
                    },
                    create_file_status.FILE_OVERWRITTEN => unreachable,
                    else => |bad| {
                        if (std.posix.unexpected_error_tracing) {
                            std.debug.print(
                                "Unexpected IoStatusBlock.Information=0x{x}\n",
                                .{bad},
                            );
                            std.debug.dumpCurrentStackTrace(@returnAddress());
                        }

                        return error.Unexpected;
                    },
                }

                comptime unreachable;
            }

            // END UNFINISHED CODE
        };

        return @call(.auto, doInPath, .{new_fd} ++ do_in_path_args_without_fd);
    } else {
        std.debug.assert(!initial_o_flags.NOFOLLOW);
        const o_flags_no_follow: std.posix.O = flags: {
            var o_flags = initial_o_flags;
            o_flags.NOFOLLOW = true;
            break :flags o_flags;
        };

        errdefer |e| log.err("OS error {t} opening {f}", .{ e, path });

        const final_name_z = if (final_name) |b| try path_arena.allocator().dupeZ(u8, b) else ".";

        const new_fd = std.posix.openatZ(
            final_dir.fd,
            final_name_z,
            o_flags_no_follow,
            0,
        ) catch |e| return switch (e) {
            error.AntivirusInterference,
            error.SharingViolation,
            error.NetworkNotFound,
            error.PipeBusy,
            => unreachable, // Windows-only
            error.FileLocksNotSupported => unreachable,
            error.SymLinkLoop => {
                log.err("TODO: final path component of {f} was a symlink", .{path});
                return error.Unimplemented;
            },
            error.Canceled => unreachable,
            else => |err| err,
        };

        coz.progressNamed("wasmstint.WasiPreview1.accessSubPath-openat");
        return @call(.auto, doInPath, .{new_fd} ++ do_in_path_args_without_fd);
    }
}

/// Allows safely accessing a path below the directory.
///
/// - On Linux, this can be implemented with the `openat2` system call, which is what is used
///   to implement [WASI support in `wasmtime`].
/// - On FreeBSD, this could probably be done with `O_RESOLVE_BENEATH` and `openat`.
///
/// [WASI support in `wasmtime`]: https://docs.rs/cap-primitives/3.4.4/src/cap_primitives/rustix/linux/fs/open_impl.rs.html
fn accessSubPath(
    dir: std.Io.Dir,
    /// Used for temporary allocations of file paths.
    scratch: *ArenaAllocator,
    flags: types.LookupFlags.Valid,
    /// The path the guest wants to access.
    ///
    /// Attempts to navigate outside the handle (e.g. with `../` or symlinks) are caught.
    path: Path,
    set_open_flags_args: anytype,
    comptime setOpenFlags: SetOpenFlags(@TypeOf(set_open_flags_args)),
    do_in_path_args: anytype,
    /// Function that performs the operation on the path.
    ///
    /// The first argument is an open file descriptor/handle referring to the target of `path`.
    ///
    /// This function is responsible for closing the opened file descriptor/handle.
    comptime doInPath: anytype,
) Error!AccessSubPathReturnType(@TypeOf(doInPath)) {
    var coz_begin = coz.begin("wasmstint.WasiPreview1.host_dir.accessSubPath");
    defer coz_begin.end();

    fallback: switch (builtin.os.tag) {
        .linux => {
            // Currently always succeeds
            if (!@hasField(std.os.linux.SYS, "openat2")) {
                break :fallback;
            }

            const supports_openat2 = comptime builtin.os.isAtLeast(
                .linux,
                std.SemanticVersion{ .major = 5, .minor = 6, .patch = 0 },
            );

            return accessSubPathLinux(
                dir,
                scratch,
                flags,
                path,
                set_open_flags_args,
                setOpenFlags,
                do_in_path_args,
                doInPath,
            ) catch |e| switch (e) {
                error.NoOpenAt2 => {
                    @branchHint(
                        if (supports_openat2 == true)
                            .cold
                        else if (supports_openat2 == false)
                            .likely
                        else
                            .none,
                    );

                    break :fallback;
                },
                else => |err| err,
            };
        },
        // .freebsd => {},
        else => {},
    }

    return accessSubPathPortable(
        dir,
        scratch,
        flags,
        path,
        set_open_flags_args,
        setOpenFlags,
        do_in_path_args,
        doInPath,
    );
}

fn pathFileStatGetFlags() SetOpenFlagsError!OsOpenFlags {
    if (builtin.os.tag == .windows) {
        return WindowsOpenFlags{
            .access_mask = host_os.windows.AccessMask.init(&.{
                .STANDARD_RIGHTS_READ,
                .FILE_READ_ATTRIBUTES,
            }),
            .create_disposition = .FILE_OPEN,
            .create_options = host_os.windows.CreateOptions.zero,
        };
    } else {
        var flags = std.posix.O{
            .ACCMODE = .RDONLY,
            .CLOEXEC = true,
        };

        if (@hasField(std.posix.O, "PATH")) {
            flags.PATH = true;
        }

        return flags;
    }
}

fn pathFileStatGet(
    new_fd: std.posix.fd_t,
    scratch: *ArenaAllocator,
    path: Path,
    device_hash_seed: types.Device.HashSeed,
    inode_hash_seed: types.INode.HashSeed,
) Error!types.FileStat {
    defer std.posix.close(new_fd);
    _ = scratch;
    const stat: types.FileStat = try host_os.fileStat(new_fd, device_hash_seed, inode_hash_seed);
    log.debug("path_filestat_get {f} -> {f}", .{ path, stat });
    return stat;
}

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
        .{},
        pathFileStatGetFlags,
        .{ device_hash_seed, inode_hash_seed },
        pathFileStatGet,
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

fn pathOpenFlags(
    open_flags: types.OpenFlags.Valid,
    rights: types.Rights.Valid,
    fd_flags: types.FdFlags.Valid,
) SetOpenFlagsError!OsOpenFlags {
    try open_flags.check();
    if (builtin.os.tag == .windows) {
        // No effect for regular files on linux.
        // POSIX says behavior on regular files is unspecified.
        // Windows doesn't really have an equivalent to `O_NONBLOCK` anyways.
        _ = fd_flags.nonblock;

        if (fd_flags.dsync or fd_flags.rsync or fd_flags.sync) {
            log.err("unsupported fdflags {f} on windows", .{fd_flags});
            return Error.NotSupported; // `Errno.notsup` for unsupported flags
        }

        const init_flags = &.{ .STANDARD_RIGHTS_READ, .FILE_TRAVERSE };
        const write_flags = host_os.windows.AccessMask.init(&.{
            .STANDARD_RIGHTS_WRITE,
            if (fd_flags.append) .FILE_APPEND_DATA else .FILE_WRITE_DATA,
        });

        return WindowsOpenFlags{
            .access_mask = host_os.windows.AccessMask.init(init_flags)
                .setConditional(rights.canWrite(), write_flags)
                .setFlagConditional(rights.fd_read, .FILE_READ_DATA)
                .setFlagConditional(rights.fd_sync, .SYNCHRONIZE)
                .setFlagConditional(rights.fd_filestat_get, .FILE_READ_ATTRIBUTES)
                .setFlagConditional(rights.fd_filestat_set_size or rights.fd_filestat_set_times, .FILE_WRITE_ATTRIBUTES)
                .setFlagConditional(rights.fd_readdir, .FILE_LIST_DIRECTORY),
            // TODO: Does this handle trunc correctly?
            .create_disposition = if (open_flags.creat and open_flags.excl)
                .FILE_CREATE
            else if (open_flags.creat)
                if (open_flags.trunc) .FILE_OVERWRITE_IF else .FILE_OPEN_IF
            else if (open_flags.excl)
                unreachable
            else if (open_flags.trunc)
                .FILE_OVERWRITE
            else
                .FILE_OPEN,
            .create_options = host_os.windows.CreateOptions.init(&.{
                .FILE_SYNCHRONOUS_IO_NONALERT,
                .FILE_OPEN_FOR_BACKUP_INTENT,
            }).setFlagConditional(open_flags.directory, .FILE_DIRECTORY_FILE),
        };
    } else {
        var o_flags = fd_flags.toFlagsPosix() catch return error.NotSupported;
        open_flags.setPosixFlags(&o_flags);

        if (@hasField(std.posix.O, "CLOEXEC")) o_flags.CLOEXEC = true;
        if (@hasField(std.posix.O, "LARGEFILE")) o_flags.LARGEFILE = true;
        if (@hasField(std.posix.O, "NOCTTY")) o_flags.NOCTTY = true;
        if (@hasField(std.posix.O, "LARGEFILE")) o_flags.LARGEFILE = true;

        if (!open_flags.directory) {
            // TODO: Darn, need to figure out if directory or file! (fstatat?)
            o_flags.ACCMODE = if (rights.canWrite()) .RDWR else .RDONLY;
        }

        return o_flags;
    }
}

fn pathOpen(
    new_fd: std.posix.fd_t,
    scratch: *ArenaAllocator,
    path: Path,
    allocator: Allocator,
    open_flags: types.OpenFlags.Valid,
    rights: types.Rights.Valid,
) Error!File.OpenedPath {
    errdefer std.posix.close(new_fd);
    _ = scratch;
    const opened_msg = "successfully opened file {f}";
    if (builtin.os.tag == .windows) {
        if (!open_flags.directory) {
            var io: std.os.windows.IO_STATUS_BLOCK = undefined;
            var info: std.os.windows.FILE_BASIC_INFORMATION = undefined;
            const status = host_os.windows.ntQueryInformationFile(
                new_fd,
                &io,
                .FileBasicInformation,
                &info,
            );

            switch (status) {
                .SUCCESS, .BUFFER_OVERFLOW => {},
                .INFO_LENGTH_MISMATCH => unreachable,
                .ACCESS_DENIED => return error.AccessDenied,
                else => return std.os.windows.unexpectedStatus(status),
            }

            if (info.FileAttributes & std.os.windows.FILE_ATTRIBUTE_DIRECTORY == 0) {
                log.debug(opened_msg, .{path});
                return File.OpenedPath{
                    .file = host_file.wrapFile(std.Io.File{ .handle = new_fd }, .close),
                    .rights = rights.intersection(host_file.possible_rights),
                };
            }
        }
    } else if (@hasDecl(std.posix.system, "O") and std.posix.O != void) {
        if (!open_flags.directory) {
            // TODO: On linux, use statx to determine if directory
            const stat = std.posix.fstat(new_fd) catch |e| switch (e) {
                error.Canceled, error.Streaming => unreachable,
                else => |err| return err,
            };

            if (types.FileType.fromPosixMode(stat.mode) catch .unknown != .directory) {
                log.debug(opened_msg, .{path});
                return File.OpenedPath{
                    .file = host_file.wrapFile(std.Io.File{ .handle = new_fd }, .close),
                    .rights = rights.intersection(host_file.possible_rights),
                };
            }
        }
    } else {
        @compileError("path_open impl for " ++ @tagName(builtin.os.tag));
    }

    log.debug("successfully opened directory {f}", .{path});
    const as_dir = std.Io.Dir{ .handle = new_fd };
    return init(as_dir, allocator, rights);
}

fn path_open(
    ctx: Ctx,
    allocator: Allocator,
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
        pathOpenFlags,
        .{ allocator, open_flags, rights },
        pathOpen,
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
    .fd_filestat_get = fd_filestat_get,
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
const host_os = @import("../host_os.zig");
const types = @import("../types.zig");
const pointer = @import("wasmstint").pointer;
const PreopenDir = @import("../PreopenDir.zig");
const Path = @import("../Path.zig");
const File = @import("../File.zig");
const Error = File.Error;
const Ctx = File.Ctx;
const host_file = @import("host_file.zig");
const coz = @import("coz");
