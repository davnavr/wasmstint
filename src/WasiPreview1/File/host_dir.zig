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
            .iter = preopen.dir.iterate(),
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
    dir: std.fs.Dir,
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
            .iter = dir.iterate(),
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
    try host_file.closeHandle(self.dir.fd);
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
    access_mask: AccessMask,
    comptime file_attributes: std.os.windows.ULONG = std.os.windows.FILE_ATTRIBUTE_NORMAL,
    share_access: ShareAccess = share_access_default,
    create_disposition: CreateDisposition,
    create_options: CreateOptions,

    const share_access_default = ShareAccess.init(
        &.{ .FILE_SHARE_READ, .FILE_SHARE_WRITE, .FILE_SHARE_DELETE },
    );

    fn Mask(comptime ValidFlags: type) type {
        return packed struct(u32) {
            bits: std.os.windows.ULONG,

            const Valid = ValidFlags;
            const Self = @This();

            const zero = Self{ .bits = 0 };

            fn init(flags: []const Valid) Self {
                var mask = Self.zero;
                for (flags) |f| {
                    switch (f) {
                        inline else => |tag| mask.bits |= @field(std.os.windows, @tagName(tag)),
                    }
                }
                return mask;
            }

            fn set(mask: Self, others: Self) Self {
                return Self{ .bits = mask.bits | others.bits };
            }

            fn setFlag(mask: Self, flag: Valid) Self {
                return mask.set(Self.init(&.{flag}));
            }

            fn setConditional(a: Self, condition: bool, b: Self) Self {
                return if (condition) a.set(b) else a;
            }

            fn setFlagConditional(mask: Self, condition: bool, flag: Valid) Self {
                return mask.setConditional(condition, Self.init(&.{flag}));
            }

            fn without(mask: Self, removed: Self) Self {
                return Self{ .bits = mask.bits & (~removed.bits) };
            }

            fn contains(a: Self, b: Self) bool {
                return a.bits | b.bits == a.bits;
            }

            fn containsFlag(mask: Self, flag: Valid) bool {
                return mask.contains(Self.init(&.{flag}));
            }
        };
    }

    /// https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/access-mask
    const AccessMask = Mask(enum {
        DELETE,
        FILE_READ_DATA,
        FILE_READ_ATTRIBUTES,
        FILE_WRITE_DATA,
        FILE_WRITE_ATTRIBUTES,
        FILE_APPEND_DATA,
        FILE_GENERIC_READ,
        FILE_GENERIC_WRITE,
        FILE_LIST_DIRECTORY,
        FILE_TRAVERSE,
        STANDARD_RIGHTS_READ,
        STANDARD_RIGHTS_WRITE,
        SYNCHRONIZE,
    });

    const ShareAccess = Mask(enum {
        FILE_SHARE_READ,
        FILE_SHARE_WRITE,
        FILE_SHARE_DELETE,
    });

    const CreateDisposition = @Type(std.builtin.Type{
        .@"enum" = std.builtin.Type.Enum{
            .tag_type = std.os.windows.ULONG,
            .decls = &.{},
            .is_exhaustive = true,
            .fields = fields: {
                const options = [_][:0]const u8{
                    "FILE_SUPERSEDE",
                    "FILE_CREATE",
                    "FILE_OPEN",
                    "FILE_OPEN_IF",
                    "FILE_OVERWRITE",
                    "FILE_OVERWRITE_IF",
                };

                var fields: [options.len]std.builtin.Type.EnumField = undefined;
                for (options, &fields) |name, *dst| {
                    dst.* = std.builtin.Type.EnumField{
                        .name = name,
                        .value = @field(std.os.windows, name),
                    };
                }

                break :fields &fields;
            },
        },
    });

    const CreateOptions = Mask(enum {
        FILE_DIRECTORY_FILE,
        FILE_NON_DIRECTORY_FILE,
        FILE_WRITE_THROUGH,
        FILE_SEQUENTIAL_ONLY,
        FILE_RANDOM_ACCESS,
        FILE_NO_INTERMEDIATE_BUFFERING,
        FILE_SYNCHRONOUS_IO_NONALERT,
        FILE_OPEN_REPARSE_POINT,
        /// Required for opening directories.
        FILE_OPEN_FOR_BACKUP_INTENT,
    });
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

const todo_openat2_on_linux_is_not_yet_supported = true; // TODO

/// https://man7.org/linux/man-pages/man2/openat2.2.html
fn accessSubPathLinux(
    dir: std.fs.Dir,
    scratch: *ArenaAllocator,
    flags: types.LookupFlags.Valid,
    path: Path,
    args: anytype,
    comptime setOpenFlags: SetOpenFlags(@TypeOf(args)),
    comptime doInPath: anytype,
) (error{NoSysOpenat2} || Error)!@typeInfo(doInPath).@"fn".return_type.? {
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
    _ = setOpenFlags;
    _ = rc;
}

// FreeBSD also supports `O_RESOLVE_BENEATH` in openat
//fn accessSubPathFreeBsd()

fn AccessSubPathReturnType(comptime Accessor: type) type {
    return @typeInfo(@typeInfo(Accessor).@"fn".return_type.?).error_union.payload;
}

/// Depends on the host OS having a way to open a path relative to an opened directory handle/fd
/// while also indicating if a symlink would have been opened.
fn accessSubPathPortable(
    dir: std.fs.Dir,
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
    var final_dir = dir;
    if (initial_components.len > 1) {
        for (0.., initial_components[0 .. initial_components.len - 1]) |i, comp| {
            var old_dir = final_dir;
            defer if (i > 0 and i < initial_components.len - 1) {
                // log.debug("closing intermediate directory {any}", .{old_dir.fd});
                old_dir.close();
            };

            const comp_bytes = comp.bytes(path);
            const comp_str = if (builtin.os.tag == .windows)
                std.unicode.utf8ToUtf16LeAllocZ(
                    path_arena.allocator(),
                    comp_bytes,
                ) catch |e| switch (e) {
                    error.InvalidUtf8 => unreachable,
                    error.OutOfMemory => |oom| return oom,
                }
            else
                try path_arena.allocator().dupeZ(u8, comp_bytes);

            // TODO: Use O_PATH on Linux, requires using platform-specific APIs

            const zigOpenDir = if (builtin.os.tag == .windows)
                std.fs.Dir.openDirW
            else
                std.fs.Dir.openDirZ;

            final_dir = zigOpenDir(
                old_dir,
                comp_str,
                std.fs.Dir.OpenOptions{
                    .access_sub_paths = true,
                    // TODO(zig): no_follow weird on windows https://github.com/ziglang/zig/issues/18335
                    .no_follow = true,
                },
            ) catch |e| return switch (e) {
                // error.NotDir might happen on windows because a symlink is obviously not a directory
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
                error.InvalidUtf8, error.InvalidWtf8 => unreachable,
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

        const win = struct {
            extern "ntdll" fn NtDuplicateObject(
                SourceProcessHandle: std.os.windows.HANDLE,
                SourceHandle: std.os.windows.HANDLE,
                TargetProcessHandle: ?std.os.windows.HANDLE,
                TargetHandle: ?*std.os.windows.HANDLE,
                DesiredAccess: std.os.windows.ACCESS_MASK,
                HandleAttributes: std.os.windows.ULONG,
                Options: std.os.windows.ULONG,
            ) callconv(.winapi) std.os.windows.NTSTATUS;

            const DUPLICATE_SAME_ATTRIBUTES = 0x0000_0004;

            const OBJ_DONT_REPARSE = 0x0000_1000;

            const STATUS_REPARSE_POINT_ENCOUNTERED: std.os.windows.NTSTATUS =
                @enumFromInt(0xC000_050B);
        };

        errdefer log.err("failed to open final component in {f}", .{path});

        // `NtCreateFile` doesn't seem to support "." or ".\\" as a path to the `final_dir`
        const final_name_bytes = final_name orelse {
            @branchHint(.unlikely);
            const current_process = std.os.windows.GetCurrentProcess();
            var new_fd: std.os.windows.HANDLE = undefined;
            const result = win.NtDuplicateObject(
                current_process,
                final_dir.fd,
                current_process,
                &new_fd,
                initial_flags.access_mask.bits,
                undefined,
                win.DUPLICATE_SAME_ATTRIBUTES,
            );

            return switch (result) {
                .SUCCESS => @call(.auto, doInPath, .{new_fd} ++ do_in_path_args_without_fd),
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

        var final_name_unicode = std.os.windows.UNICODE_STRING{
            // Lengths are in bytes, excluding null-terminator
            .Length = @intCast(final_name_w.len * 2),
            .MaximumLength = @intCast(final_name_w.len * 2),
            .Buffer = final_name_w.ptr,
        };

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

        const create_file_status = struct {
            const FILE_SUPERSEDED = 0x0000_0000;
            const FILE_OPENED = 0x0000_0001;
            const FILE_CREATED = 0x0000_0002;
            const FILE_OVERWRITTEN = 0x0000_0003;
            const FILE_EXISTS = 0x0000_0004;
            const FILE_DOES_NOT_EXIST = 0x0000_0005;
        };

        const new_fd: std.fs.File.Handle = if (has_obj_dont_reparse == true) opened: {
            var attrs = std.os.windows.OBJECT_ATTRIBUTES{
                .Length = @sizeOf(std.os.windows.OBJECT_ATTRIBUTES),
                .RootDirectory = final_dir.fd,
                .ObjectName = &final_name_unicode,
                .Attributes = win.OBJ_DONT_REPARSE,
                .SecurityDescriptor = null,
                .SecurityQualityOfService = null,
            };

            // Recreates some logic for `std.os.windows.OpenFile`
            while (true) {
                var opened_handle: std.fs.File.Handle = undefined;
                var io: std.os.windows.IO_STATUS_BLOCK = undefined;
                const status = std.os.windows.ntdll.NtCreateFile(
                    &opened_handle,
                    initial_flags.access_mask.bits,
                    &attrs,
                    &io,
                    null,
                    std.os.windows.FILE_ATTRIBUTE_NORMAL,
                    initial_flags.share_access.bits,
                    @intFromEnum(initial_flags.create_disposition),
                    initial_flags.create_options.bits,
                    null,
                    0,
                );
                switch (status) {
                    .SUCCESS => break :opened opened_handle,
                    win.STATUS_REPARSE_POINT_ENCOUNTERED => {
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
            error.InvalidWtf8, error.NetworkNotFound => unreachable, // Windows-only
            error.FileLocksNotSupported => unreachable,
            error.SymLinkLoop => {
                log.err("TODO: final path component of {f} was a symlink", .{path});
                return error.Unimplemented;
            },
            else => |err| err,
        };

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
    dir: std.fs.Dir,
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
                set_open_flags_args,
                setOpenFlags,
                do_in_path_args,
                doInPath,
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
            .access_mask = WindowsOpenFlags.AccessMask.init(&.{
                .STANDARD_RIGHTS_READ,
                .FILE_READ_ATTRIBUTES,
            }),
            .create_disposition = .FILE_OPEN,
            .create_options = WindowsOpenFlags.CreateOptions.zero,
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
    // Some duplicate code with `host_file.fd_fdstat_get`
    const stat: types.FileStat = if (builtin.os.tag == .windows) stat: {
        // Kernel32 equivalent is `GetFileInformationByHandle`

        // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_stat_lx_information
        // Want to use `FILE_STAT_LX_INFORMATION`, but it is pretty new
        // - No `std.os.windows.FILE_STAT_LX_INFORMATION` in Zig standard library
        // - Introduced as part of WSL
        // - Available since Windows 10 update 1803
        // TODO: Include check and fallback path for builtin version `.win10_rs4` (does invalid class mean INVALID_PARAMETER?)

        const file_all_info = info: {
            var io: std.os.windows.IO_STATUS_BLOCK = undefined;
            var info: std.os.windows.FILE_ALL_INFORMATION = undefined;
            const status = std.os.windows.ntdll.NtQueryInformationFile(
                new_fd,
                &io,
                &info,
                @sizeOf(@TypeOf(info)),
                .FileAllInformation,
            );
            switch (status) {
                .SUCCESS, .BUFFER_OVERFLOW => break :info info,
                .INFO_LENGTH_MISMATCH => unreachable,
                .ACCESS_DENIED => return error.AccessDenied,
                else => return std.os.windows.unexpectedStatus(status),
            }
        };

        // Can't use `FILE_FS_OBJECTID_INFORMATION`, since 16-byte GUID can't fit in 64-bit dev #
        const fs_volume_info = info: {
            var io: std.os.windows.IO_STATUS_BLOCK = undefined;
            var info: std.os.windows.FILE_FS_VOLUME_INFORMATION = undefined;
            const status = std.os.windows.ntdll.NtQueryVolumeInformationFile(
                new_fd,
                &io,
                &info,
                @sizeOf(@TypeOf(info)),
                .FileFsVolumeInformation,
            );
            switch (status) {
                .SUCCESS, .BUFFER_OVERFLOW => break :info info,
                .INVALID_PARAMETER => unreachable,
                .ACCESS_DENIED => return error.AccessDenied,
                else => return std.os.windows.unexpectedStatus(status),
            }
        };

        break :stat types.FileStat{
            .dev = types.Device.init(device_hash_seed, fs_volume_info.VolumeSerialNumber),
            .ino = types.INode.init(
                inode_hash_seed,
                @bitCast(file_all_info.InternalInformation.IndexNumber),
            ),
            .type = if (file_all_info.StandardInformation.Directory != 0)
                .directory
            else
                .regular_file,
            .nlink = file_all_info.StandardInformation.NumberOfLinks,
            .size = types.FileSize{
                .bytes = @bitCast(file_all_info.StandardInformation.AllocationSize),
            },
            // WASI doesn't seem to specify the meaning of the timestamps here.
            // The Windows times are relative to system time, in 100-ns intervals.
            .atim = types.Timestamp.fromWindowsSystemTimeRelative(
                file_all_info.BasicInformation.LastAccessTime,
            ),
            .mtim = types.Timestamp.fromWindowsSystemTimeRelative(
                file_all_info.BasicInformation.LastWriteTime,
            ),
            .ctim = types.Timestamp.fromWindowsSystemTimeRelative(
                file_all_info.BasicInformation.ChangeTime,
            ),
        };
    } else stat: {
        // TODO: Use statx "." NOFOLLOW on Linux
        const stat = try std.posix.fstat(new_fd);
        break :stat types.FileStat.fromPosixStat(&stat, device_hash_seed, inode_hash_seed);
    };

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
        const write_flags = WindowsOpenFlags.AccessMask.init(&.{
            .STANDARD_RIGHTS_WRITE,
            if (fd_flags.append) .FILE_APPEND_DATA else .FILE_WRITE_DATA,
        });

        return WindowsOpenFlags{
            .access_mask = WindowsOpenFlags.AccessMask.init(init_flags)
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
            .create_options = WindowsOpenFlags.CreateOptions.init(&.{
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
            const status = std.os.windows.ntdll.NtQueryInformationFile(
                new_fd,
                &io,
                &info,
                @sizeOf(@TypeOf(info)),
                .FileBasicInformation,
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
                    .file = host_file.wrapFile(std.fs.File{ .handle = new_fd }, .close),
                    .rights = rights.intersection(host_file.possible_rights),
                };
            }
        }
    } else if (@hasDecl(std.posix.system, "O") and std.posix.O != void) {
        if (!open_flags.directory) {
            const as_file = std.fs.File{ .handle = new_fd };
            const kind = (try as_file.stat()).kind;
            switch (kind) {
                .directory => {},
                else => {
                    log.debug(opened_msg, .{path});
                    return File.OpenedPath{
                        .file = host_file.wrapFile(as_file, .close),
                        .rights = rights.intersection(host_file.possible_rights),
                    };
                },
            }
        }
    } else {
        @compileError("path_open impl for " ++ @tagName(builtin.os.tag));
    }

    log.debug("successfully opened directory {f}", .{path});
    const as_dir = std.fs.Dir{ .fd = new_fd };
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
const types = @import("../types.zig");
const pointer = @import("wasmstint").pointer;
const PreopenDir = @import("../PreopenDir.zig");
const Path = @import("../Path.zig");
const File = @import("../File.zig");
const Error = File.Error;
const Ctx = File.Ctx;
const host_file = @import("host_file.zig");
