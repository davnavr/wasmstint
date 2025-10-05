//! Implementation of a WASI file descriptor and its operations.

pub const Rights = packed struct(u60) {
    base: types.Rights.Valid,
    /// Applies to `File` descriptors that inherit from this one.
    inheriting: types.Rights.Valid,

    pub fn init(base: types.Rights.Valid) Rights {
        return .{ .base = base, .inheriting = base };
    }
};

impl: Impl,
rights: Rights,

const File = @This();

pub const Impl = struct {
    ctx: Ctx,
    vtable: *const VTable,
};

pub const Ctx = struct {
    const ctx_size = 16;

    bytes: [ctx_size]u8 align(ctx_size),

    fn checkSize(comptime T: type) void {
        if (@sizeOf(T) > ctx_size) {
            @compileError(@typeName(T) ++ " is too big");
        }
    }

    pub fn init(context: anytype) Ctx {
        const T = @TypeOf(context);
        comptime {
            checkSize(T);
        }

        var ctx = Ctx{ .bytes = undefined };
        @as(*align(ctx_size) T, @ptrCast(&ctx.bytes)).* = context;
        return ctx;
    }

    pub fn get(ctx: Ctx, comptime T: type) T {
        comptime {
            checkSize(T);
        }

        return @as(*align(ctx_size) const T, @ptrCast(&ctx.bytes)).*;
    }
};

pub const StandardStreams = struct {
    stdin: File,
    stdout: File,
    stderr: File,
};

pub const host_file = @import("File/host_file.zig");
pub const host_dir = @import("File/host_dir.zig");

pub const Ciovec = extern struct {
    inner: std.posix.iovec_const,

    pub fn init(b: []const u8) Ciovec {
        return .{
            .inner = .{ .base = b.ptr, .len = b.len },
        };
    }

    pub fn bytes(ciov: Ciovec) []const u8 {
        return ciov.inner.base[0..ciov.inner.len];
    }

    pub fn castSlice(ciovecs: []const Ciovec) []const std.posix.iovec_const {
        const casted: []const std.posix.iovec_const = @ptrCast(ciovecs);
        std.debug.assert(casted.len == ciovecs.len);
        return casted;
    }
};

pub const Error = @import("errno.zig").Error;

/// Called when an Zig `std` OS abstract returns an unexpected error.
pub fn unexpectedError(err: anyerror) std.posix.UnexpectedError {
    if (std.posix.unexpected_error_tracing) {
        std.log.err("unexpected error: {t}", .{err});
        if (@errorReturnTrace()) |trace| {
            std.debug.dumpStackTrace(trace.*);
        }
    }

    return error.Unexpected;
}

pub const invalid = struct {
    pub fn fd_prestat_get(_: Ctx) Error!types.Prestat {
        return Error.NotDir;
    }

    pub fn fd_prestat_dir_name(_: Ctx, _: []u8) Error!void {
        return Error.NotDir;
    }

    pub fn fd_readdir(
        _: Ctx,
        _: types.INode.HashSeed,
        _: []u8,
        _: types.DirCookie,
    ) Error!types.Size {
        return Error.NotDir;
    }
};

/// Do not call function pointers without checking the corresponding `File`'s `rights`.
pub const VTable = struct {
    // Could add scratch: *ArenaAllocator parameter
    fd_fdstat_get: *const fn (ctx: Ctx) Error!types.FdStat.File,
    fd_prestat_get: *const fn (ctx: Ctx) Error!types.Prestat,
    fd_prestat_dir_name: *const fn (ctx: Ctx, path: []u8) Error!void,
    fd_pwrite: *const fn (
        ctx: Ctx,
        iovs: []const Ciovec,
        offset: types.FileSize,
        total_len: u32,
    ) Error!u32,
    // fd_read
    fd_readdir: *const fn (
        ctx: Ctx,
        inode_hash_seed: types.INode.HashSeed,
        // allocator: Allocator,
        buf: []u8,
        cookie: types.DirCookie,
    ) Error!types.Size,
    fd_write: *const fn (ctx: Ctx, iovs: []const Ciovec, total_len: u32) Error!u32,
    fd_close: *const fn (ctx: Ctx, allocator: Allocator) Error!void,
};

fn hasVTable(file: *const File, vtable: *const VTable) bool {
    return @intFromPtr(file.impl.vtable) == @intFromPtr(vtable);
}

fn api(
    file: *const File,
    comptime right: Api,
    comptime func: std.meta.FieldEnum(VTable),
) error{AccessDenied}!@FieldType(VTable, @tagName(func)) {
    return if (@field(file.rights.base, @tagName(right)))
        @field(file.impl.vtable, @tagName(func))
    else
        error.AccessDenied;
}

// Is this what it's called?
const manual_function_devirtualization = switch (builtin.mode) {
    .ReleaseSafe, .ReleaseFast => true,
    .Debug, .ReleaseSmall => false,
};

pub fn fd_fdstat_get(file: *File) Error!types.FdStat {
    // No corresponding rights flag for this function.

    return .{
        .file = try file.impl.vtable.fd_fdstat_get(file.impl.ctx),
        .rights_base = types.Rights{ .valid = file.rights.base },
        .rights_inheriting = types.Rights{ .valid = file.rights.base },
    };
}

pub fn fd_prestat_get(file: *File) Error!types.Prestat {
    if (manual_function_devirtualization and file.hasVTable(&host_dir.vtable)) {
        @branchHint(.likely);
        return host_dir.fd_prestat_get(file.impl.ctx);
    } else {
        return file.impl.vtable.fd_prestat_get(file.impl.ctx);
    }
}

pub fn fd_prestat_dir_name(file: *File, path: []u8) Error!void {
    if (manual_function_devirtualization and file.hasVTable(&host_dir.vtable)) {
        @branchHint(.likely);
        return host_dir.fd_prestat_dir_name(file.impl.ctx, path);
    } else {
        return file.impl.vtable.fd_prestat_dir_name(file.impl.ctx, path);
    }
}

pub fn fd_readdir(
    file: *File,
    inode_hash_seed: types.INode.HashSeed,
    // allocator: Allocator,
    buf: []u8,
    cookie: types.DirCookie,
) Error!types.Size {
    if (!file.rights.base.fd_readdir) {
        return error.AccessDenied;
    }

    const args = .{ file.impl.ctx, inode_hash_seed, buf, cookie };
    if (manual_function_devirtualization and file.hasVTable(&host_dir.vtable)) {
        @branchHint(.likely);
        return @call(.auto, host_dir.fd_readdir, args);
    } else {
        return @call(.auto, file.impl.vtable.fd_readdir, args);
    }
}

pub fn fd_pwrite(
    file: *File,
    iovs: []const Ciovec,
    offset: types.FileSize,
    total_len: u32,
) Error!u32 {
    return (try file.api(.fd_write, .fd_pwrite))(file.impl.ctx, iovs, offset, total_len);
}

pub fn fd_write(file: *File, iovs: []const Ciovec, total_len: u32) Error!u32 {
    return (try file.api(.fd_write, .fd_write))(file.impl.ctx, iovs, total_len);
}

// pub fn fd_fdstat_set_rights(file: *File, base: Rights, inheriting: Rights) Error!void
// if padding bits set => error
// if actual rights contains (do bitwise &) rights they want => OK
// otherwise => error

pub fn fd_close(file: *File, allocator: Allocator) Error!void {
    try file.impl.vtable.fd_close(file.impl.ctx, allocator);
    file.* = undefined;
}

const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const Api = @import("api.zig").Api;
const types = @import("types.zig");
