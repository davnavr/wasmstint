//! Unbuffered access to a real, genuine, 100% all-natural OS file descriptor.

/// Callers must ensure that `fd` is an open file handle.
pub fn wrapFile(fd: std.fs.File, rights: Rights) File {
    return .{
        .rights = rights,
        .impl = .{ .ctx = .{ .real = fd }, .vtable = &vtable },
    };
}

pub fn wrapStandardStreams() File.StandardStreams {
    const write_rights: Rights = .{ .fd_write = true };
    return .{
        .stdin = wrapFile(std.fs.File.stdin(), .{ .fd_read = true }),
        .stdout = wrapFile(std.fs.File.stdout(), write_rights),
        .stderr = wrapFile(std.fs.File.stderr(), write_rights),
    };
}

fn deinit(ctx: Ctx, allocator: std.mem.Allocator) void {
    _ = allocator;
    ctx.real.close();
}

fn fd_write(ctx: Ctx, iovs: []const File.Ciovec, total_len: u32) Error!u32 {
    if (total_len == 0) {
        return 0;
    }

    // TODO: How to handle Windows? multiple WriteFile calls?
    const written = ctx.real.writev(File.Ciovec.castSlice(iovs)) catch |e| return switch (e) {
        // Windows-specific
        error.SystemResources => error.OutOfMemory,
        error.LockViolation => error.WouldBlock,
        error.NoDevice => |bad| File.unexpectedError(bad),

        error.NotOpenForWriting => error.BadFd,
        else => |known| known,
    };

    return @intCast(written);
}

const vtable = File.VTable{
    .api = .{
        .fd_write = &fd_write,
    },
    .deinit = &deinit,
};

const std = @import("std");
const File = @import("../File.zig");
const Ctx = File.Ctx;
const Rights = File.Rights;
const Error = File.Error;
