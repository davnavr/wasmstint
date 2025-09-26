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

const vtable = File.VTable{
    .api = .{},
    .deinit = &deinit,
};

const std = @import("std");
const File = @import("../File.zig");
const Ctx = File.Ctx;
const Rights = File.Rights;
