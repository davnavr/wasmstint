//! Used to implement `random_get`.
//!
//! [`random_get`]: https://github.com/WebAssembly/WASI/blob/v0.2.7/legacy/preview1/docs.md#random_get

ctx: *anyopaque,
fill: *const fn (ctx: *anyopaque, buf: []u8) FillError!void,

const Csprng = @This();

pub const FillError = error{
    Unexpected,
    Unimplemented,

    // Subset of `std.posix.GetRandomError`
    AccessDenied,
    FileNotFound,
    IsDir,
    NotDir,
    PermissionDenied,
    ProcessFdQuotaExceeded,
    SymLinkLoop,
    SystemFdQuotaExceeded,
    SystemResources,
    WouldBlock,
};

pub fn get(csprng: Csprng, buf: []u8) FillError!void {
    return csprng.fill(csprng.ctx, buf);
}

fn osFill(_: *anyopaque, buf: []u8) FillError!void {
    return std.posix.getrandom(buf) catch |e| switch (e) {
        error.Unexpected,
        error.AccessDenied,
        error.IsDir,
        error.NotDir,
        error.FileNotFound,
        error.ProcessFdQuotaExceeded,
        error.SymLinkLoop,
        error.SystemFdQuotaExceeded,
        error.SystemResources,
        error.WouldBlock,
        => |err| err,
        else => |unexpected| {
            if (std.posix.unexpected_error_tracing) {
                std.debug.print("unexpected getrandom error: {t}\n", .{unexpected});
            }
            return error.Unexpected;
        },
    };
}

pub const os = Csprng{
    .ctx = undefined,
    .fill = &osFill,
};

fn randomFill(ctx: *anyopaque, buf: []const u8) FillError!void {
    errdefer comptime unreachable;
    @as(*const std.Random, @ptrCast(@alignCast(@constCast(ctx)))).bytes(buf);
}

pub fn fromRandom(rng: *const std.Random) Csprng {
    return .{
        .ctx = @ptrCast(rng),
        .get = randomFill,
    };
}

const std = @import("std");
