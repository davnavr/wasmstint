//! Wrappers over Linux-specific ABIs.
//!
//! See the `unix_like` modules for wrappers over POSIX/Unix-like ABIs instead.

pub const Fd = system.fd_t;
pub const Errno = std.os.linux.E;

pub const DT = dt: {
    const src_decls = @typeInfo(std.os.linux.DT).@"struct".decls;
    break :dt @Enum(
        u8,
        .nonexhaustive,
        names: {
            var names: [src_decls.len][]const u8 = undefined;
            for (src_decls, &names) |src, *n| {
                n.* = src.name;
            }
            break :names &names;
        },
        values: {
            var values: [src_decls.len]u8 = undefined;
            for (src_decls, &values) |src, *v| {
                v.* = @field(std.os.linux.DT, src.name);
            }
            break :values &values;
        },
    );
};

const statx_available = builtin.os.isAtLeast(.linux, .{ .major = 4, .minor = 11, .patch = 0 });

/// Used when marking branches where `statx` is unavailable.
const hint_statx_unavailable: std.builtin.BranchHint = if (statx_available == true)
    .unlikely
else if (statx_available == false)
    .likely
else
    .none;

/// https://github.com/ziglang/zig/issues/23514
var has_statx = std.atomic.Value(bool).init(true);

pub const StatxFlags = packed struct(c_int) {
    _0: u8 = 0,
    SYMLINK_NOFOLLOW: bool = false,
    _9: u2 = 0,
    NO_AUTOMOUNT: bool = false,
    EMPTY_PATH: bool = false,
    SYNC: Sync = .AS_STAT,
    _15: u16 = 0,
    RESERVED: Reserved = .reserved,

    pub const Sync = enum(u2) {
        AS_STAT = 0b00,
        FORCE = 0b01,
        DONT = 0b10,
    };

    pub const Reserved = enum(u1) { reserved = 0 };

    test "known fields" {
        inline for (@typeInfo(system.AT).@"struct".decls) |decl| {
            if (@hasField(StatxFlags, decl.name)) {
                const expected: u32 = @field(system.AT, decl.name);
                var actual = StatxFlags{};
                @field(actual, decl.name) = true;
                const actual_bits: u32 = @bitCast(actual);
                try std.testing.expectEqual(expected, actual_bits);
            }
        }
    }

    test "sync" {
        try std.testing.expectEqual(
            system.AT.STATX_SYNC_AS_STAT,
            @as(u32, @bitCast(StatxFlags{ .SYNC = .AS_STAT })),
        );
        try std.testing.expectEqual(
            system.AT.STATX_FORCE_SYNC,
            @as(u32, @bitCast(StatxFlags{ .SYNC = .FORCE })),
        );
        try std.testing.expectEqual(
            system.AT.STATX_DONT_SYNC,
            @as(u32, @bitCast(StatxFlags{ .SYNC = .DONT })),
        );
    }
};

pub const StatxMask = packed struct(c_uint) {
    TYPE: bool = false,
    MODE: bool = false,
    NLINK: bool = false,
    UID: bool = false,
    GID: bool = false,
    ATIM: bool = false,
    MTIM: bool = false,
    CTIM: bool = false,
    INO: bool = false,
    SIZE: bool = false,
    _10: u22 = 0,
};

pub const StatxError = std.posix.UnexpectedError || error{
    StatxNotSupported,
    /// Some fields that were requested could not be provided.
    MissingRequestedFields,
    AccessDenied,
    SymLinkLoop,
    NameTooLong,
    DirNotFound,
    SystemResources,
    NotDir,
};

/// Note that Zig currently does not expose the glibc wrapper for `statx`.
///
/// Since glibc 2.28.
pub fn statx(
    dir: Fd,
    path: [:0]const u8,
    flags: StatxFlags,
    mask: StatxMask,
    buf: *system.Statx,
) StatxError!void {
    if (!has_statx.load(.unordered)) {
        @branchHint(hint_statx_unavailable);
        return error.StatxNotSupported;
    }

    buf.* = undefined;
    const result = system.statx(dir, path, @bitCast(flags), @bitCast(mask), buf);
    const requested_mask = @as(u32, @bitCast(mask));
    switch (std.os.linux.errno(result)) {
        .SUCCESS => if (buf.mask & requested_mask != requested_mask) {
            return error.MissingRequestedFields;
        },
        .NOSYS => {
            @branchHint(hint_statx_unavailable);
            has_statx.store(false, .monotonic);
            return error.StatxNotSupported;
        },
        .ACCES => return error.AccessDenied,
        .BADF => unreachable, // kernel expected absolute path
        .FAULT => unreachable,
        .INVAL => unreachable, // bad flags (or mask reserved bit was set)
        .LOOP => return error.SymLinkLoop,
        .NAMETOOLONG => return error.NameTooLong,
        .NOENT => {
            std.debug.assert(!(@min(path.len, std.mem.len(path.ptr)) == 0 and !flags.EMPTY_PATH));
            return error.DirNotFound;
        },
        .NOMEM => return error.SystemResources,
        .NOTDIR => return error.NotDir,
        else => |bad| return std.posix.unexpectedErrno(bad),
    }
}

const std = @import("std");
const builtin = @import("builtin");
const system = std.os.linux;

test {
    _ = StatxFlags;
}
