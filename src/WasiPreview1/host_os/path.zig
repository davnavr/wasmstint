pub const Char = if (host_os.is_windows) u16 else u8;

fn Literal(comptime wtf8: [:0]const u8) type {
    if (host_os.is_windows) {
        const len = std.unicode.calcUtf16LeLen(wtf8) catch |e|
            @compileError("invalid path literal: " ++ @tagName(e));

        return *const [len:0]u16;
    } else {
        return *const [wtf8.len:0]u8;
    }
}

pub fn literal(comptime wtf8: [:0]const u8) Literal(wtf8) {
    if (host_os.is_windows) {
        return std.unicode.utf8ToUtf16LeStringLiteral(wtf8);
    } else {
        if (comptime !std.unicode.utf8ValidateSlice(wtf8)) {
            @compileError(std.fmt.comptimePrint("invalid WTF-8 path: {X}", .{wtf8}));
        } else {
            return wtf8[0..wtf8.len :0];
        }
    }
}

pub fn eql(a: []const Char, b: []const Char) bool {
    return std.mem.eql(Char, a, b);
}

pub fn isSeparator(c: Char) bool {
    return if (host_os.is_windows and c == '\\') true else c == '/';
}

/// Represents an arbitrary null-terminated byte sequence on Unix-like systems, or a WTF-16 encoded
/// string on Windows.
pub const Slice = if (host_os.is_windows) []const u16 else [:0]const u8;

/// Like `Slice`, but has a null terminator on Windows.
///
/// Some Windows API functions may require null-terminated wide strings, while others accept an
/// explicit length instead.
///
/// On Unix-like systems, paths always have null terminators anyway.
pub const SliceZ = [:0]const Char;

pub const Ptr = if (host_os.is_windows) [*]const u8 else [*:0]const u8;

pub const AllocMode = enum { alloc_always, alloc_windows };

const AllocError = Allocator.Error || error{
    /// Windows-only.
    InvalidWtf8,
};

/// Converts a null-terminated byte path to a `Slice`.
///
/// Is a no-op on Unix-like sytems when `mode == .alloc_windows`.
pub fn allocFromBytesZ(path: [:0]const u8, mode: AllocMode, alloc: Allocator) AllocError!SliceZ {
    return if (host_os.is_windows)
        std.unicode.wtf8ToWtf16LeAllocZ(alloc, path)
    else switch (mode) {
        .alloc_windows => path,
        .alloc_always => alloc.dupeZ(u8, path),
    };
}

pub fn format(path: Slice, writer: *std.Io.Writer) std.Io.Writer.Error!void {
    try writer.print(
        "{f}",
        .{if (host_os.is_windows) std.unicode.fmtUtf16Le(path) else std.unicode.fmtUtf8(path)},
    );
}

pub fn fmt(path: Slice) std.fmt.Alt(Slice, format) {
    return .{ .data = path };
}

const std = @import("std");
const Allocator = std.mem.Allocator;
const host_os = @import("../host_os.zig");
