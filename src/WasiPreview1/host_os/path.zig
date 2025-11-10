/// Represents an arbitrary null-terminated byte sequence on Unix-like systems, or a WTF-16 encoded
/// string on Windows.
pub const Slice = if (host_os.is_windows) []const u16 else [:0]const u8;

pub const Ptr = if (host_os.is_windows) [*]const u8 else [*:0]const u8;

pub const AllocMode = enum { alloc_always, alloc_windows };

const AllocError = Allocator.Error || error{
    /// Windows-only.
    InvalidWtf8,
};

/// Converts a null-terminated byte path to a `Slice`.
///
/// Is a no-op on Unix-like sytems when `mode == .alloc_windows`.
pub fn allocFromBytesZ(path: [:0]const u8, mode: AllocMode, alloc: Allocator) AllocError!Slice {
    return if (host_os.is_windows)
        std.unicode.wtf8ToWtf16LeAlloc(alloc, path)
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
