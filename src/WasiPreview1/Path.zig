//! A UTF-8 encoded path.
//!
//! In WASI, paths are
//! [always valid UTF-8](https://github.com/WebAssembly/wasi-filesystem/issues/17).

ptr: Ptr,
len: Len,

const Path = @This();

pub const Ptr = [*]const u8;
pub const Len = u16; // Most OS's don't even allow paths to have a length this high

// TODO: Consider invalid characters (e.g. control chars, ':', '/')
// https://dwheeler.com/essays/fixing-unix-linux-filenames.html
pub fn initUtf8(path: std.unicode.Utf8View) error{PathTooLong}!Path {
    return .{
        .ptr = path.bytes.ptr,
        .len = std.math.cast(Len, path.bytes.len) orelse return error.PathTooLong,
    };
}

pub fn init(path: []const u8) error{ PathTooLong, InvalidUtf8 }!Path {
    return .initUtf8(try std.unicode.Utf8View.init(path));
}

pub fn bytes(path: Path) []const u8 {
    return path.ptr[0..path.len];
}

const std = @import("std");
