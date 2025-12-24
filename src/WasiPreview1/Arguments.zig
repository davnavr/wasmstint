//! Command-line argument data to pass to the application.
//!
//! Obtained by calling `args_sizes_get` and `args_get`.

const Arguments = @This();

ptr: [*]const String,
count: u32,
/// Total size, in bytes, of all argument data.
///
/// This is the sum of all strings' lengths (including their null-terminators).
size: u32,

pub fn entries(args: Arguments) []const String {
    return args.ptr[0..args.count];
}

pub const String = struct {
    /// Invariant that `chars.len <= max_len`.
    ///
    /// `Char` guarantees no null-terminators are present.
    chars: []const Char,

    pub const max_len = std.math.maxInt(u32) - 1;

    pub const empty = String{ .chars = &.{} };

    /// Takes a slice of the given bytes up to the first encountered null-terminator (`\x00`),
    /// and truncates the length up to `max_len`.
    pub fn initTruncated(s: []const u8) String {
        const null_terminated = std.mem.sliceTo(s[0..@min(max_len, s.len)], 0);
        return .{ .chars = @ptrCast(null_terminated) };
    }

    pub fn len(s: String) u32 {
        return @intCast(s.chars.len);
    }

    pub fn lenWithNullTerminator(s: String) u32 {
        return s.len() + 1;
    }

    pub fn bytes(s: String) []const u8 {
        _ = s.len();
        return @ptrCast(s.chars);
    }

    pub fn format(s: String, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        return writer.writeAll(s.bytes());
    }

    // pub fn formatEscaped(s: String, writer: *std.Io.Writer) std.Io.Writer.Error!void {}
};

pub const List = struct {
    ptr: [*]String,
    count: u32,
    capacity: u32,
    /// In bytes.
    size: u32,

    pub fn initCapacity(gpa: Allocator, capacity: u32) Allocator.Error!List {
        const s = try gpa.alloc(String, capacity);
        return .{
            .ptr = s.ptr,
            .capacity = @intCast(s.len),
            .count = 0,
            .size = 0,
        };
    }

    fn allocatedSlice(list: *const List) []String {
        std.debug.assert(list.count <= list.capacity);
        return list.ptr[0..list.capacity];
    }

    pub fn appendBounded(list: *List, s: String) Allocator.Error!void {
        if (list.count == list.capacity) {
            return error.OutOfMemory; // at capacity
        }

        const new_size = std.math.add(u32, list.size, s.lenWithNullTerminator()) catch
            return error.OutOfMemory; // total size overflow

        list.allocatedSlice()[list.count] = s;
        list.count += 1;
        list.size = new_size;
    }

    fn slice(list: *const List) []String {
        return list.allocatedSlice()[0..list.count];
    }

    pub fn replaceAt(list: *List, at: u32, with: String) Allocator.Error!String {
        const elem = &list.slice()[at];
        const existing = elem.*;
        list.size = std.math.add(u32, list.size - existing.len(), with.len()) catch
            return error.OutOfMemory; // total size overflow
        elem.* = with;
        return existing;
    }

    pub fn arguments(list: *const List) Arguments {
        return .{
            .ptr = list.ptr,
            .count = list.count,
            .size = list.size,
        };
    }
};

const std = @import("std");
const Allocator = std.mem.Allocator;
const Char = @import("char.zig").Char;
