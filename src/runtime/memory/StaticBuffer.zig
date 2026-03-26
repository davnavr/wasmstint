//! A `MemInst` implementation backed by an existing buffer..

memory: MemInst,

const StaticBuffer = @This();

/// Does not check that the buffer is all zeroes.
pub fn initUnchecked(buffer: []align(MemInst.buffer_align) u8, size: usize) StaticBuffer {
    std.debug.assert(buffer.len % MemInst.page_size == 0);
    std.debug.assert(size <= buffer.len);
    std.debug.assert(size % MemInst.page_size == 0);
    return StaticBuffer{
        .memory = MemInst{
            .base = buffer.ptr,
            .size = size,
            .capacity = buffer.len,
            .limit = buffer.len,
            .vtable = &vtable,
        },
    };
}

/// Like `init()`, but instead only asserts that `buffer` contains only zero bytes.
pub fn initAssumeZeroed(buffer: []align(MemInst.buffer_align) u8, size: usize) StaticBuffer {
    const actual_buf = buffer[0..std.mem.alignBackward(usize, buffer.len, MemInst.page_size)];
    const actual_size = std.mem.alignBackward(usize, size, MemInst.page_size);
    std.debug.assert(actual_size <= actual_buf.len);
    if (@inComptime()) {
        comptime {
            for (actual_buf, 0..) |b, i| {
                if (b != 0) {
                    @compileError(
                        std.fmt.comptimePrint(
                            "non-zero byte in linear memory buffer at index {d}",
                            .{i},
                        ),
                    );
                }
            }
        }
    } else if (builtin.mode == .Debug) {
        for (actual_buf, 0..) |*b, i| {
            if (b.* != 0) {
                std.debug.panic(
                    "buffer must be zeroed: non-zero byte 0x{X:0>2} at index {d} (0x{X})",
                    .{ b.*, i, @intFromPtr(b) },
                );
            }
        }
    }

    return .initUnchecked(actual_buf, actual_size);
}

/// Creates a `MemInst` from a static buffer, setting all bytes to zero.
///
/// Rounds the buffer size down to the nearest multiple of the `page_size`.
pub fn init(
    buffer: []align(MemInst.buffer_align) u8,
    /// The initial size of the linear memory, rounded down to the nearest multiple of the page
    /// size.
    size: usize,
) StaticBuffer {
    const actual_buf = buffer[0..std.mem.alignBackward(usize, buffer.len, MemInst.page_size)];
    const actual_size = std.mem.alignBackward(usize, size, MemInst.page_size);
    std.debug.assert(actual_size <= actual_buf.len);
    @memset(actual_buf, 0);
    return .initUnchecked(actual_buf, actual_size);
}

fn free(inst: *MemInst) void {
    std.debug.assert(inst.size == 0);
    std.debug.assert(inst.capacity == 0);
}

const vtable = MemInst.VTable{
    .grow = MemInst.noGrow,
    .free = free,
    .moving = .forType(StaticBuffer, "memory"),
};

const std = @import("std");
const builtin = @import("builtin");
const MemInst = @import("../memory.zig").MemInst;
