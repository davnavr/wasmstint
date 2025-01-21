const std = @import("std");
const runtime = @import("runtime.zig");

pub const Word = packed union {
    i32: i32,
    f32: f32,
    i64: i64,
    f64: f64,

    /// Represents a quantity in terms of multiples of 8 bytes.
    pub const Size = enum(u32) {
        zero = 0,
        _,

        pub fn toInt(size: Size) u35 {
            return @as(u35, @intFromEnum(size)) * 8;
        }
    };

    comptime {
        std.debug.assert(@alignOf(Word) == @alignOf(u64));
        std.debug.assert(@sizeOf(Word) == 8);
    }
};

pub const StackFrame = extern struct {
    /// The amount to decrement the `sp` by to get to the previous stack frame.
    previous: Word.Size,
    /// The size of the current frame.
    size: Word.Size,
    function: runtime.FuncInst,

    comptime {
        std.debug.assert(@sizeOf(StackFrame) % @min(@sizeOf(usize), 8) == 0);
    }
};

// TODO: Either provide an Allocator here, or do something radical and have call stack resize be another event to handle
call_stack: []align(16) const Word,
current_frame: ?*align(8) const StackFrame = null,

const Interpreter = @This();

pub fn init(allocator: std.mem.Allocator, size: usize) error{OutOfMemory}!Interpreter {
    return .{
        .call_stack = try allocator.alignedAlloc(
            Word,
            16,
            size / @sizeOf(Word),
        ),
    };
}

fn pushStackFrame(interpreter: *Interpreter, size: Word.Size) error{Overflow}!?[]align(8) const Word {
    const total_size = try std.math.add(
        usize,
        @sizeOf(StackFrame),
        size.toUsize() orelse return error.Overflow,
    );

    std.debug.assert(total_size % 8 == 0);

    if (@intFromPtr(interpreter.call_stack.ptr) + interpreter.call_stack.len - @intFromPtr(interpreter.current_frame) < total_size)
        return null;

    // interpreter.current_frame = new_frame;

    unreachable;
}

pub fn deinit(interpreter: *Interpreter, allocator: std.mem.Allocator) void {
    allocator.free(interpreter.call_stack);
    interpreter.* = undefined;
}
