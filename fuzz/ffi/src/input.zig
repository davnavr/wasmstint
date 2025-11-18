/// Note that some functions may introduce a bias, assuming the input bytes are random.
pub const Input = extern struct {
    bytes: ByteSlice,

    pub const Error = error{
        /// The end of the input bytes was reached, or the input bytes were not in the correct
        /// format.
        BadInput,
    };

    pub fn init(bytes: []const u8) Input {
        return Input{ .bytes = ByteSlice.init(bytes) };
    }

    pub fn remaining(input: Input) []const u8 {
        return input.bytes.slice();
    }

    pub fn take(input: *Input, count: usize) Error![]const u8 {
        if (input.bytes.len < count) {
            return Error.BadInput;
        }

        const bytes = input.remaining()[0..count];
        input.bytes = ByteSlice.init(input.remaining()[count..]);
        return bytes;
    }

    pub fn takeArray(input: *Input, comptime count: usize) Error!*const [count]u8 {
        return (try input.take(count))[0..count];
    }

    pub fn boolean(input: *Input) Error!bool {
        return (try input.takeArray(1))[0] & 1 == 1;
    }

    pub fn int(input: *Input, comptime T: type) Error!T {
        const ByteAligned = std.math.ByteAlignedInt(T);
        return @truncate(std.mem.readInt(
            ByteAligned,
            try input.takeArray(@sizeOf(ByteAligned)),
            .little,
        ));
    }

    pub fn uintLessThan(input: *Input, comptime T: type, max: T) Error!T {
        comptime {
            std.debug.assert(@typeInfo(T).int.signedness == .unsigned);
        }

        const value: T = try input.int(T);
        if (max != 0) {
            const clamped: T = value % max;
            std.debug.assert(clamped < max);
            return clamped;
        } else {
            @branchHint(.unlikely);
            return 0;
        }
    }

    /// Asserts that `max >= min`.
    pub fn uintInRangeExclusive(input: *Input, comptime T: type, min: T, max: T) Error!T {
        const value: T = min + (try input.uintLessThan(T, max - min));
        std.debug.assert(value < max);
        return value;
    }

    /// Asserts that `max >= min`.
    pub fn uintInRangeInclusive(input: *Input, comptime T: type, min: T, max: T) Error!T {
        const value: T = min + (try input.uintLessThan(T, (max - min) +| 1));
        std.debug.assert(value <= max);
        return value;
    }

    pub fn choose(input: *Input, comptime T: type, comptime I: type, choices: []const T) Error!T {
        std.debug.assert(0 < choices.len);
        std.debug.assert(choices.len <= std.math.maxInt(I));
        return choices[try input.uintLessThan(I, @intCast(choices.len))];
    }

    pub fn enumValue(input: *Input, comptime T: type, comptime I: type) Error!T {
        return input.choose(T, I, std.enums.values(T));
    }

    pub fn floatFromBits(input: *Input, comptime T: type) Error!T {
        const Int = std.meta.Int(.unsigned, @typeInfo(T).float.bits);
        return @bitCast(try input.int(Int));
    }
};

test {
    const original = "helloworld\x34\x12\x00\x01\x02\x03\x04\x05\x07\x08";
    var input = Input.init(original);
    try std.testing.expectEqual(original[0..5], input.take(5));
    try std.testing.expectEqual(original[5..10], input.takeArray(5));
    try std.testing.expectEqual(0x1234, input.int(u16));
    try std.testing.expectEqual(false, input.boolean());
    try std.testing.expectEqual(true, input.boolean());
    try std.testing.expectEqual(false, input.boolean());
    try std.testing.expectEqual(3, input.uintLessThan(u8, 4));
    try std.testing.expectEqual(0, input.uintLessThan(u8, 4));
    try std.testing.expectEqual(3, input.uintInRangeExclusive(u8, 2, 6));
    try std.testing.expectEqual(5, input.uintInRangeExclusive(u8, 2, 6));
    try std.testing.expectEqual(2, input.uintInRangeExclusive(u8, 2, 6));
}

const std = @import("std");
const ByteSlice = @import("ffi.zig").ByteSlice;
