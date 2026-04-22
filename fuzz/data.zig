/// Used when to pass byte slices across the FFI boundary.
pub const ByteSlice = extern struct {
    ptr: [*]const u8,
    len: usize,

    pub fn init(bytes: []const u8) ByteSlice {
        return ByteSlice{ .ptr = bytes.ptr, .len = bytes.len };
    }

    pub fn slice(bytes: ByteSlice) []const u8 {
        return bytes.ptr[0..bytes.len];
    }

    pub const empty = ByteSlice.init("");
};

/// Note that some functions may introduce a bias, assuming the input bytes are random.
///
/// Where possible, functions choose a default value when the input bytes are exhausted. For
/// more information, see <https://github.com/rust-fuzz/arbitrary/issues/92>.
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

    pub fn boolean(input: *Input) bool {
        return (input.takeArray(1) catch return false)[0] & 1 == 1;
    }

    pub fn int(input: *Input, comptime T: type) T {
        const ByteAligned = std.math.ByteAlignedInt(T);
        const bytes = input.takeArray(@sizeOf(ByteAligned)) catch return 0;
        return @truncate(std.mem.readInt(ByteAligned, bytes, .little));
    }

    pub fn vector(input: *Input, comptime V: type) V {
        const T = @typeInfo(V).vector.child;
        const len = @typeInfo(V).vector.len;
        var lanes: [len]T = undefined;
        for (&lanes) |*l| {
            l.* = switch (@typeInfo(T)) {
                .int => input.int(T),
                .float => input.floatFromBits(T),
                else => comptime unreachable,
            };
        }

        return lanes;
    }

    pub fn uintLessThan(input: *Input, comptime T: type, max: T) T {
        comptime {
            std.debug.assert(@typeInfo(T).int.signedness == .unsigned);
        }

        const value: T = input.int(T);
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
    pub fn uintInRangeExclusive(input: *Input, comptime T: type, min: T, max: T) T {
        const value: T = min + input.uintLessThan(T, max - min);
        std.debug.assert(value < max);
        return value;
    }

    /// Asserts that `max >= min`.
    pub fn uintInRangeInclusive(input: *Input, comptime T: type, min: T, max: T) T {
        const value: T = min + input.uintLessThan(T, (max - min) +| 1);
        std.debug.assert(value <= max);
        return value;
    }

    pub fn choose(input: *Input, comptime T: type, comptime I: type, choices: []const T) T {
        std.debug.assert(0 < choices.len);
        std.debug.assert(choices.len <= std.math.maxInt(I));
        return choices[input.uintLessThan(I, @intCast(choices.len))];
    }

    pub fn enumValue(input: *Input, comptime T: type, comptime I: type) T {
        return input.choose(T, I, std.enums.values(T));
    }

    pub fn floatFromBits(input: *Input, comptime T: type) T {
        const Int = @Int(.unsigned, @typeInfo(T).float.bits);
        return @bitCast(input.int(Int));
    }
};

const std = @import("std");
const testing = std.testing;

test Input {
    const original = "helloworld\x34\x12\x00\x01\x02\x03\x04\x05\x07\x08\x00\xAA\xBB\xCC\xDD";
    var input = Input.init(original);
    try testing.expectEqual(original[0..5], input.take(5));
    try testing.expectEqual(original[5..10], input.takeArray(5));
    try testing.expectEqual(0x1234, input.int(u16));
    try testing.expectEqual(false, input.boolean());
    try testing.expectEqual(true, input.boolean());
    try testing.expectEqual(false, input.boolean());
    try testing.expectEqual(3, input.uintLessThan(u8, 4));
    try testing.expectEqual(0, input.uintLessThan(u8, 4));
    try testing.expectEqual(3, input.uintInRangeExclusive(u8, 2, 6));
    try testing.expectEqual(5, input.uintInRangeExclusive(u8, 2, 6));
    try testing.expectEqual(2, input.uintInRangeExclusive(u8, 2, 6));
    try testing.expectEqual(42, input.uintInRangeInclusive(u8, 42, 42));
    try testing.expectEqual([4]u8{ 0xAA, 0xBB, 0xCC, 0xDD }, input.vector(@Vector(4, u8)));
}
