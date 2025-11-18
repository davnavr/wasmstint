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
};

const std = @import("std");
const ByteSlice = @import("ffi.zig").ByteSlice;
