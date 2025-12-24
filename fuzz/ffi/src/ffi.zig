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

pub const wasm_smith = @import("wasm_smith.zig");

pub const Input = @import("input.zig").Input;

test {
    _ = Input;
}
