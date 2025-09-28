pub fn main() u8 {
    std.debug.print("Hello WASM!\n", .{});
    return 0;
}

const std = @import("std");
