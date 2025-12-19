/// Implements 128-bit SIMD operations introduced in the
/// [fixed-width SIMD proposal](https://github.com/WebAssembly/simd).
pub const V128 = extern union {
    i8x16: @Vector(16, i8),

    pub const LaneIdxSize = enum(u4) {
        @"2" = 1,
        @"4" = 2,
        @"8" = 3,
        @"16" = 4,
        @"32" = 5,
    };

    pub fn LaneIdx(comptime size: LaneIdxSize) type {
        return std.meta.Int(.unsigned, @intFromEnum(size));
    }
};

const std = @import("std");
