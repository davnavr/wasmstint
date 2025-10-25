/// Ensures that `State` structs operate on the correct `Interpreter`.
pub const Version = packed struct {
    pub const enabled = switch (builtin.mode) {
        .Debug, .ReleaseSafe => true,
        .ReleaseFast, .ReleaseSmall => false,
    };

    number: if (enabled) u32 else void =
        if (enabled) 0 else {},

    pub fn increment(ver: *Version) void {
        if (enabled) {
            ver.number +%= 1;
        }
    }

    pub fn check(expected: Version, actual: Version) void {
        if (enabled) {
            if (expected.number != actual.number) {
                std.debug.panic(
                    "bad interpreter version: expected {}, got {}",
                    .{ expected, actual },
                );
            }
        }
    }
};

const std = @import("std");
const builtin = @import("builtin");
