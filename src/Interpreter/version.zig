/// Ensures that `State` structs operate on the correct `Interpreter`.
pub const Version = packed struct {
    pub const enabled = true; // Zero-sized types might break Zig codegen.

    number: if (enabled) u32 else u0 = 0,

    pub fn increment(ver: *Version) void {
        if (enabled) {
            ver.number +%= 1;
        }
    }

    pub fn check(expected: Version, actual: Version) void {
        if (enabled and expected.number != actual.number) {
            @branchHint(.cold);
            const message = "interpreter version out of sync";
            switch (builtin.mode) {
                .Debug, .ReleaseSafe => std.debug.panic(
                    message ++ ": expected {}, got {}",
                    .{ expected, actual },
                ),
                .ReleaseFast => @panic(message),
                .ReleaseSmall => @trap(),
            }
        }
    }
};

const std = @import("std");
const builtin = @import("builtin");
