//! A *st*ackless, in-place *int*erpreter for [WebAssembly].
//!
//! [WebAssembly]: https://webassembly.org/

pub const Module = @import("module").Module;
pub const runtime = @import("runtime.zig");
pub const Interpreter = @import("interpreter").Interpreter;

comptime {
    if (!builtin.is_test) {
        _ = @import("interpreter"); // ensure inclusion of `@export`ed functions.
    }
}

pub const pointer = @import("pointer.zig");
pub const V128 = @import("v128.zig").V128;
pub const round = @import("round.zig");

pub fn waitForDebugger(io: std.Io) void {
    const os = builtin.target.os;
    if (os.tag == .windows) {
        std.debug.print("Attach debugger to process {}\n", .{std.os.windows.GetCurrentProcessId()});

        const debugapi = struct {
            pub extern "kernel32" fn IsDebuggerPresent() callconv(.winapi) std.os.windows.BOOL;
        };

        while (debugapi.IsDebuggerPresent() == .FALSE) {
            io.sleep(.fromMilliseconds(100), .awake) catch continue;
        }
    } else {
        if (os.tag == .linux) {
            std.debug.print("Attach debugger to process {}\n", .{std.os.linux.getpid()});
        }

        var dbg: usize = 0;
        const dbg_ptr: *volatile usize = &dbg;
        while (dbg_ptr.* == 0) {
            io.sleep(.fromMilliseconds(100), .awake) catch continue;
        }
    }
}

comptime {
    // See https://webassembly.org/docs/portability/
    std.debug.assert(std.mem.byte_size_in_bits == 8);
}

const std = @import("std");
const builtin = @import("builtin");

test {
    _ = pointer;
}
