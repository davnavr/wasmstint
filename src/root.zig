//! A *st*ackless, in-place *int*erpreter for [WebAssembly].
//!
//! [WebAssembly]: https://webassembly.org/

pub const Module = @import("Module.zig");
pub const runtime = @import("runtime.zig");
pub const Interpreter = @import("Interpreter.zig");

pub const pointer = @import("pointer.zig");

pub fn waitForDebugger() void {
    const os = @import("builtin").target.os;
    if (os.tag == .windows) {
        std.debug.print("Attach debugger to process {}\n", .{std.os.windows.GetCurrentProcessId()});

        const debugapi = struct {
            pub extern "kernel32" fn IsDebuggerPresent() callconv(.winapi) std.os.windows.BOOL;
        };

        while (debugapi.IsDebuggerPresent() == 0) {
            _ = std.os.windows.kernel32.SleepEx(100, 0);
        }
    } else {
        if (os.tag == .linux) {
            std.debug.print("Attach debugger to process {}\n", .{std.os.linux.getpid()});
        }

        var dbg: usize = 0;
        const dbg_ptr: *volatile usize = &dbg;
        while (dbg_ptr.* == 0) {
            std.posix.nanosleep(0, 100_000_000);
        }
    }
}

comptime {
    // See https://webassembly.org/docs/portability/
    std.debug.assert(std.mem.byte_size_in_bits == 8);
}

const std = @import("std");

test {
    _ = Module;
    _ = Interpreter;
    _ = pointer;
}
