//! A *st*ackless, in-place *int*erpreter for [WebAssembly].
//!
//! [WebAssembly]: https://webassembly.org/

pub const Module = @import("Module.zig");
pub const float = @import("float.zig");
pub const runtime = @import("runtime.zig");
pub const Interpreter = @import("Interpreter.zig");

pub const pointer = @import("pointer.zig");

pub const LimitedAllocator = @import("LimitedAllocator.zig");
pub const PageBufferAllocator = @import("PageBufferAllocator.zig");

pub const FileContent = @import("FileContent.zig");

const std = @import("std");

pub fn waitForDebugger() void {
    const os = @import("builtin").target.os;
    if (os.tag == .windows) {
        std.debug.print("Attach debugger to process {}\n", .{std.os.windows.GetCurrentProcessId()});

        const debugapi = struct {
            pub extern "kernel32" fn IsDebuggerPresent() callconv(.winapi) std.os.windows.BOOL;
        };

        while (debugapi.IsDebuggerPresent() == 0) {
            std.Thread.sleep(100);
        }
    } else {
        if (os.tag == .linux) {
            std.debug.print("Attach debugger to process {}\n", .{std.os.linux.getpid()});
        }

        var dbg: usize = 0;
        const dbg_ptr: *volatile usize = &dbg;
        while (dbg_ptr.* == 0) {
            std.Thread.sleep(100);
        }
    }
}

comptime {
    // See https://webassembly.org/docs/portability/
    std.debug.assert(std.mem.byte_size_in_bits == 8);
}

test {
    _ = @import("reservation_allocator.zig");
    _ = PageBufferAllocator;
    _ = Module;
    _ = Interpreter;
    _ = pointer;
}
