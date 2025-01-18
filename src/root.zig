//! A *st*ackless, in-place *int*erpreter for [WebAssembly].
//!
//! [WebAssembly]: https://webassembly.org/

pub const Wast = @import("Wast.zig");
pub const Module = @import("Module.zig");
pub const float = @import("float.zig");
pub const runtime = @import("runtime.zig");

comptime {
    const std = @import("std");

    // See https://webassembly.org/docs/portability/
    std.debug.assert(std.mem.byte_size_in_bits == 8);
}

test {
    _ = Wast;
    _ = @import("IndexedArena.zig");
}
