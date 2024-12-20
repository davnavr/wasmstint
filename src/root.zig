//! A *st*ackless, in-place *int*erpreter for [WebAssembly].
//!
//! [WebAssembly]: https://webassembly.org/

pub const Wast = @import("Wast.zig");
pub const float = @import("float.zig");

test {
    _ = Wast;
}
