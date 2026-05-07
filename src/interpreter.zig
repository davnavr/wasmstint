//! Internal API.

pub const const_eval = @import("interpreter/const_eval.zig");
pub const instantiation = @import("interpreter/instantiation.zig");
pub const Instr = @import("interpreter/Instr.zig");
pub const Interpreter = @import("interpreter/Interpreter.zig");
pub const SideTable = @import("interpreter/side_table.zig").SideTable;
pub const Stack = @import("interpreter/Stack.zig");
pub const Value = @import("interpreter/value.zig").Value;
pub const Version = @import("interpreter/version.zig").Version;

comptime {
    if (!@import("builtin").is_test) {
        _ = @import("handlers"); // ensure inclusion of `@export`ed functions.
    }
}

test {
    _ = Instr;
    _ = Interpreter;
}
