pub fn main() u8 {
    std.debug.print("Hello WASM!\n", .{});
    return 0;
}

const std = @import("std");

test {
    try subprocess.invokeWasiInterpreter(
        test_paths.interpreter,
        test_paths.wasm,
        .{},
        .{
            .stdout = "Hello WASM!\n",
        },
    );
}

const subprocess = @import("subprocess");
const test_paths = @import("test_paths");
