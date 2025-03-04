const harness = @import("harness");

/// Instantiates a randomly generated WebAssembly module, then invokes its exported functions.
pub fn target(input_bytes: []const u8) !harness.Result {
    var input = input_bytes;
    const wasm = try harness.generateValidModule(&input);
    defer wasm.deinit();

    @panic("TODO: Actually write the test");
    // return .ok;
}

comptime {
    harness.defineFuzzTarget(target);
}
