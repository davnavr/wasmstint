const std = @import("std");
const harness = @import("harness");
const wasmstint = @import("wasmstint");

// TODO: Move common code out, this target doesn't need Rust

/// Assumes the given input buffer is WASM, and passes it to the parser/validator.
pub fn target(input_bytes: []const u8) !harness.Result {
    var main_pages = try wasmstint.PageBufferAllocator.init(4 * (1024 * 1024));
    defer main_pages.deinit();
    var main_arena = std.heap.ArenaAllocator.init(main_pages.allocator());

    var scratch_pages = try wasmstint.PageBufferAllocator.init(2 * (1024 * 1024));
    defer scratch_pages.deinit();
    var scratch = std.heap.ArenaAllocator.init(scratch_pages.allocator());

    var rng = std.Random.DefaultPrng.init(42);

    var wasm_parse = input_bytes;
    var module = try wasmstint.Module.parse(
        main_arena.allocator(),
        &wasm_parse,
        &scratch,
        rng.random(),
        .{},
    );

    _ = module.finishCodeValidation(
        main_arena.allocator(),
        &scratch,
    ) catch |e| switch (e) {
        error.OutOfMemory => |oom| return oom,
        error.InvalidWasm,
        error.MalformedWasm,
        error.EndOfStream,
        error.WasmImplementationLimit,
        => {},
    };

    return .ok;
}

comptime {
    harness.defineFuzzTarget(target);
}
