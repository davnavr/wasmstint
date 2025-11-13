const configuration = wasm_smith.Configuration{};

fn doTest(input: []const u8) !void {
    var wasm_buffer: wasm_smith.ModuleBuffer = undefined;
    wasm_smith.generateModule(input, &wasm_buffer, &configuration) catch |e| return switch (e) {
        error.BadInput => error.SkipZigTest,
    };

    defer wasm_smith.freeModule(&wasm_buffer);

    var scratch = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer scratch.deinit();

    var diagnostic_writer = try std.Io.Writer.Allocating.initCapacity(std.testing.allocator, 128);
    defer diagnostic_writer.deinit();

    var wasm = wasm_buffer.bytes();
    const module = wasmstint.Module.parse(
        std.testing.allocator,
        &wasm,
        &scratch,
        .{ .diagnostics = .init(&diagnostic_writer.writer) },
    ) catch |e| switch (e) {
        error.OutOfMemory => |oom| return oom,
        error.InvalidWasm, error.MalformedWasm => {
            try std.testing.expect(diagnostic_writer.written().len > 4);
            return;
        },
        error.WasmImplementationLimit => {
            try std.testing.expectEqual(diagnostic_writer.written().len, 0);
            return;
        },
    };
    defer module.deinitLeakCodeEntries(std.testing.allocator);

    try std.testing.expectEqual(wasm.len, 0);
}

test {
    // TODO(zig): Fix crash in fuzz test runner
    if (true) {
        try std.testing.fuzz({}, doTest, .{});
    }
}

const std = @import("std");
const wasm_smith = @import("wasm-smith");
const wasmstint = @import("wasmstint");
