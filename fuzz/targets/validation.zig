const configuration = wasm_smith.Configuration{};

pub fn testOne(
    input: []const u8,
    scratch: *std.heap.ArenaAllocator,
    allocator: std.mem.Allocator,
) error{ OutOfMemory, SkipZigTest }!void {
    var wasm_buffer: wasm_smith.ModuleBuffer = undefined;
    wasm_smith.generateModule(input, &wasm_buffer, &configuration) catch |e| return switch (e) {
        error.BadInput => error.SkipZigTest,
    };

    defer wasm_smith.freeModule(&wasm_buffer);

    var diagnostic_writer = try std.Io.Writer.Allocating.initCapacity(allocator, 128);
    defer diagnostic_writer.deinit();

    var wasm = wasm_buffer.bytes();
    const module = wasmstint.Module.parse(
        allocator,
        &wasm,
        scratch,
        .{ .diagnostics = .init(&diagnostic_writer.writer) },
    ) catch |e| switch (e) {
        error.OutOfMemory => |oom| return oom,
        error.InvalidWasm, error.MalformedWasm => if (diagnostic_writer.written().len <= 4) {
            @panic("no diagnostic was written");
        } else {
            std.debug.panic("{t}: {s}", .{ e, diagnostic_writer.written() });
        },
        error.WasmImplementationLimit => return,
    };
    defer module.deinitLeakCodeEntries(allocator);

    if (wasm.len != 0) {
        std.debug.panic("WASM buffer was not fully parsed: {d} bytes remaining", .{wasm.len});
    }
}

// test {
//     // TODO(zig): Fix crash in fuzz test runner
//     if (true) {
//         try std.testing.fuzz({}, doTest, .{});
//     }
// }

const std = @import("std");
const wasm_smith = @import("wasm-smith");
const wasmstint = @import("wasmstint");
