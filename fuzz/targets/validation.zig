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
            std.debug.panic(
                "module validation error {t}: {s}",
                .{ e, diagnostic_writer.written() },
            );
        },
        error.WasmImplementationLimit => return,
    };
    defer module.deinitLeakCodeEntries(allocator);

    if (wasm.len != 0) {
        std.debug.panic("WASM buffer was not fully parsed: {d} bytes remaining", .{wasm.len});
    }

    _ = scratch.reset(.retain_capacity);

    var code_arena = std.heap.ArenaAllocator.init(allocator);
    defer code_arena.deinit();

    const finished = module.finishCodeValidation(
        code_arena.allocator(), // TODO: Provide way to deallocate individual code entries
        scratch,
        .init(&diagnostic_writer.writer),
    ) catch |e| switch (e) {
        error.OutOfMemory => |oom| return oom,
        error.InvalidWasm, error.MalformedWasm => if (diagnostic_writer.written().len <= 4) {
            @panic("no diagnostic was written");
        } else {
            std.debug.panic("code validation error {t}: {s}", .{ e, diagnostic_writer.written() });
        },
        error.WasmImplementationLimit => return,
    };

    if (!finished) {
        @panic("validation was not finished!");
    }

    for (module.funcImportTypes().len..module.funcTypes().len) |i| {
        const code = module.code(@enumFromInt(i));
        if (code.status.load(.monotonic) != .finished) {
            std.debug.panic("validation did not finish for function #{d}", .{i});
        }

        const inner = &code.inner;
        if (@intFromPtr(module.inner.raw.code_section) >= @intFromPtr(inner.instructions_start)) {
            std.debug.panic(
                "instruction start {*} out of bounds of code section {*}",
                .{ inner.instructions_start, module.inner.raw.code_section },
            );
        }

        if (@intFromPtr(inner.instructions_end) < @intFromPtr(inner.instructions_start)) {
            std.debug.panic(
                "instruction end {*} less than start {*}",
                .{ inner.instructions_end, inner.instructions_start },
            );
        }
    }

    std.debug.print("validated {d} functions\n", .{module.codeEntries().len});
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
