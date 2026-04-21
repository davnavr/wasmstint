//! Fuzzes the `wasmstint` parser by providing potentially invalid or malformed WASM modules.
pub fn testOne(
    input: []const u8,
    scratch: *std.heap.ArenaAllocator,
    allocator: std.mem.Allocator,
) error{OutOfMemory}!void {
    var diagnostic_writer = try std.Io.Writer.Allocating.initCapacity(allocator, 128);
    defer diagnostic_writer.deinit();

    var wasm: []const u8 = input;
    const module = wasmstint.Module.parse(
        allocator,
        &wasm,
        scratch,
        .{ .diagnostics = .init(&diagnostic_writer.writer) },
    ) catch |e| switch (e) {
        error.OutOfMemory => |oom| return oom,
        error.InvalidWasm, error.MalformedWasm => {
            std.debug.assert(diagnostic_writer.written().len > 0);
            std.log.info("module {t}: {s}", .{ e, diagnostic_writer.written() });
            return;
        },
        error.WasmImplementationLimit => {
            std.debug.assert(diagnostic_writer.written().len > 0);
            std.log.warn("hit implementation limit: {s}", .{diagnostic_writer.written()});
            return;
        },
    };
    defer module.deinit(allocator, allocator);

    std.debug.assert(wasm.len == 0);

    _ = scratch.reset(.retain_capacity);

    const finished = module.finishCodeValidation(
        allocator,
        scratch,
        .init(&diagnostic_writer.writer),
    ) catch |e| switch (e) {
        error.OutOfMemory => |oom| return oom,
        error.InvalidWasm, error.MalformedWasm => {
            std.debug.assert(diagnostic_writer.written().len > 0);
            std.log.info("code {t}: {s}", .{ e, diagnostic_writer.written() });
            return;
        },
        error.WasmImplementationLimit => {
            std.debug.assert(diagnostic_writer.written().len > 0);
            std.log.warn("hit implementation limit: {s}", .{diagnostic_writer.written()});
            return;
        },
    };

    // TODO: differential, check if `wasmparser` indicates success/failure

    if (!finished) {
        @panic("validation was not finished!");
    }
}

const std = @import("std");
const wasmstint = @import("wasmstint");
