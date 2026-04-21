//! Fuzzes the `wasmstint` parser by providing potentially invalid or malformed WASM modules.
pub fn testOne(
    input: []const u8,
    scratch: *ArenaAllocator,
    allocator: std.mem.Allocator,
) error{OutOfMemory}!void {
    var diag_arena = ArenaAllocator.init(allocator);
    defer diag_arena.deinit();

    var diag = wasmstint.Module.ParseDiagnostics.init(&diag_arena);
    var wasm: []const u8 = input;
    const module = wasmstint.Module.parse(
        allocator,
        &wasm,
        scratch,
        .{ .diagnostics = &diag },
    ) catch |e| switch (e) {
        error.OutOfMemory => |oom| return oom,
        error.InvalidWasm, error.MalformedWasm => {
            std.debug.assert(diag.message.?.len > 0);
            std.log.info("module {t}: {s}", .{ e, diag.message.? });
            return;
        },
        error.WasmImplementationLimit => {
            std.debug.assert(diag.message.?.len > 0);
            std.log.warn("hit implementation limit: {s}", .{diag.message.?});
            return;
        },
    };
    defer module.deinit(allocator, allocator);

    std.debug.assert(wasm.len == 0);

    _ = scratch.reset(.retain_capacity);

    const finished = module.finishCodeValidation(
        allocator,
        scratch,
        &diag,
    ) catch |e| switch (e) {
        error.OutOfMemory => |oom| return oom,
        error.InvalidWasm, error.MalformedWasm => {
            std.debug.assert(diag.message.?.len > 0);
            std.log.info("code {t}: {s}", .{ e, diag.message.? });
            return;
        },
        error.WasmImplementationLimit => {
            std.debug.assert(diag.message.?.len > 0);
            std.log.warn("hit implementation limit: {s}", .{diag.message.?});
            return;
        },
    };

    // TODO: differential, check if `wasmparser` indicates success/failure

    if (!finished) {
        @panic("validation was not finished!");
    }
}

const std = @import("std");
const ArenaAllocator = std.heap.ArenaAllocator;
const wasmstint = @import("wasmstint");
