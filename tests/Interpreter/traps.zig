//! Tests that traps are handled correctly.

fn checkTrapIp(
    /// Must have the following signature:
    /// ```wat
    /// (module
    ///   (func (export "f"))
    /// )
    /// ```
    wasm: []const u8,
    /// The exact amount of fuel consumed before the trap occurs.
    consumed_fuel: u64,
    expected_trap_code: Interpreter.Trap.Code,
    expected_ip: [*]const u8,
) !void {
    var scratch = ArenaAllocator.init(testing.allocator);
    _ = scratch.deinit();

    var module = try setup.WasmModule.init(wasm, &scratch);
    defer module.deinit();

    var module_definitions: setup.WasmModule.ModuleDefinitions = undefined;
    var module_alloc = try module.allocate(&module_definitions, &scratch, .none);
    defer module_definitions.deinit();

    var module_inst = module_alloc.assumeInstantiated();
    module_inst.deinit(testing.allocator);

    const f = (try module_inst.findExport("f")).func.funcInst();

    var interp: Interpreter = undefined;
    var fuel = Interpreter.Fuel{ .remaining = consumed_fuel };
    const after_trap: Interpreter.State.Trapped = try checks.expectInterpreterState(
        try (try Interpreter.init(&interp, testing.allocator, .{})).awaiting_host
            .beginCall(testing.allocator, f, &.{}, &fuel),
        .trapped,
    );
    try testing.expectEqual(.function_call, after_trap.source());
    try testing.expectEqual(expected_trap_code, after_trap.trap().code);
    try testing.expectEqual(0, fuel.remaining);

    const frame = try checks.expectNonNull(after_trap.inner.currentFrame());
    try testing.expectEqual(expected_ip, frame.wasm.ip);
}

test "basic" {
    try checkTrapIp(
        &[_]u8{},
        3,
        .unreachable_code_reached,
        @ptrFromInt(42),
    );
}

// test "overlong"

const std = @import("std");
const ArenaAllocator = std.heap.ArenaAllocator;
const testing = std.testing;
const wasmstint = @import("wasmstint");
const Interpreter = wasmstint.Interpreter;
const checks = @import("checks.zig");
const setup = @import("setup.zig");
