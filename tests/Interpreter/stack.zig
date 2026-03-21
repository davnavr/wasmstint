//! Tests handling of call stack exhaustion conditions.

test {
    var scratch = std.heap.ArenaAllocator.init(testing.allocator);
    defer scratch.deinit();

    var wasm = wasm: {
        var b = WasmBuilder.init(testing.allocator);
        defer b.deinit();

        const f = try b.function(try b.funcType(&.{}, &.{}));
        {
            var wip = f.writeCode(&b, testing.allocator, .{});
            try wip.byte(.nop, {});
            try wip.byte(.call, f);
            try wip.byte(.end, {});
            try wip.finish(&scratch);
        }
        try f.@"export"(&b, try b.string("recursive"));

        break :wasm try b.toBinary(testing.allocator, &scratch, .{});
    };
    defer wasm.deinit(testing.allocator);

    var module = try setup.WasmModule.init(wasm.items, &scratch);
    defer module.deinit();

    var module_definitions: setup.WasmModule.ModuleDefinitions = undefined;
    var module_alloc = try module.allocate(&module_definitions, &scratch, .none);
    defer module_definitions.deinit();

    var interp: Interpreter = undefined;
    var fuel = Interpreter.Fuel{ .remaining = std.math.maxInt(u32) };
    var interp_allocator = testing.FailingAllocator.init(testing.allocator, .{
        .fail_index = 1,
        .resize_fail_index = 2,
    });
    const interp_alloca = interp_allocator.allocator();

    var state = try Interpreter.init(&interp, interp_alloca, .{});
    defer interp.deinit(interp_allocator.allocator());

    state = try state.awaiting_host.instantiateModule(interp_alloca, &module_alloc, &fuel);

    var module_inst = module_alloc.assumeInstantiated();
    defer module_inst.deinit(testing.allocator);

    const f = (try module_inst.findExport("recursive")).func.funcInst();
    state = try (try checks.expectInterpreterState(state, .awaiting_host))
        .beginCall(testing.allocator, f, &.{}, &fuel);

    const stack_overflow = try checks.expectInterpreterState(state, .call_stack_exhaustion);
    const current_frame = stack_overflow.inner.currentFrame().?;
    const wasm_func = current_frame.function.expanded().wasm;
    try testing.expectEqual(wasm_func.idx, @as(wasmstint.Module.FuncIdx, @enumFromInt(0)));
    try testing.expectEqual(1, current_frame.wasm.ip - wasm_func.code().inner.instructions_start);
}

const std = @import("std");
const testing = std.testing;
const wasmstint = @import("wasmstint");
const Interpreter = wasmstint.Interpreter;
const checks = @import("checks.zig");
const setup = @import("setup.zig");
const WasmBuilder = @import("WasmBuilder");
