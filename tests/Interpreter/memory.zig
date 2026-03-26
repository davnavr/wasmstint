test "StaticBuffer" {
    var scratch = std.heap.ArenaAllocator.init(testing.allocator);
    defer scratch.deinit();

    const memory_buffer = try testing.allocator
        .alignedAlloc(u8, .fromByteUnits(MemInst.buffer_align), MemInst.page_size * 2);
    defer testing.allocator.free(memory_buffer);

    @memset(memory_buffer, 0);

    var wasm_binary = wasm: {
        var b = WasmBuilder.init(testing.allocator);
        defer b.deinit();

        const mem = try b.memory(.init(.{ .minimum = 1 }));

        const store = try b.function(try b.funcType(&.{.i32}, &.{}));
        {
            var wip = store.writeCode(&b, testing.allocator, .{});
            try wip.byte(.@"local.get", wip.param(0));
            try wip.byte(.@"i32.const", 0xF0F0);
            try wip.byte(.@"i32.store", .{ .memory = mem });
            try wip.byte(.end, {});
            try wip.finish(&scratch);
        }
        try store.@"export"(&b, try b.string("store"));

        break :wasm try b.toBinary(testing.allocator, &scratch, .{});
    };
    defer wasm_binary.deinit(testing.allocator);

    var module = try setup.WasmModule.init(wasm_binary.items, &scratch);
    defer module.deinit();

    const initial_fuel = 4;

    var interp: Interpreter = undefined;
    var state = try Interpreter.init(&interp, testing.allocator, .{});
    defer interp.deinit(testing.allocator);

    {
        var fuel = Interpreter.Fuel{ .remaining = initial_fuel };

        var mem = MemInst.StaticBuffer.initAssumeZeroed(memory_buffer, MemInst.page_size);
        var module_inst = inst: {
            var module_alloc = try module.allocateWithDefinitions(.none, .{
                .memories = &.{&mem.memory},
            });
            errdefer module_alloc.deinit(testing.allocator);

            state = try state.awaiting_host
                .instantiateModule(testing.allocator, &module_alloc, &fuel);
            break :inst module_alloc.assumeInstantiated();
        };
        defer module_inst.deinit(testing.allocator);

        const store_fn = (try module_inst.findExport("store")).func.funcInst();
        const index: u32 = 42;

        state = try (try checks.expectInterpreterState(state, .awaiting_host))
            .beginCall(testing.allocator, store_fn, &.{.{ .i32 = @bitCast(index) }}, &fuel);

        try testing.expectEqual(0, fuel.remaining);
        try testing.expectEqual(
            0xF0F0,
            std.mem.readInt(u32, memory_buffer[index..][0..4], .little),
        );

        _ = try checks.expectInterpreterState(state, .awaiting_host);
    }

    {
        var fuel = Interpreter.Fuel{ .remaining = initial_fuel };

        // Memory contents are not zero, test that this calls `memset`
        var mem = MemInst.StaticBuffer.init(memory_buffer, MemInst.page_size);
        var module_inst = inst: {
            var module_alloc = try module.allocateWithDefinitions(.none, .{
                .memories = &.{&mem.memory},
            });
            errdefer module_alloc.deinit(testing.allocator);

            state = try state.awaiting_host
                .instantiateModule(testing.allocator, &module_alloc, &fuel);
            break :inst module_alloc.assumeInstantiated();
        };
        defer module_inst.deinit(testing.allocator);

        const store_fn = (try module_inst.findExport("store")).func.funcInst();
        const index: u32 = 4242;

        state = try (try checks.expectInterpreterState(state, .awaiting_host))
            .beginCall(testing.allocator, store_fn, &.{.{ .i32 = @bitCast(index) }}, &fuel);

        try testing.expectEqual(0, fuel.remaining);
        try testing.expectEqual(
            0xF0F0,
            std.mem.readInt(u32, memory_buffer[index..][0..4], .little),
        );
        try testing.expectEqual(0, std.mem.readInt(u32, memory_buffer[42..][0..4], .little));

        _ = try checks.expectInterpreterState(state, .awaiting_host);
    }
}

const std = @import("std");
const testing = std.testing;
const wasmstint = @import("wasmstint");
const Interpreter = wasmstint.Interpreter;
const MemInst = wasmstint.runtime.MemInst;
const checks = @import("checks.zig");
const setup = @import("setup.zig");
const WasmBuilder = @import("WasmBuilder");
