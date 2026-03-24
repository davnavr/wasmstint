//! Tests that traps are handled correctly.

const call_name = "f";

const Context = struct {
    arena: std.heap.ArenaAllocator,
    scratch: std.heap.ArenaAllocator,

    fn init() Context {
        return .{
            .arena = .init(testing.allocator),
            .scratch = .init(testing.allocator),
        };
    }

    fn deinit(ctx: *Context) void {
        ctx.arena.deinit();
        ctx.scratch.deinit();
        ctx.* = undefined;
    }

    fn expectTrapIp(
        after_trap: *const Interpreter.State.Trapped,
        expected_func: wasmstint.Module.FuncIdx,
        expected_trap_code: Interpreter.Trap.Code,
        /// Based off the first byte of the first opcode of the trapping function.
        expected_trap_offset: u32,
    ) !void {
        const frame = try checks.expectNonNull(after_trap.inner.currentFrame());
        const wasm_func = frame.function.expanded().wasm;
        const code = wasm_func.code();
        try testing.expectEqual(expected_func, wasm_func.idx);
        try testing.expectEqual(.function_call, after_trap.source());
        try testing.expectEqual(expected_trap_code, after_trap.trap().code);

        const expected_ip = @intFromPtr(code.inner.instructions_start + expected_trap_offset);
        const actual_ip = @intFromPtr(frame.wasm.ip);
        if (expected_ip != actual_ip) {
            const ip_diff = if (expected_ip > actual_ip)
                expected_ip - actual_ip
            else
                actual_ip - expected_ip;

            std.log.err(
                "expected IP=0x{X}, got 0x{X} (off by {d} bytes)",
                .{ expected_ip, actual_ip, ip_diff },
            );
            std.log.err("function bytecode is at 0x{X} to 0x{X}", .{
                @intFromPtr(code.inner.instructions_start),
                @intFromPtr(code.inner.instructions_end),
            });
            return error.TestExpectedEqual;
        }
    }

    fn checkTrapIpForModule(
        ctx: *Context,
        /// Must have the following signature:
        /// ```wat
        /// (module
        ///   (func (export "f"))
        /// )
        /// ```
        wasm: *const WasmBuilder,
        /// The exact amount of fuel consumed before the trap occurs.
        consumed_fuel: u64,
        expected_func: wasmstint.Module.FuncIdx,
        expected_trap_code: Interpreter.Trap.Code,
        expected_trap_offset: u32,
    ) !void {
        _ = ctx.arena.reset(.retain_capacity);
        const wasm_binary = (try wasm.toBinary(ctx.arena.allocator(), &ctx.scratch, .{})).items;

        var module = try setup.WasmModule.init(wasm_binary, &ctx.scratch);
        defer module.deinit();

        var module_definitions: setup.WasmModule.ModuleDefinitions = undefined;
        var module_alloc = try module.allocate(&module_definitions, &ctx.scratch, .none);
        defer module_definitions.deinit();

        var interp: Interpreter = undefined;
        var fuel = Interpreter.Fuel{ .remaining = consumed_fuel };
        const initial_state = try Interpreter.init(&interp, testing.allocator, .{});
        defer interp.deinit(testing.allocator);
        const state_after_instantiate = try initial_state.awaiting_host
            .instantiateModule(testing.allocator, &module_alloc, &fuel);

        var module_inst = module_alloc.assumeInstantiated();
        defer module_inst.deinit(testing.allocator);

        const f = (try module_inst.findExport(call_name)).func.funcInst();
        const after_trap: Interpreter.State.Trapped = try checks.expectInterpreterState(
            try (try checks.expectInterpreterState(state_after_instantiate, .awaiting_host))
                .beginCall(testing.allocator, f, &.{}, &fuel),
            .trapped,
        );
        try testing.expectEqual(0, fuel.remaining);
        try expectTrapIp(&after_trap, expected_func, expected_trap_code, expected_trap_offset);
    }
};

test "unreachable" {
    var ctx = Context.init();
    defer ctx.deinit();
    {
        var b = WasmBuilder.init(testing.allocator);
        defer b.deinit();

        const f = try b.function(try b.funcType(&.{}, &.{}));
        {
            var wip = f.writeCode(&b, testing.allocator, .{});
            try wip.byte(.nop, {});
            try wip.byte(.nop, {});
            try wip.byte(.@"unreachable", {});
            try wip.byte(.end, {});
            try wip.finish(&ctx.scratch);
        }
        try f.@"export"(&b, try b.string(call_name));

        try ctx.checkTrapIpForModule(&b, 3, @enumFromInt(0), .unreachable_code_reached, 2);
    }
    {
        var b = WasmBuilder.init(testing.allocator);
        defer b.deinit();

        const func_type = try b.funcType(&.{}, &.{});
        const called = try b.function(func_type);
        const trapping = try b.function(func_type);
        {
            var wip = called.writeCode(&b, testing.allocator, .{});
            try wip.byte(.nop, {});
            try wip.byte(.call, trapping);
            try wip.byte(.@"unreachable", {});
            try wip.byte(.end, {});
            try wip.finish(&ctx.scratch);
        }
        try called.@"export"(&b, try b.string(call_name));

        {
            var wip = trapping.writeCode(&b, testing.allocator, .{});
            try wip.byte(.nop, {});
            try wip.byte(.nop, {});
            try wip.byte(.nop, {});
            try wip.byte(.nop, {});
            try wip.byte(.@"unreachable", {});
            try wip.byte(.nop, {});
            try wip.byte(.end, {});
            try wip.finish(&ctx.scratch);
        }

        try ctx.checkTrapIpForModule(&b, 7, @enumFromInt(1), .unreachable_code_reached, 4);
    }
}

test "call_indirect" {
    var ctx = Context.init();
    defer ctx.deinit();
    {
        var b = WasmBuilder.init(testing.allocator);
        defer b.deinit();

        const table = try b.table(.init(.funcref, .{ .minimum = 1 }));

        const f = try b.function(try b.funcType(&.{}, &.{}));
        {
            var wip = f.writeCode(&b, testing.allocator, .{});
            try wip.byte(.nop, {});
            try wip.byte(.nop, {});
            try wip.byte(.@"i32.const", 0);
            try wip.byte(.call_indirect, .{ .table = table, .signature = f.signature(&b) });
            try wip.byte(.nop, {});
            try wip.byte(.end, {});
            try wip.finish(&ctx.scratch);
        }
        try f.@"export"(&b, try b.string(call_name));

        try ctx.checkTrapIpForModule(&b, 4, @enumFromInt(0), .indirect_call_to_null, 3);
    }
}

test "SIMD" {
    if (!wasm_features.simd128) {
        return error.SkipZigTest;
    }

    var ctx = Context.init();
    defer ctx.deinit();
    {
        var b = WasmBuilder.init(testing.allocator);
        defer b.deinit();

        const mem = try b.memory(.init(.{}));
        const f = try b.function(try b.funcType(&.{}, &.{}));
        {
            var wip = f.writeCode(&b, testing.allocator, .{});
            try wip.byte(.nop, {});
            try wip.byte(.@"i32.const", 16);
            try wip.simd(.@"v128.load", .{ .memory = mem, .offset = 32 });
            try wip.byte(.drop, {});
            try wip.byte(.end, {});
            try wip.finish(&ctx.scratch);
        }
        try f.@"export"(&b, try b.string(call_name));

        try ctx.checkTrapIpForModule(&b, 3, @enumFromInt(0), .memory_access_out_of_bounds, 3);
    }
    {
        var b = WasmBuilder.init(testing.allocator);
        defer b.deinit();

        const mem = try b.memory(.init(.{}));
        const f = try b.function(try b.funcType(&.{}, &.{}));
        {
            var wip = f.writeCode(&b, testing.allocator, .{});
            try wip.byte(.nop, {});
            try wip.byte(.@"i32.const", 132);
            try wip.byte(.nop, {});
            wip.uleb_min_len = .@"3";
            try wip.simd(.@"v128.load32_splat", .{ .memory = mem, .offset = 8 });
            wip.uleb_min_len = .smallest;
            try wip.byte(.drop, {});
            try wip.byte(.end, {});
            try wip.finish(&ctx.scratch);
        }
        try f.@"export"(&b, try b.string(call_name));

        try ctx.checkTrapIpForModule(&b, 4, @enumFromInt(0), .memory_access_out_of_bounds, 5);
    }
}

const std = @import("std");
const testing = std.testing;
const wasmstint = @import("wasmstint");
const wasm_features = @import("wasm_features");
const Interpreter = wasmstint.Interpreter;
const checks = @import("checks.zig");
const setup = @import("setup.zig");
const WasmBuilder = @import("WasmBuilder");
