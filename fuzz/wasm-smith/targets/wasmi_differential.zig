const std = @import("std");
const ArenaAllocator = std.heap.ArenaAllocator;
const harness = @import("harness");
const wasmstint = @import("wasmstint");

const InterpreterResult = union(enum) {
    trapped: wasmstint.Interpreter.Trap.Code,
    results: []wasmstint.Interpreter.TaggedValue,
};

fn driveInterpreter(
    interp: *wasmstint.Interpreter,
    fuel: *wasmstint.Interpreter.Fuel,
    code_arena: *ArenaAllocator,
    scratch: *ArenaAllocator,
) error{ OutOfMemory, ResourceExhaustion }!InterpreterResult {
    while (true) {
        _ = scratch.reset(.retain_capacity);
        switch (interp.state) {
            .awaiting_host => |*host| {
                std.debug.assert(interp.call_stack.items.len == 0);
                return .{ .results = try host.copyValues(scratch) };
            },
            .awaiting_validation => |*validate| {
                _ = validate.validate(
                    code_arena.allocator(),
                    scratch,
                    std.heap.page_allocator,
                    fuel,
                );
            },
            .call_stack_exhaustion => return error.ResourceExhaustion,
            .interrupted => |*interruption| {
                switch (interruption.cause) {
                    .out_of_fuel, .memory_grow, .table_grow => return error.ResourceExhaustion,
                }
            },
            .trapped => |trap| return .{ .trapped = trap.code },
        }
    }
}

pub fn target(input_bytes: []const u8) !harness.Result {
    var gen = harness.Generator.init(input_bytes);
    const wasmi_exec = try harness.wasmi_differential.Execution.runTestCase(&gen);
    defer wasmi_exec.deinit();

    var main_pages = try wasmstint.PageBufferAllocator.init(64 * (1024 * 1024));
    defer main_pages.deinit();

    var scratch_pages = try wasmstint.PageBufferAllocator.init(4 * (1024 * 1024));
    var scratch = ArenaAllocator.init(scratch_pages.allocator());
    defer scratch_pages.deinit();

    std.debug.print("parsing module...\n", .{});

    var rng = std.Random.Xoshiro256{ .s = @bitCast((try gen.byteArray(32)).*) };
    var wasm_parse = wasmi_exec.wasmBinaryModule();
    var module = try wasmstint.Module.parse(
        main_pages.allocator(),
        &wasm_parse,
        &scratch,
        rng.random(),
        .{ .realloc_contents = true },
    );

    defer module.deinit(main_pages.allocator());

    std.debug.print("allocating module...\n", .{});

    var import_failure: wasmstint.runtime.ImportProvider.FailedRequest = undefined;
    var module_alloc = wasmstint.runtime.ModuleAlloc.allocate(
        &module,
        wasmstint.runtime.ImportProvider.no_imports.provider,
        main_pages.allocator(),
        wasmstint.runtime.ModuleAllocator.page_allocator,
        &import_failure,
    ) catch |e| switch (e) {
        error.OutOfMemory => |oom| return oom,
        error.ImportFailure => std.debug.panic("module should not have imports: {}", .{import_failure}),
    };

    defer module_alloc.requiring_instantiation.deinit(
        main_pages.allocator(),
        wasmstint.runtime.ModuleAllocator.page_allocator,
    );

    var code_arena = ArenaAllocator.init(main_pages.allocator());
    defer code_arena.deinit();

    const init_fuel = wasmstint.Interpreter.Fuel{ .remaining = 5_000_000 };
    var interp = try wasmstint.Interpreter.init(
        std.heap.page_allocator,
        .{},
    );
    defer interp.deinit(std.heap.page_allocator);

    const init_result = init: {
        var fuel = init_fuel;
        _ = try interp.state.awaiting_host.instantiateModule(
            std.heap.page_allocator,
            &module_alloc,
            &fuel,
        );
        break :init driveInterpreter(&interp, &fuel, &code_arena, &scratch) catch |e| switch (e) {
            error.OutOfMemory => |oom| return oom,
            error.ResourceExhaustion => return .skip,
        };
    };

    const actions: *const harness.FfiVec(harness.wasmi_differential.Action) = switch (wasmi_exec.instantiationResult()) {
        .trapped => |wasmi_trap| switch (init_result) {
            .results => |results| std.debug.panic(
                "expected trap {s}, but got {}",
                .{
                    @tagName(wasmi_trap.*),
                    wasmstint.Interpreter.TaggedValue.sliceFormatter(results),
                },
            ),
            .trapped => |actual_trap| if (actual_trap != wasmi_trap.*) std.debug.panic(
                "expected trap {s}, but got trap {s}",
                .{ @tagName(wasmi_trap.*), @tagName(actual_trap) },
            ) else return .ok,
        },
        .instantiated => |actions| actions,
    };

    std.debug.print("will execute {} actions...\n", .{actions.items.len});

    for (0.., actions.slice()) |i, act| {
        std.debug.print("[{}]: {s}\n", .{ i, @tagName(act.tag) });
        switch (act.tagForSwitch()) {
            .check_global_value => |check_idx| {
                const check = check_idx.inner(wasmi_exec);
                _ = check;
            },
            else => @panic("TODO!"),
        }
    }

    return .ok;
}

comptime {
    harness.defineFuzzTarget(target);
}
