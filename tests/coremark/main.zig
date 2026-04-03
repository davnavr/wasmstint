//! Executes the `coremark-minimal.wasm` benchmark.

const coremark_wasm = @embedFile("coremark-minimal.wasm");

pub const std_options = std.Options{ .networking = false };

pub fn main() !void {
    var io = std.Io.Threaded.init_single_threaded;

    var scratch = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer if (builtin.mode == .Debug) scratch.deinit();

    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer if (builtin.mode == .Debug) arena.deinit();

    var wasm: []const u8 = coremark_wasm;
    const module = try wasmstint.Module.parse(arena.allocator(), &wasm, &scratch, .{});
    std.debug.assert(try module.finishCodeValidation(arena.allocator(), &scratch, .none));

    const mem_type = &module.memDefinedTypes()[0];
    var memory = try runtime.MemInst.Mapped.allocateFromType(
        mem_type,
        mem_type.limits.min * runtime.MemInst.page_size,
        std.math.maxInt(usize),
    );

    var module_alloc = try runtime.ModuleAlloc.allocateWithDefinitions(
        module,
        arena.allocator(),
        imports.provider,
        null,
        .{ .memories = &.{&memory.memory} },
    );

    var interp: Interpreter = undefined;
    var fuel = Interpreter.Fuel{ .remaining = std.math.maxInt(u64) };
    var state = try Interpreter.init(&interp, std.heap.page_allocator, .{});
    defer if (builtin.mode == .Debug) interp.deinit(std.heap.page_allocator);

    state = try state.awaiting_host
        .instantiateModule(std.heap.page_allocator, &module_alloc, &fuel);

    _ = state.awaiting_host;
    // No `start` function
    var module_inst = module_alloc.assumeInstantiated();

    // (func (export "run") (result f32))
    const entrypoint = (try module_inst.findExport("run")).func.funcInst();
    state = try state.awaiting_host.beginCall(std.heap.page_allocator, entrypoint, &.{}, &fuel);
    const result: f32 = done: while (true) {
        state = next: switch (state) {
            .awaiting_host => |*host| if (host.currentHostFunction() != null) {
                const ms = std.Io.Timestamp.now(io.io(), .cpu_process).toMilliseconds();
                break :next try host.returnFromHostTyped(.{@as(i64, ms)}, &fuel);
            } else {
                var results_buf: [1]Interpreter.TaggedValue = undefined;
                host.copyResultsTo(&results_buf);
                break :done results_buf[0].f32;
            },
            .awaiting_validation => unreachable,
            .call_stack_exhaustion => @panic("call stack exhausted"),
            .interrupted => |*interrupt| {
                switch (interrupt.cause().*) {
                    .out_of_fuel => @panic("out of fuel"),
                    .memory_grow => |grow_request| grow_request.grow() catch {},
                    .table_grow => unreachable,
                }

                break :next interrupt.resumeExecution(&fuel);
            },
            .trapped => |*trapped| std.debug.panic("trap {t}", .{trapped.trap().code}),
        };
    };

    std.debug.print("{}\n", .{result});
}

const imports = struct {
    /// ```wasm
    /// (import "env" "clock_ms" (result i64))
    /// ```
    const clock_ms = runtime.HostFunc{ .signature = .initComptime(&.{}, &.{.i64}) };

    fn resolve(
        ctx: *anyopaque,
        module: wasmstint.Module.Name,
        name: wasmstint.Module.Name,
        desc: runtime.ImportProvider.Desc,
    ) anyerror!?runtime.ExternVal {
        _ = ctx;
        _ = desc;
        return if (std.mem.eql(u8, module.bytes(), "env") and
            std.mem.eql(u8, name.bytes(), "clock_ms"))
            .{ .func = .init(.{ .host = &clock_ms }) }
        else
            null;
    }

    /// Always returns `null` indicating that an imported value cannot be provided.
    pub const provider = runtime.ImportProvider{
        .ctx = undefined,
        .resolve = resolve,
    };
};

const std = @import("std");
const builtin = @import("builtin");
const wasmstint = @import("wasmstint");
const Interpreter = wasmstint.Interpreter;
const runtime = wasmstint.runtime;
