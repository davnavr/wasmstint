const is_smoke_test = @import("builtin").is_test;
const init_counter = if (is_smoke_test) 0 else @compileError("not in smoke test");
var largest_code_count: usize = init_counter;
var largest_side_table_len: u32 = init_counter;
var larget_max_values: u16 = init_counter;
var larget_local_count: u16 = init_counter;

// TODO: counters in validation code to track which opcodes were validated

pub fn testOne(
    wasm_module: []const u8,
    input: *fuzz_data.Input,
    scratch: *ArenaAllocator,
    allocator: std.mem.Allocator,
) error{OutOfMemory}!void {
    _ = input;

    var diagnostic_writer = try std.Io.Writer.Allocating.initCapacity(allocator, 128);
    defer diagnostic_writer.deinit();

    var wasm: []const u8 = wasm_module;
    const module = wasmstint.Module.parse(
        allocator,
        &wasm,
        scratch,
        .{ .diagnostics = .init(&diagnostic_writer.writer) },
    ) catch |e| switch (e) {
        error.OutOfMemory => |oom| return oom,
        error.InvalidWasm, error.MalformedWasm => std.debug.panic(
            "module validation error {t}: {s}",
            .{ e, diagnostic_writer.written() },
        ),
        error.WasmImplementationLimit => {
            std.log.warn("hit implementation limit", .{});
            return;
        },
    };
    defer module.deinit(allocator, allocator);

    if (wasm.len != 0) {
        std.debug.panic("WASM buffer was not fully parsed: {d} bytes remaining", .{wasm.len});
    }

    _ = scratch.reset(.retain_capacity);

    const finished = module.finishCodeValidation(
        allocator,
        scratch,
        .init(&diagnostic_writer.writer),
    ) catch |e| switch (e) {
        error.OutOfMemory => |oom| return oom,
        error.InvalidWasm, error.MalformedWasm => std.debug.panic(
            "code validation error {t}: {s}",
            .{ e, diagnostic_writer.written() },
        ),
        error.WasmImplementationLimit => {
            std.log.warn("hit implementation limit", .{});
            return;
        },
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
        if (@intFromPtr(module.inner.code_section) >= @intFromPtr(inner.instructions_start)) {
            std.debug.panic(
                "instruction start {*} out of bounds of code section {*}",
                .{ inner.instructions_start, module.inner.code_section },
            );
        }

        if (@intFromPtr(inner.instructions_end) < @intFromPtr(inner.instructions_start)) {
            std.debug.panic(
                "instruction end {*} less than start {*}",
                .{ inner.instructions_end, inner.instructions_start },
            );
        }

        // TODO: check delta IP OOB, delta STP OOB, and copy_count <= max_values

        if (is_smoke_test) {
            largest_side_table_len = @max(largest_side_table_len, inner.side_table_len);
            larget_max_values = @max(larget_local_count, inner.max_values);
            larget_local_count = @max(larget_local_count, inner.local_values);
        }
    }

    const code_count = module.codeEntries().len;
    if (is_smoke_test) {
        largest_code_count = @max(largest_code_count, code_count);
    } else {
        std.debug.print("validated {d} functions\n", .{code_count});
    }
}

// test {
//     // TODO(zig): Fix crash in fuzz test runner
//     if (true) {
//         try std.testing.fuzz({}, doTest, .{});
//     }
// }

fn testOneAllocationFailure(
    allocator: std.mem.Allocator,
    wasm: []const u8,
    input: *fuzz_data.Input,
) !void {
    var scratch = ArenaAllocator.init(testing.allocator);
    defer scratch.deinit();
    try testOne(wasm, input, &scratch, allocator);
}

test {
    const fuzz_buffer = try testing.allocator.alloc(u8, 2048);
    defer testing.allocator.free(fuzz_buffer);

    var rng = std.Random.DefaultPrng.init(testing.random_seed);
    var generated_cases: usize = 0;
    const total_case_count = 2000;
    for (0..total_case_count) |i| {
        errdefer std.log.err("failed while generating test case {d}", .{i});

        rng.fill(fuzz_buffer);

        var input = fuzz_data.Input.init(fuzz_buffer);
        var wasm_buffer: ffi.wasm_smith.ModuleBuffer = undefined;
        wasm_buffer.generate(&input, &.{}) catch |e| return switch (e) {
            error.BadInput => continue,
        };
        defer wasm_buffer.deinit();

        try testing.checkAllAllocationFailures(
            testing.allocator,
            testOneAllocationFailure,
            .{ wasm_buffer.bytes(), &input },
        );

        generated_cases += 1;
    }

    try testing.expect(generated_cases >= generated_cases - (generated_cases / 4));
    try testing.expect(largest_code_count >= 5);
    try testing.expect(largest_side_table_len >= 128);
    try testing.expect(larget_max_values >= 50);
    try testing.expect(larget_local_count >= 50);
}

const std = @import("std");
const ArenaAllocator = std.heap.ArenaAllocator;
const testing = std.testing;
const wasmstint = @import("wasmstint");
const fuzz_data = @import("fuzz_data");
const ffi = @import("ffi");
