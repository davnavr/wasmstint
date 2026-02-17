//! [`libFuzzer`] style fuzzer harness, for use with AFL++.
//!
//! [`libFuzzer`]: https://www.llvm.org/docs/LibFuzzer.html

inline fn testOne(
    wasm: []const u8,
    input: *ffi.Input,
    scratch: *std.heap.ArenaAllocator,
    allocator: std.mem.Allocator,
) anyerror!void {
    return target.testOne(wasm, input, scratch, allocator);
}

const Status = enum(c_int) {
    accept = 0,
    reject = -1,
    _,
};

/// Defined here to avoid "undefined symbol" linker errors.
///
/// https://clang.llvm.org/docs/SanitizerCoverage.html#tracing-stack-depth
pub export threadlocal var __sancov_lowest_stack: usize = 0;

pub const std_options: std.Options = .{
    // https://github.com/AFLplusplus/AFLplusplus/blob/stable/docs/fuzzing_in_depth.md#k-known-limitations--areas-for-improvement
    .enable_segfault_handler = false,
    .allow_stack_tracing = false,
};

pub export fn LLVMFuzzerTestOneInput(data_ptr: [*]const u8, data_size: usize) Status {
    const data: []const u8 = data_ptr[0..data_size];

    const allocator = std.heap.c_allocator;

    var scratch = std.heap.ArenaAllocator.init(allocator);
    defer scratch.deinit();

    var input = ffi.Input.init(data);

    const configuration = ffi.wasm_smith.Configuration.fromTarget(target);
    var wasm_buffer: ffi.wasm_smith.ModuleBuffer = undefined;
    wasm_buffer.generate(&input, &configuration) catch |e| return switch (e) {
        error.BadInput => {
            std.debug.print("failed to generate WASM module\n", .{});
            return Status.reject;
        },
    };
    defer wasm_buffer.deinit();

    testOne(wasm_buffer.bytes(), &input, &scratch, allocator) catch |e| switch (e) {
        error.SkipZigTest, error.BadInput => return Status.reject,
        error.OutOfMemory => {},
        else => abortOnError(e),
    };

    return Status.accept;
}

fn dumpStackTrace(
    st: ?*const std.builtin.StackTrace,
    terminal: std.Io.Terminal,
) std.Io.Writer.Error!void {
    empty: {
        const trace = st orelse break :empty;
        if (trace.index == 0) break :empty;

        terminal.setColor(.dim) catch {};
        for (trace.instruction_addresses[0..@min(
            trace.index,
            trace.instruction_addresses.len,
        )]) |addr| {
            try terminal.writer.print(
                "{[addr]X:0>[width]}",
                .{ .addr = addr, .width = @sizeOf(usize) * 2 },
            );
        }

        const skipped_count = trace.index -| trace.instruction_addresses.len;
        if (skipped_count > 0) {
            terminal.setColor(.bold) catch {};
            try terminal.writer.print("{d} frames omitted\n", .{skipped_count});
        }
        terminal.setColor(.reset) catch {};
    }

    try terminal.writer.writeAll("(empty stack trace)\n");
}

fn abortOnError(e: anyerror) noreturn {
    @branchHint(.cold);
    var stderr_buffer: [128]u8 align(16) = undefined;
    const stderr = std.debug.lockStderr(&stderr_buffer).terminal();
    defer std.debug.unlockStderr();

    abort: {
        stderr.setColor(.bright_red) catch break :abort;
        stderr.writer.writeAll("error: ") catch break :abort;
        stderr.setColor(.reset) catch break :abort;
        stderr.writer.print("{t}\n", .{e}) catch break :abort;
        dumpStackTrace(@errorReturnTrace(), stderr) catch break :abort;
    }

    abort();
}

fn panicHandler(msg: []const u8, first_trace_addr: ?usize) noreturn {
    @branchHint(.cold);

    var stderr_buffer: [128]u8 align(16) = undefined;
    // This uses a mutex, and no fuzz targets currently use multiple threads anyway, so there is
    // no need for explicit locking here
    const stderr = std.debug.lockStderr(&stderr_buffer).terminal();

    abort: {
        stderr.setColor(.bright_red) catch break :abort;
        stderr.writer.writeAll("panic") catch break :abort;
        stderr.setColor(.reset) catch break :abort;
        if (first_trace_addr) |addr| {
            stderr.writer.print(
                " @ {[addr]X:0>[width]}",
                .{ .addr = addr, .width = @sizeOf(usize) * 2 },
            ) catch break :abort;
        }
        stderr.writer.print(" : {s}\n", .{msg}) catch break :abort;
        dumpStackTrace(@errorReturnTrace(), stderr) catch break :abort;
    }

    abort();
}

pub const panic = std.debug.FullPanic(panicHandler);

const std = @import("std");
/// LLVM docs state that `exit()`ing shouldn't be done.
const abort = std.process.abort;
const ffi = @import("ffi");
const target = @import("target");
