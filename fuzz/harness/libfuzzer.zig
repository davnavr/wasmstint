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
        else => {
            var stderr_buffer: [512]u8 align(16) = undefined;
            const stderr, const color = std.debug.lockStderrWriter(&stderr_buffer);
            defer std.debug.unlockStderrWriter();

            color.setColor(stderr, .bright_red) catch {};
            stderr.writeAll("error: ") catch {};
            color.setColor(stderr, .reset) catch {};
            stderr.print("{t}\n", .{e}) catch {};
            if (@errorReturnTrace()) |trace| {
                std.debug.writeStackTrace(trace, stderr, color) catch {};
            } else {
                stderr.writeAll("(stack trace unavailable)\n") catch {};
            }

            // LLVM docs state that `exit()`ing shouldn't be done.
            std.process.abort();
        },
    };

    return Status.accept;
}

const std = @import("std");
const ffi = @import("ffi");
const target = @import("target");
