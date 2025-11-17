//! [`libFuzzer`] style fuzzer harness, for use with AFL++.
//!
//! [`libFuzzer`]: https://www.llvm.org/docs/LibFuzzer.html

inline fn testOne(
    wasm: []const u8,
    scratch: *std.heap.ArenaAllocator,
    allocator: std.mem.Allocator,
) anyerror!void {
    return target.testOne(wasm, scratch, allocator);
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

    var allocator = std.heap.DebugAllocator(.{ .safety = true }).init;
    defer {
        const leaks = allocator.deinit();
        if (leaks == .leak) {
            std.process.abort();
        }
    }

    var scratch = std.heap.ArenaAllocator.init(allocator.allocator());
    defer scratch.deinit();

    const configuration = wasm_smith.Configuration.fromTarget(target);
    var wasm_buffer: wasm_smith.ModuleBuffer = undefined;
    wasm_smith.generateModule(data, &wasm_buffer, &configuration) catch |e| return switch (e) {
        error.BadInput => {
            std.debug.print("failed to generate WASM module\n", .{});
            return Status.reject;
        },
    };

    defer wasm_smith.freeModule(&wasm_buffer);

    testOne(wasm_buffer.bytes(), &scratch, allocator.allocator()) catch |e| switch (e) {
        error.SkipZigTest => return Status.reject,
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
const wasm_smith = @import("wasm-smith");
const target = @import("target");
