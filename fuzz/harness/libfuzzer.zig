//! [`libFuzzer`] style fuzzer harness, for use with AFL++.
//!
//! [`libFuzzer`]: https://www.llvm.org/docs/LibFuzzer.html

const Harness = struct {
    pub fn generatedModule(_: Harness, _: []const u8) void {}
};

inline fn testOne(
    input: []const u8,
    scratch: *std.heap.ArenaAllocator,
    allocator: std.mem.Allocator,
) anyerror!void {
    return @import("target").testOne(input, scratch, allocator, Harness{});
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

pub export fn LLVMFuzzerTestOneInput(data: [*]const u8, size: usize) Status {
    var allocator = std.heap.DebugAllocator(.{ .safety = true }).init;
    defer {
        const leaks = allocator.deinit();
        if (leaks == .leak) {
            std.process.abort();
        }
    }

    var scratch = std.heap.ArenaAllocator.init(allocator.allocator());
    defer scratch.deinit();

    testOne(data[0..size], &scratch, allocator.allocator()) catch |e| switch (e) {
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
