//! [`libfuzzer`] style fuzzer harness, for use with AFL++.

const testOne: fn (
    []const u8,
    *std.heap.ArenaAllocator,
    std.mem.Allocator,
) anyerror!void = @import("target").testOne;

const Status = enum(c_int) {
    accept = 0,
    reject = -1,
    _,
};

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

    testOne(data[0..size], &scratch, allocator.allocator()) catch |e| switch (@as(anyerror, e)) {
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
