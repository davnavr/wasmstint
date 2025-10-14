pub fn main() !void {
    var args = try std.process.ArgIteratorWasi.init(std.heap.wasm_allocator);
    defer args.deinit();

    _ = args.next() orelse @panic("no process name!");

    if (args.next()) |name| {
        std.debug.print("Hello {f}, I am greeting you!\n", .{std.unicode.fmtUtf8(name)});
    } else {
        std.debug.print("How rude! You didn't tell me your name.\n", .{});
    }
}

const std = @import("std");

test "no arguments" {
    try subprocess.invokeWasiInterpreter(
        test_paths.interpreter,
        test_paths.wasm,
        .{},
        .{
            .stderr = "How rude! You didn't tell me your name.\n",
        },
    );
}

test "one argument" {
    try subprocess.invokeWasiInterpreter(
        test_paths.interpreter,
        test_paths.wasm,
        .{
            .args = &.{"The Tester"},
        },
        .{
            .stderr = "Hello The Tester, I am greeting you!\n",
        },
    );
}

const subprocess = @import("subprocess");
const test_paths = @import("test_paths");
