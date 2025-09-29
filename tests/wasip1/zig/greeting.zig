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
